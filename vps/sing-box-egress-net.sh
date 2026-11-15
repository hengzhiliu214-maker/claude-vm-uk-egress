#!/bin/sh
# 可审阅拟稿 / 不执行 / 不改现网
# 撰写本清单时不运行。运行它会改防火墙规则。
set -eu

CONF=/etc/sing-box/egress.json
LEAF_DIR=/sys/fs/cgroup/system.slice/sing-box-egress.service
LEAF_PATH=/system.slice/sing-box-egress.service
STATE_DIR=/run/sing-box-egress
INO_FILE=$STATE_DIR/cgroup-inode
REL_FILE=$STATE_DIR/release
FACTS_FILE=$STATE_DIR/facts
GUARD_FILE=/etc/nftables/sbguard.nft
LOCK_FILE=$STATE_DIR/guard.lock
TUN_ADDR=172.18.0.1/30

fail() {
  printf 'sing-box-egress-net: %s\n' "$*" >&2
  exit 1
}
gen_sbguard_baseline() {
  # 不读取事实文件：只输出无许可基线（四条 forward drop + skuid-999 drop；
  # 叶存在时保留叶内非属主拒绝；永不输出例外与 forward ACCEPT）。
  # 用于清理路径：facts 损坏/目录/删除失败时仍可撤销已生效的许可。
  leaf_ok=0
  [ -d "$LEAF_DIR" ] && leaf_ok=1
  printf '%s\n' 'table inet sbguard {'
  printf '%s\n' '    chain guard_forward {'
  printf '%s\n' '        type filter hook forward priority -200; policy accept;'
  printf '%s\n' '        iifname "wg0" counter drop'
  printf '%s\n' '        oifname "wg0" counter drop'
  printf '%s\n' '        iifname "tun0" counter drop'
  printf '%s\n' '        oifname "tun0" counter drop'
  printf '%s\n' '    }'
  printf '%s\n' '    chain guard_output {'
  printf '%s\n' '        type filter hook output priority -200; policy accept;'
  if [ "$leaf_ok" = "1" ]; then
    printf '%s\n' '        socket cgroupv2 level 2 "system.slice/sing-box-egress.service" meta skuid != 999 counter drop'
  fi
  printf '%s\n' '        meta skuid 999 counter drop'
  printf '%s\n' '    }'
  printf '%s\n' '}'
}
with_lock() {
  # 串行化一次完整状态变更。调用者（systemd 启停、UFW reload、手工入口）均经分发器走此入口；
  # 内部函数（refresh_leaf/install_e/cleanup_guard/on_err）永不再次加锁，避免重入死锁。
  # 锁随持有进程退出自动释放（flock 语义），无残留锁；锁文件在 tmpfs 的 STATE_DIR 内，重启后无旧锁。
  # 锁等待上限 60 秒（systemd 默认启动超时 90 秒内）；超时未取得即大声失败，不静默跳过。
  [ -z "${LOCK_HELD:-}" ] || fail "with_lock: already holding the lock"
  mkdir -p "$STATE_DIR" || fail "cannot create state directory"
  exec 9>"$LOCK_FILE" || fail "cannot open lock file"
  flock -w 60 9 || fail "cannot acquire guard lock"
  LOCK_HELD=1
  "$@"
}

facts_body_digest() {
  # 输出规范化授权事实内容（socks_host/socks_port/leaf_ino/config_sha，按此顺序，
  # 不含 version/guard_sha/guard_e）的 sha256。签发与核对共用同一函数、同一规范化。
  # 该摘要是对端点值的承诺，不泄露真实端点（单向哈希）；放行信记录摘要值。
  read_facts || fail "cannot read facts for digest"
  printf 'socks_host=%s\nsocks_port=%s\nleaf_ino=%s\nconfig_sha=%s\n' \
    "$F_SOCKS_HOST" "$F_SOCKS_PORT" "$F_LEAF_INO" "$F_CONFIG_SHA" \
    | sha256sum | awk '{print $1}'
}


sbguard_apply() {
  mkdir -p "$STATE_DIR" || fail "cannot create state directory"
  mkdir -p "$(dirname "$GUARD_FILE")" || fail "cannot create nftables directory"
  tmp_rules=$(mktemp "$STATE_DIR/.guard-rules.XXXXXX") || fail "cannot create temp rules file"
  chmod 600 "$tmp_rules" || fail "cannot chmod temp rules file"
  # --baseline 模式：用不读 facts 的基线生成器（见 gen_sbguard_baseline），
  # 且跳过事实文件写回（facts 可能已损坏/不存在，写回不得成为撤销的卡点）。
  if [ "${1:-}" = "--baseline" ]; then
    gen_sbguard_baseline > "$tmp_rules" || fail "cannot generate baseline rules"
    if grep -q 'counter accept' "$tmp_rules"; then fail "baseline contains an accept"; fi
  else
    gen_sbguard_rules "$@" > "$tmp_rules" || fail "cannot generate sbguard rules"
  fi
  tmp_file=$(mktemp "$STATE_DIR/.guard-file.XXXXXX") || fail "cannot create temp file"
  chmod 600 "$tmp_file" || fail "cannot chmod temp file"
  # 表已存在时才写清理行（T4：表不存在时无条件 delete 会使整个事务失败）。
  # 存在性核对须区分"不存在"与"读失败"：只在报错含 No such file 时视为不存在，
  # 其他读失败即 fail（不把瞬时错误当作不存在而追加）。
  err_file=$(mktemp "$STATE_DIR/.guard-list.XXXXXX") || fail "cannot create temp file"
  if nft list table inet sbguard >/dev/null 2>"$err_file"; then
    printf '%s\n' 'delete table inet sbguard' > "$tmp_file"
  elif grep -q "No such file or directory" "$err_file" 2>/dev/null; then
    : # 表不存在，不写清理行
  else
    rm -f "$tmp_rules" "$tmp_file" "$err_file"
    fail "cannot list sbguard table"
  fi
  rm -f "$err_file"
  cat "$tmp_rules" >> "$tmp_file" || fail "cannot assemble guard file"
  # --allow-e 时核对：请求了 E 许可但生成结果缺 forward ACCEPT（无叶/无事实文件），
  # 必须大声失败，不得静默提交一张缺许可的规则表（否则 install_e 会误认 E 已启用）。
  if [ "${1:-}" = "--allow-e" ]; then
    grep -q 'iifname "wg0" oifname "tun0" ip saddr 10.66.0.2/32 counter accept' "$tmp_file" || { rm -f "$tmp_rules" "$tmp_file"; fail "allow-e requested but wg0->tun0 accept not generated"; }
    grep -q 'iifname "wg0" oifname "tun0" ip saddr 10.66.0.3/32 counter accept' "$tmp_file" || { rm -f "$tmp_rules" "$tmp_file"; fail "allow-e requested but phone wg0->tun0 accept not generated"; }
    grep -q 'iifname "tun0" oifname "wg0" ip daddr 10.66.0.2/32 counter accept' "$tmp_file" || { rm -f "$tmp_rules" "$tmp_file"; fail "allow-e requested but tun0->wg0 accept not generated"; }
    grep -q 'iifname "tun0" oifname "wg0" ip daddr 10.66.0.3/32 counter accept' "$tmp_file" || { rm -f "$tmp_rules" "$tmp_file"; fail "allow-e requested but phone tun0->wg0 accept not generated"; }
  fi
  nft -f "$tmp_file" || { rm -f "$tmp_rules" "$tmp_file"; fail "cannot apply sbguard rules"; }
  nft list table inet sbguard >/dev/null || fail "sbguard table not present after apply"
  cp "$tmp_file" "$GUARD_FILE" || fail "cannot record guard file"
  chmod 600 "$GUARD_FILE" || fail "cannot chmod guard file"
  rm -f "$tmp_rules" "$tmp_file"
  # 写回观测状态（guard_sha/guard_e）：只作回读记录；生成器永不以此作为输入。
  # 事实文件不存在时（开机基线、停止后）跳过写回。
  # --baseline 模式跳过写回（不读 facts；见上）。
  if [ -f "$FACTS_FILE" ] && [ "${1:-}" != "--baseline" ]; then
    gsha=$(sha256sum "$GUARD_FILE" | awk '{print $1}') || fail "cannot hash guard file"
    read_facts || fail "cannot read facts for guard state write-back"
    tmp_facts=$(mktemp "$STATE_DIR/.facts.XXXXXX") || fail "cannot create temp facts file"
    chmod 600 "$tmp_facts" || fail "cannot chmod temp facts file"
    {
      printf 'version=%s\n' "$F_VERSION"
      printf 'socks_host=%s\nsocks_port=%s\nleaf_ino=%s\nconfig_sha=%s\n' "$F_SOCKS_HOST" "$F_SOCKS_PORT" "$F_LEAF_INO" "$F_CONFIG_SHA"
      printf 'guard_sha=%s\n' "$gsha"
      if [ "${1:-}" = "--allow-e" ]; then printf 'guard_e=1\n'; else printf 'guard_e=0\n'; fi
    } > "$tmp_facts" || fail "cannot write temp facts file"
    mv "$tmp_facts" "$FACTS_FILE" || fail "cannot install facts file"
  fi
}

gen_sbguard_rules() {
  # 用法：gen_sbguard_rules [ --allow-e ]；规则文本写到 stdout。
  # cgroup 匹配是常量叶子路径（加载时由 nft 解析）；不插值 inode。
  # 两条 socket 规则只在叶存在时输出（§1.2：叶不存在时为冷启基线，零 socket 规则）；
  # forward ACCEPT 只在 --allow-e 且叶存在且事实文件齐全（ino/host/port 均非空）时输出；
  # 无叶或无事实文件时，即使 --allow-e 也不产生任何 forward ACCEPT（fail-closed）。
  # output 例外只在 leaf_ino 非空时输出。
  allow_e=0
  [ "${1:-}" = "--allow-e" ] && allow_e=1
  ino=""; host=""; port=""
  if [ -f "$FACTS_FILE" ]; then
    read_facts || fail "cannot read facts"
    ino="$F_LEAF_INO"; host="$F_SOCKS_HOST"; port="$F_SOCKS_PORT"
  fi
  leaf_ok=0
  [ -d "$LEAF_DIR" ] && leaf_ok=1
  printf '%s\n' 'table inet sbguard {'
  printf '%s\n' '    chain guard_forward {'
  printf '%s\n' '        type filter hook forward priority -200; policy accept;'
  if [ "$allow_e" = "1" ] && [ "$leaf_ok" = "1" ] && [ -n "$ino" ] && [ -n "$host" ] && [ -n "$port" ]; then
    printf '%s\n' '        iifname "wg0" oifname "tun0" ip saddr 10.66.0.2/32 counter accept'
    printf '%s\n' '        iifname "wg0" oifname "tun0" ip saddr 10.66.0.3/32 counter accept'
    printf '%s\n' '        iifname "tun0" oifname "wg0" ip daddr 10.66.0.2/32 counter accept'
    printf '%s\n' '        iifname "tun0" oifname "wg0" ip daddr 10.66.0.3/32 counter accept'
  fi
  printf '%s\n' '        iifname "wg0" counter drop'
  printf '%s\n' '        oifname "wg0" counter drop'
  printf '%s\n' '        iifname "tun0" counter drop'
  printf '%s\n' '        oifname "tun0" counter drop'
  printf '%s\n' '    }'
  printf '%s\n' '    chain guard_output {'
  printf '%s\n' '        type filter hook output priority -200; policy accept;'
  if [ "$leaf_ok" = "1" ]; then
    printf '%s\n' '        socket cgroupv2 level 2 "system.slice/sing-box-egress.service" meta skuid != 999 counter drop'
    if [ -n "$ino" ] && [ -n "$host" ] && [ -n "$port" ]; then
      printf '        socket cgroupv2 level 2 "system.slice/sing-box-egress.service" meta skuid 999 ip daddr %s tcp dport %s counter accept\n' "$host" "$port"
    fi
  fi
  printf '%s\n' '        meta skuid 999 counter drop'
  printf '%s\n' '    }'
  printf '%s\n' '}'
}

cleanup_guard() {
  # 撤销独立层许可与放行凭证；三动作各在子 shell 中执行，
  # 前一动作失败不跳过后一动作；失败分别记录，合并返回码。
  # 顺序：先独立应用无许可基线（不读 facts——facts 损坏/目录/删除失败也不影响撤销），
  # 再分别删除事实文件与凭证。基线应用失败也不跳过后两步。
  local rc=0
  ( sbguard_apply --baseline ) || { echo "sing-box-egress-net: cleanup_guard: baseline apply failed" >&2; rc=1; }
  ( rm -f "$FACTS_FILE" ) || { echo "sing-box-egress-net: cleanup_guard: cannot delete facts file" >&2; rc=1; }
  ( revoke_release ) || { echo "sing-box-egress-net: cleanup_guard: revoke_release failed" >&2; rc=1; }
  return $rc
}

read_facts() {
  # 严格解析 $FACTS_FILE，合法值写入 F_* 变量；任一核对失败即 fail。
  # 先核 STATE_DIR（与 require_release 同级：非符号链接、root 所有、不可组/其他写）。
  [ -d "$STATE_DIR" ] || fail "facts state directory is missing"
  [ ! -L "$STATE_DIR" ] || fail "facts state directory is a symbolic link"
  dir_owner=$(stat -c %U "$STATE_DIR" 2>/dev/null) || fail "cannot read facts state directory owner"
  [ "$dir_owner" = root ] || fail "facts state directory is not root-owned"
  dir_perms=$(stat -c %A "$STATE_DIR" 2>/dev/null) || fail "cannot read facts state directory permissions"
  case "$dir_perms" in
    ?????w*|????????w?) fail "facts state directory is group- or world-writable" ;;
  esac
  [ -f "$FACTS_FILE" ] || fail "facts missing"
  [ -L "$FACTS_FILE" ] && fail "facts is a symlink"
  # 属主与权限：root 所有、mode 600（stat 显式核对，不用 find）。
  [ "$(stat -c %U "$FACTS_FILE")" = "root" ] || fail "facts not owned by root"
  [ "$(stat -c %a "$FACTS_FILE")" = "600" ] || fail "facts mode is not 600"
  # 每键恰好出现一次；未知键拒绝；值类型严格。
  for k in version socks_host socks_port leaf_ino config_sha guard_sha guard_e; do
    n=$(grep -c "^$k=" "$FACTS_FILE") || fail "cannot read facts"
    [ "$n" = "1" ] || fail "facts key $k appears $n times"
  done
  [ "$(grep -c -v -E '^(version|socks_host|socks_port|leaf_ino|config_sha|guard_sha|guard_e)=' "$FACTS_FILE")" = "0" ] || fail "facts has unknown keys"
  F_VERSION=$(awk -F= '$1=="version"{print $2}' "$FACTS_FILE")
  F_SOCKS_HOST=$(awk -F= '$1=="socks_host"{print $2}' "$FACTS_FILE")
  F_SOCKS_PORT=$(awk -F= '$1=="socks_port"{print $2}' "$FACTS_FILE")
  F_LEAF_INO=$(awk -F= '$1=="leaf_ino"{print $2}' "$FACTS_FILE")
  F_CONFIG_SHA=$(awk -F= '$1=="config_sha"{print $2}' "$FACTS_FILE")
  F_GUARD_SHA=$(awk -F= '$1=="guard_sha"{print $2}' "$FACTS_FILE")
  F_GUARD_E=$(awk -F= '$1=="guard_e"{print $2}' "$FACTS_FILE")
  case "$F_VERSION" in ''|*[!0-9]*) fail "facts version is not numeric";; esac
  case "$F_LEAF_INO" in '' ) ;; *[!0-9]*) fail "facts leaf_ino is not numeric";; esac
  case "$F_SOCKS_PORT" in ''|*[!0-9]*) fail "facts socks_port is not numeric";; esac
  [ "$F_SOCKS_PORT" -ge 1 ] && [ "$F_SOCKS_PORT" -le 65535 ] || fail "facts socks_port out of range"
  echo "$F_SOCKS_HOST" | grep -q -E '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$' || fail "facts socks_host is not an IPv4 literal"
  echo "$F_CONFIG_SHA" | grep -q -E '^[0-9a-f]{64}$' || fail "facts config_sha is not a sha256"
  echo "$F_GUARD_SHA" | grep -q -E '^[0-9a-f]{64}$' || fail "facts guard_sha is not a sha256"
  case "$F_GUARD_E" in 0|1) ;; *) fail "facts guard_e is not 0/1";; esac
}

write_facts() {
  # refresh_leaf 调用：传入新内容（inode/SOCKS/配置摘要）；与已存事实文件逐字段比对，
  # 内容变化才递增代次，内容相同则代次不变；经临时文件 + mv 落盘。
  # 事实文件重写即作废此前的观测记录：guard_sha 置零占位、guard_e 置 0，
  # 由下一次 sbguard_apply 成功后重新写回（见 §2.2）。
  # 参数：$1=leaf_ino $2=socks_host $3=socks_port $4=config_sha
  local new_version=1 old_version="" old_body="" new_body=""
  if [ -f "$FACTS_FILE" ]; then
    read_facts || fail "cannot read old facts"
    old_version="$F_VERSION"
    old_body=$(grep -v -E '^(version|guard_sha|guard_e)=' "$FACTS_FILE")
    new_body=$(printf 'socks_host=%s\nsocks_port=%s\nleaf_ino=%s\nconfig_sha=%s\n' "$2" "$3" "$1" "$4")
    if [ "$old_body" = "$new_body" ]; then new_version="$old_version"; else new_version=$((old_version + 1)); fi
  fi
  tmp_facts=$(mktemp "$STATE_DIR/.facts.XXXXXX") || fail "cannot create temp facts file"
  chmod 600 "$tmp_facts" || fail "cannot chmod temp facts file"
  {
    printf 'version=%s\n' "$new_version"
    printf 'socks_host=%s\nsocks_port=%s\nleaf_ino=%s\nconfig_sha=%s\n' "$2" "$3" "$1" "$4"
    printf 'guard_sha=%s\n' "0000000000000000000000000000000000000000000000000000000000000000"
    printf 'guard_e=0\n'
  } > "$tmp_facts" || fail "cannot write temp facts file"
  mv "$tmp_facts" "$FACTS_FILE" || fail "cannot install facts file"
}


# 表 167 的正路由用 ip -j 解析。裸 IPv4 主机地址与 /32 归一后是同一条。
# 不回退到 grep 字面量。ip -j 失败或 JSON 解析失败都失败，不当成路由不在。
# owner 插入与核对都用 id -u sb-egress 的数字。-S 里出现用户名不算通过。
# 删除成功只表示回读确认目标已经不在。-D / del 的非零退出本身不算缺席。

require_egress_uid() {
  if [ -z "${EGRESS_UID:-}" ]; then
    EGRESS_UID=$(id -u sb-egress) || fail "id -u sb-egress failed"
    case "$EGRESS_UID" in
      ""|*[!0-9]*) fail "id -u sb-egress did not return a numeric uid" ;;
    esac
  fi
}

ip_json_task() {
  awk -v task="$1" -v pref="${2:-}" '
function norm_dst(dst,    n, a) {
  if (dst == "" || dst == "default" || dst == "0.0.0.0/0" || dst == "::/0")
    return "default/0"
  n = split(dst, a, "/")
  if (n == 1) {
    if (dst ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return dst "/32"
    if (index(dst, ":") > 0) return dst "/128"
    return dst "/?"
  }
  if (n == 2 && a[2] == "32" && a[1] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
    return a[1] "/32"
  return dst
}

function take_string(obj,    n, c, val) {
  n = length(obj)
  val = ""
  i++
  esc = 0
  while (i <= n) {
    c = substr(obj, i, 1)
    if (esc) {
      val = val c
      esc = 0
      i++
      continue
    }
    if (c == "\\") { esc = 1; i++; continue }
    if (c == "\"") { i++; break }
    val = val c
    i++
  }
  return val
}

function skip_ws(obj,    n, c) {
  n = length(obj)
  while (i <= n) {
    c = substr(obj, i, 1)
    if (c != " " && c != "\t" && c != "\n" && c != "\r") break
    i++
  }
}

function parse_obj(obj,    n, c, depth, key, val, dst, dev, rtype, nd) {
  n = length(obj)
  depth = 0
  dst = ""
  dev = ""
  rtype = ""
  i = 1
  while (i <= n) {
    c = substr(obj, i, 1)
    if (c == "{" || c == "[") { depth++; i++; continue }
    if (c == "}" || c == "]") { depth--; i++; continue }
    if (c == "\"" && depth == 1) {
      key = take_string(obj)
      skip_ws(obj)
      if (substr(obj, i, 1) != ":") continue
      i++
      skip_ws(obj)
      if (substr(obj, i, 1) == "\"") {
        val = take_string(obj)
        if (key == "dst") dst = val
        else if (key == "dev") dev = val
        else if (key == "type") rtype = val
      }
      continue
    }
    i++
  }
  if (rtype == "") rtype = "unicast"
  nd = norm_dst(dst)
  if (rtype == "unreachable" && nd == "default/0" && dev == "")
    unreach++
  else if (rtype == "unicast" && nd == "10.66.0.2/32" && dev == "wg0")
    guest++
  else if (rtype == "unicast" && nd == "10.66.0.3/32" && dev == "wg0")
    phone++
  else
    other = other " [" nd " dev=" dev " type=" rtype "]"
  if (nd == "10.66.0.0/24" && dev == "wg0")
    has24 = 1
}

function parse_pref(obj,    n, c, depth, key, val, num) {
  n = length(obj)
  depth = 0
  i = 1
  while (i <= n) {
    c = substr(obj, i, 1)
    if (c == "{" || c == "[") { depth++; i++; continue }
    if (c == "}" || c == "]") { depth--; i++; continue }
    if (c == "\"" && depth == 1) {
      key = take_string(obj)
      skip_ws(obj)
      if (substr(obj, i, 1) != ":") continue
      i++
      skip_ws(obj)
      if (key == "priority" && substr(obj, i, 1) >= "0" && substr(obj, i, 1) <= "9") {
        num = ""
        while (i <= n) {
          c = substr(obj, i, 1)
          if (c < "0" || c > "9") break
          num = num c
          i++
        }
        if (task == "prefs") print num
        if (task == "haspref" && num == pref) hitpref = 1
      }
      continue
    }
    i++
  }
}

function walk(json,    n, c, depth, instr, wesc, start, wi) {
  n = length(json)
  depth = 0
  instr = 0
  wesc = 0
  start = 0
  seen = 0
  for (wi = 1; wi <= n; wi++) {
    c = substr(json, wi, 1)
    if (instr) {
      if (wesc) { wesc = 0; continue }
      if (c == "\\") { wesc = 1; continue }
      if (c == "\"") instr = 0
      continue
    }
    if (c == "\"") { instr = 1; continue }
    if (c == "[") {
      if (depth == 0) seen = 1
      depth++
      continue
    }
    if (c == "{") {
      if (depth == 1) start = wi
      depth++
      continue
    }
    if (c == "]") { depth--; continue }
    if (c == "}") {
      depth--
      if (depth == 1 && start > 0) {
        if (task == "prefs" || task == "haspref")
          parse_pref(substr(json, start, wi - start + 1))
        else
          parse_obj(substr(json, start, wi - start + 1))
        start = 0
      }
      continue
    }
  }
  if (!seen || depth != 0 || instr) {
    print "PARSE_ERROR"
    exit 2
  }
}

BEGIN {
  guest = 0
  unreach = 0
  has24 = 0
  hitpref = 0
  other = ""
  buf = ""
}
{
  buf = buf $0 "\n"
}
END {
  walk(buf)
  if (task == "assert167") {
    if (guest != 1) {
      print "guest route count " guest " want 1 (10.66.0.2/32 dev wg0; bare host and /32 are the same)" other
      exit 1
    }
    if (phone != 1) {
      print "phone route count " phone " want 1 (10.66.0.3/32 dev wg0)" other
      exit 1
    }
    if (unreach < 1) {
      print "no unreachable default" other
      exit 1
    }
    if (other != "") {
      print "unexpected" other
      exit 1
    }
    exit 0
  }
  if (task == "has24") {
    if (has24) print "yes"
    else print "no"
    exit 0
  }
  if (task == "haspref") {
    if (hitpref) print "yes"
    else print "no"
    exit 0
  }
  if (task == "prefs") exit 0
  print "unknown ip json task"
  exit 2
}
'
}

read_table_167() {
  json=$(ip -j route show table 167) || fail "ip -j route show table 167 failed"
  [ -n "$json" ] || fail "ip -j route show table 167 returned empty output"
}

table_167_has_slash24() {
  read_table_167
  got=$(printf '%s\n' "$json" | ip_json_task has24) || fail "cannot parse table 167"
  case "$got" in
    yes) return 0 ;;
    no) return 1 ;;
  esac
  fail "cannot parse table 167"
}

del_slash24_wg0() {
  tries=0
  while table_167_has_slash24; do
    tries=$((tries + 1))
    if [ "$tries" -gt 32 ]; then
      fail "table 167 still has 10.66.0.0/24 dev wg0"
    fi
    if ip route del table 167 10.66.0.0/24 dev wg0; then
      :
    else
      if table_167_has_slash24; then
        fail "ip route del table 167 10.66.0.0/24 dev wg0 failed and the route is still present"
      fi
      return 0
    fi
  done
}

assert_table_167() {
  read_table_167
  err=$(printf '%s\n' "$json" | ip_json_task assert167) && rc=0 || rc=$?
  [ "$rc" -eq 0 ] || fail "table 167: ${err}"
}

rule_pref_present() {
  if [ "$1" = 6 ]; then
    json=$(ip -j -6 rule show) || fail "ip -j -6 rule show failed"
  else
    json=$(ip -j rule show) || fail "ip -j rule show failed"
  fi
  [ -n "$json" ] || fail "ip -j rule show returned empty output"
  got=$(printf '%s\n' "$json" | ip_json_task haspref "$2") || fail "cannot parse ip rule json"
  case "$got" in
    yes) return 0 ;;
    no) return 1 ;;
  esac
  fail "cannot parse ip rule json"
}

del_rule_pref() {
  fam=$1
  pref=$2
  tries=0
  while rule_pref_present "$fam" "$pref"; do
    tries=$((tries + 1))
    if [ "$tries" -gt 32 ]; then
      fail "ip rule pref ${pref} family ${fam} still present"
    fi
    if [ "$fam" = 6 ]; then
      ip -6 rule del pref "$pref" && deleted=0 || deleted=$?
    else
      ip rule del pref "$pref" && deleted=0 || deleted=$?
    fi
    if [ "$deleted" -ne 0 ] && rule_pref_present "$fam" "$pref"; then
      fail "ip rule del pref ${pref} family ${fam} failed and the rule is still present"
    fi
  done
}

# 0 = 规则在，1 = 回读确认不在。读不到规则集、权限、锁、语法或其它错误直接失败。
rule_state() {
  bin=$1
  table=$2
  chain=$3
  shift 3
  serr=$(LC_ALL=C "$bin" -t "$table" -S "$chain" 2>&1) && src=0 || src=$?
  if [ "$src" -ne 0 ]; then
    case "$serr" in
      *"No chain/target/match by that name."*)
        return 1 ;;
    esac
    fail "${bin} cannot read ${chain}: ${serr}"
  fi
  serr=$(LC_ALL=C "$bin" -t "$table" -C "$chain" "$@" 2>&1) && crc=0 || crc=$?
  if [ "$crc" -eq 0 ]; then
    return 0
  fi
  case "$serr" in
    *"Bad rule (does a matching rule exist in that chain?)."*)
      return 1 ;;
  esac
  fail "${bin} cannot check ${chain}: ${serr}"
}

rule_absent() {
  rule_state "$@" && st=0 || st=$?
  [ "$st" -eq 1 ]
}

rule_present() {
  rule_state "$@" && st=0 || st=$?
  [ "$st" -eq 0 ]
}

# 精确 -D。成功只表示回读确认目标已经不在。不 -F，不清空整表。
rule_del() {
  bin=$1
  shift
  table=filter
  if [ "${1:-}" = "-t" ]; then
    table=$2
    shift 2
  fi
  if [ "${1:-}" != "-D" ]; then
    fail "rule_del: expected -D"
  fi
  shift
  chain=${1:-}
  [ -n "$chain" ] || fail "rule_del: missing chain"
  shift
  tries=0
  while :; do
    if rule_absent "$bin" "$table" "$chain" "$@"; then
      return 0
    fi
    tries=$((tries + 1))
    if [ "$tries" -gt 32 ]; then
      fail "${bin} -D ${chain} still present after repeated deletes"
    fi
    if LC_ALL=C "$bin" -t "$table" -D "$chain" "$@"; then
      :
    else
      if rule_absent "$bin" "$table" "$chain" "$@"; then
        return 0
      fi
      fail "${bin} -D ${chain} failed and the rule is still present"
    fi
  done
}

reject_with() {
  if [ "$1" = iptables ]; then
    printf '%s\n' icmp-port-unreachable
  else
    printf '%s\n' icmp6-port-unreachable
  fi
}

first_rule() {
  bin=$1
  chain=$2
  if ! rules=$("$bin" -S "$chain" 2>/dev/null); then
    return 1
  fi
  printf '%s\n' "$rules" | awk -v c="$chain" '$1 == "-A" && $2 == c { print; exit }'
}

ensure_reject() {
  bin=$1
  chain=$2
  shift 2
  rej=$(reject_with "$bin")
  if ! "$bin" -t filter -C "$chain" "$@" -j REJECT --reject-with "$rej" 2>/dev/null; then
    "$bin" -t filter -A "$chain" "$@" -j REJECT --reject-with "$rej"
  fi
}

hook_first() {
  bin=$1
  chain=$2
  target=$3
  want="-A ${chain} -j ${target}"
  got=$(first_rule "$bin" "$chain" || true)
  if [ "$got" != "$want" ]; then
    "$bin" -t filter -I "$chain" 1 -j "$target"
  fi
  got=$(first_rule "$bin" "$chain" || true)
  [ "$got" = "$want" ] || fail "jump is not first on ${chain}"
}

# 先写满拒绝并 -C 通过，再挂跳转。不把空链先挂到首位。
ensure_phase_a() {
  bin=$1
  require_egress_uid
  uid=$EGRESS_UID
  "$bin" -t filter -N SB-FWD 2>/dev/null || true
  "$bin" -t filter -N SB-EGRESS 2>/dev/null || true
  "$bin" -t filter -N SB-INPUT 2>/dev/null || true
  ensure_reject "$bin" SB-FWD -i tun0
  ensure_reject "$bin" SB-FWD -i wg0
  ensure_reject "$bin" SB-FWD -o wg0
  ensure_reject "$bin" SB-EGRESS -m owner --uid-owner "$uid"
  ensure_reject "$bin" SB-INPUT -i tun0
  ensure_reject "$bin" SB-INPUT -i wg0
  rej=$(reject_with "$bin")
  "$bin" -t filter -C SB-FWD -i tun0 -j REJECT --reject-with "$rej"
  "$bin" -t filter -C SB-FWD -i wg0 -j REJECT --reject-with "$rej"
  "$bin" -t filter -C SB-FWD -o wg0 -j REJECT --reject-with "$rej"
  "$bin" -t filter -C SB-EGRESS -m owner --uid-owner "$uid" -j REJECT --reject-with "$rej"
  "$bin" -t filter -C SB-INPUT -i tun0 -j REJECT --reject-with "$rej"
  "$bin" -t filter -C SB-INPUT -i wg0 -j REJECT --reject-with "$rej"
  if [ "$bin" = ip6tables ]; then
    hook_fwd=ufw6-before-forward
    hook_out=ufw6-before-output
    hook_in=ufw6-before-input
  else
    hook_fwd=ufw-before-forward
    hook_out=ufw-before-output
    hook_in=ufw-before-input
  fi
  hook_first "$bin" "$hook_fwd" SB-FWD
  hook_first "$bin" "$hook_out" SB-EGRESS
  hook_first "$bin" "$hook_in" SB-INPUT
}

norm_rules() {
  sed -E -e 's#/32([[:space:]]|$)#\1#g' -e 's#/128([[:space:]]|$)#\1#g' -e 's/(^|:)0+([0-9a-fA-F])/\1\2/g' -e 's/--set-xmark (0x[0-9a-fA-F]+)\/0xffffffff/--set-mark \1/g'
}

chain_state() {
  bin=$1
  table=$2
  chain=$3
  err=$(LC_ALL=C "$bin" -t "$table" -S "$chain" 2>&1 >/dev/null) && return 0 || true
  case "$err" in
    *"No chain/target/match by that name."*)
      return 1 ;;
  esac
  fail "${bin} cannot read ${chain}: ${err}"
}

ensure_rule() {
  bin=$1
  table=$2
  chain=$3
  shift 3
  if rule_present "$bin" "$table" "$chain" "$@"; then
    return 0
  fi
  if rule_absent "$bin" "$table" "$chain" "$@"; then
    "$bin" -t "$table" -A "$chain" "$@" || fail "cannot append ${chain} rule"
    rule_present "$bin" "$table" "$chain" "$@" || fail "${chain} rule not confirmed after insert"
    return 0
  fi
  fail "${chain} rule state is unknown"
}

ensure_mark() {
  bin=$1
  if [ "$bin" = ip6tables ]; then
    dst1=::1
    dst2="<VPS_IPV6>"
    dst3="<VPS_LINK_LOCAL>"
  else
    dst1=127.0.0.1
    dst2="<VPS_IP>"
    dst3=10.66.0.1
  fi
  if chain_state "$bin" mangle SB-MARK; then
    :
  else
    "$bin" -t mangle -N SB-MARK || fail "cannot create SB-MARK"
    chain_state "$bin" mangle SB-MARK || fail "SB-MARK is not present after create"
  fi
  ensure_rule "$bin" mangle SB-MARK -d "$dst1" -j RETURN
  ensure_rule "$bin" mangle SB-MARK -d "$dst2" -j RETURN
  ensure_rule "$bin" mangle SB-MARK -d "$dst3" -j RETURN
  ensure_rule "$bin" mangle SB-MARK -j MARK --set-mark 0x66
  ensure_rule "$bin" mangle PREROUTING -i wg0 -j SB-MARK
  want=$(printf -- '-N SB-MARK\n-A SB-MARK -d %s -j RETURN\n-A SB-MARK -d %s -j RETURN\n-A SB-MARK -d %s -j RETURN\n-A SB-MARK -j MARK --set-mark 0x66\n' "$dst1" "$dst2" "$dst3")
  got=$("$bin" -t mangle -S SB-MARK) || fail "cannot read SB-MARK"
  [ "$(printf '%s\n' "$got" | norm_rules)" = "$(printf '%s\n' "$want" | norm_rules)" ] \
    || fail "SB-MARK rules are not the section 6 sequence"
  pre_rules=$(LC_ALL=C "$bin" -t mangle -S PREROUTING 2>&1) || fail "cannot read PREROUTING"
  hook_count=$(printf '%s\n' "$pre_rules" | grep -c -- '-A PREROUTING -i wg0 -j SB-MARK' || true)
  [ "$hook_count" -eq 1 ] || fail "PREROUTING SB-MARK hook is not unique"
  first_pre=$(printf '%s\n' "$pre_rules" | awk '$1=="-A" && $2=="PREROUTING" {print; exit}')
  [ "$first_pre" = "-A PREROUTING -i wg0 -j SB-MARK" ] || fail "PREROUTING SB-MARK hook is not first"
}

assert_no_ctstate() {
  bin=$1
  chain=$2
  if ! rules=$("$bin" -S "$chain" 2>/dev/null); then
    fail "${bin} -S ${chain} failed"
  fi
  if printf '%s\n' "$rules" | grep -q -- '--ctstate'; then
    fail "${bin} ${chain} is limited by ctstate"
  fi
}

assert_no_return() {
  bin=$1
  chain=$2
  if ! rules=$("$bin" -S "$chain" 2>/dev/null); then
    fail "${bin} -S ${chain} failed"
  fi
  if printf '%s\n' "$rules" | grep -q -- '-j RETURN'; then
    fail "${bin} ${chain} has RETURN; wg0 or tun0 could fall through"
  fi
}

assert_fwd_accepts() {
  if ! rules=$(iptables -S SB-FWD 2>/dev/null); then
    fail "iptables -S SB-FWD failed"
  fi
  bad=$(printf '%s\n' "$rules" | awk '
    $1 == "-A" && $2 == "SB-FWD" && /-j ACCEPT$/ {
      forward = (($0 ~ /-s 10\.66\.0\.2\/32/ || $0 ~ /-s 10\.66\.0\.3\/32/) && $0 ~ /-i wg0/ && $0 ~ /-o tun0/ && $0 !~ /-d /)
      ret = (($0 ~ /-d 10\.66\.0\.2\/32/ || $0 ~ /-d 10\.66\.0\.3\/32/) && $0 ~ /-i tun0/ && $0 ~ /-o wg0/ && $0 !~ /-s /)
      if ($0 ~ /10\.66\.0\.0\/24/ || (!forward && !ret)) print
    }
  ')
  [ -z "$bad" ] || fail "unexpected v4 accept: ${bad}"
  if ! rules6=$(ip6tables -S SB-FWD 2>/dev/null); then
    fail "ip6tables -S SB-FWD failed"
  fi
  if printf '%s\n' "$rules6" | grep -q -- '-j ACCEPT'; then
    fail "ip6 SB-FWD has an accept"
  fi
}

assert_egress_accepts() {
  require_egress_uid
  uid=$EGRESS_UID
  if ! rules=$(iptables -S SB-EGRESS 2>/dev/null); then
    fail "iptables -S SB-EGRESS failed"
  fi
  bad=$(printf '%s\n' "$rules" | awk -v want="$uid" -v want_path="$LEAF_PATH" '
    function norm_v4(d, n, a) {
      n = split(d, a, "/")
      if (n == 1 && d ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return d "/32"
      if (n == 2 && a[2] == "32" && a[1] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return a[1] "/32"
      return d
    }
    $1 == "-A" && $2 == "SB-EGRESS" {
      j = ""
      for (i = 1; i <= NF; i++) if ($i == "-j" && i < NF) j = $(i+1)
      if (j != "ACCEPT") next
      if ($0 ~ /!/) { print; next }
      uid = ""; path = ""; proto = ""; dst = ""; dport = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "--uid-owner" && i < NF) { uid = $(i+1); i++ }
        else if ($i == "--path" && i < NF) { path = $(i+1); sub(/^"/, "", path); sub(/"$/, "", path); i++ }
        else if ($i == "-p" && i < NF) { proto = $(i+1); i++ }
        else if ($i == "-d" && i < NF) { dst = $(i+1); i++ }
        else if ($i == "--dport" && i < NF) { dport = $(i+1); i++ }
      }
      if (!(uid == want && path == want_path && proto == "tcp" && norm_v4(dst) == "<出口_IP>/32" && dport == "12324"))
        print
    }
  ') || fail "cannot enumerate SB-EGRESS accepts"
  [ -z "$bad" ] || fail "unexpected v4 egress accept: ${bad}"
  if ! rules6=$(ip6tables -S SB-EGRESS 2>/dev/null); then
    fail "ip6tables -S SB-EGRESS failed"
  fi
  if printf '%s\n' "$rules6" | grep -q -- '-j ACCEPT'; then
    fail "ip6 SB-EGRESS has an accept"
  fi
}

assert_input_closed() {
  bin=$1
  if ! rules=$("$bin" -S SB-INPUT 2>/dev/null); then
    fail "${bin} -S SB-INPUT failed"
  fi
  if printf '%s\n' "$rules" | grep -q -- '-j ACCEPT'; then
    fail "${bin} SB-INPUT has an accept; local allow-set is not empty"
  fi
}

check_deny() {
  require_egress_uid
  uid=$EGRESS_UID
  for bin in iptables ip6tables; do
    rej=$(reject_with "$bin")
    if [ "$bin" = ip6tables ]; then
      hook_fwd=ufw6-before-forward
      hook_out=ufw6-before-output
      hook_in=ufw6-before-input
    else
      hook_fwd=ufw-before-forward
      hook_out=ufw-before-output
      hook_in=ufw-before-input
    fi
    "$bin" -t filter -C SB-FWD -i tun0 -j REJECT --reject-with "$rej"
    "$bin" -t filter -C SB-FWD -i wg0 -j REJECT --reject-with "$rej"
    "$bin" -t filter -C SB-FWD -o wg0 -j REJECT --reject-with "$rej"
    "$bin" -t filter -C SB-EGRESS -m owner --uid-owner "$uid" -j REJECT --reject-with "$rej"
    "$bin" -t filter -C SB-INPUT -i tun0 -j REJECT --reject-with "$rej"
    "$bin" -t filter -C SB-INPUT -i wg0 -j REJECT --reject-with "$rej"
    [ "$(first_rule "$bin" "$hook_fwd")" = "-A ${hook_fwd} -j SB-FWD" ] || fail "${bin} forward jump"
    [ "$(first_rule "$bin" "$hook_out")" = "-A ${hook_out} -j SB-EGRESS" ] || fail "${bin} output jump"
    [ "$(first_rule "$bin" "$hook_in")" = "-A ${hook_in} -j SB-INPUT" ] || fail "${bin} input jump"
    assert_no_ctstate "$bin" SB-FWD
    assert_no_ctstate "$bin" SB-EGRESS
    assert_no_ctstate "$bin" SB-INPUT
    assert_no_return "$bin" SB-FWD
    assert_no_return "$bin" SB-EGRESS
    assert_no_return "$bin" SB-INPUT
    if "$bin" -S SB-FWD | grep -q -- '-i wg0 -o enp1s0'; then
      fail "${bin} SB-FWD still has an enp1s0-only wg0 rule"
    fi
    assert_input_closed "$bin"
  done
  assert_fwd_accepts
  assert_egress_accepts
}

pre_start() {
  # 与 down_cmd/on_err/refresh_leaf_only 同一独立清理：先撤销旧独立层许可与凭证，
  # 清理失败拒绝继续启动（不带旧许可进入新启动过程）。
  cleanup_guard || fail "pre_start: cleanup_guard failed; refusing to start"
  [ -f "$CONF" ] || fail "config missing"
  grep -q '"detour": "socks-out"' "$CONF" || fail "dns detour missing"
  grep -F -q "$TUN_ADDR" "$CONF" || fail "tun address is not ${TUN_ADDR}"
  grep -F -q '<出口_IP>' "$CONF" || fail "socks endpoint missing in config"
  grep -F -q '1.1.1.1' "$CONF" || fail "dns placeholder missing"
  if grep -q '"type": "direct"' "$CONF"; then
    fail "direct outbound"
  fi
  sing-box check -c "$CONF"
  check_deny
}

iface_ready() {
  n=0
  while [ "$n" -lt 15 ]; do
    if ip -o link show dev tun0 >/dev/null 2>&1 \
      && ip -4 addr show dev tun0 | grep -F -q "inet ${TUN_ADDR}"; then
      return 0
    fi
    n=$((n + 1))
    sleep 1
  done
  fail "tun0 is not up with ${TUN_ADDR}"
}

refresh_routes() {
  ip route replace table 167 unreachable default
  del_slash24_wg0
  ip route replace table 167 10.66.0.2/32 dev wg0
  ip route replace table 167 10.66.0.3/32 dev wg0
  assert_table_167
  del_rule_pref 4 100
  del_rule_pref 4 101
  ip rule add pref 101 iif tun0 unreachable
  ip rule add pref 100 iif tun0 lookup 167
  del_rule_pref 4 110
  del_rule_pref 4 111
  ip rule add pref 111 fwmark 0x66 unreachable
  ip route replace table 166 default dev tun0
  ip rule add pref 110 fwmark 0x66 lookup 166
  ip -6 route replace table 167 unreachable default
  del_rule_pref 6 100
  del_rule_pref 6 101
  ip -6 rule add pref 101 iif tun0 unreachable
  ip -6 rule add pref 100 iif tun0 lookup 167
  del_rule_pref 6 110
  del_rule_pref 6 111
  ip -6 rule add pref 111 fwmark 0x66 unreachable
  ip -6 route replace table 166 default dev tun0
  ip -6 rule add pref 110 fwmark 0x66 lookup 166
}

install_return() {
  rule_del iptables -t filter -D SB-FWD -i tun0 -o wg0 -d 10.66.0.0/24 -j ACCEPT
  iptables -t filter -C SB-FWD -i tun0 -o wg0 -d 10.66.0.2/32 -j ACCEPT 2>/dev/null \
    || iptables -t filter -I SB-FWD 1 -i tun0 -o wg0 -d 10.66.0.2/32 -j ACCEPT
  iptables -t filter -C SB-FWD -i tun0 -o wg0 -d 10.66.0.3/32 -j ACCEPT 2>/dev/null \
    || iptables -t filter -I SB-FWD 1 -i tun0 -o wg0 -d 10.66.0.3/32 -j ACCEPT
}

withdraw_e() {
  rule_del iptables -t filter -D SB-FWD -i wg0 -o tun0 -s 10.66.0.2/32 -j ACCEPT
  rule_del iptables -t filter -D SB-FWD -i wg0 -o tun0 -s 10.66.0.3/32 -j ACCEPT
  rule_del iptables -t filter -D SB-FWD -i tun0 -o wg0 -d 10.66.0.0/24 -j ACCEPT
}

down_cmd() {
  w_rc=0
  c_rc=0
  ( withdraw_e ) || w_rc=$?
  ( cleanup_guard ) || c_rc=$?
  if [ "$w_rc" -ne 0 ]; then
    printf 'sing-box-egress-net: down: withdraw_e did not succeed (rc=%s); stage E closure is uncertain\n' "$w_rc" >&2
  fi
  if [ "$c_rc" -ne 0 ]; then
    printf 'sing-box-egress-net: down: cleanup_guard did not succeed (rc=%s); guard/credential cleanup is uncertain\n' "$c_rc" >&2
  fi
  [ "$w_rc" -eq 0 ] && [ "$c_rc" -eq 0 ] || return 1
}

refresh_leaf() {
  [ -d "$LEAF_DIR" ] || fail "leaf cgroup missing"
  require_egress_uid
  uid=$EGRESS_UID
  ino=$(stat -c '%i' "$LEAF_DIR")
  rej4=$(reject_with iptables)
  rej6=$(reject_with ip6tables)
  rule_del iptables -t filter -D SB-EGRESS \
    -m owner --uid-owner "$uid" -m cgroup --path "$LEAF_PATH" \
    -p tcp -d <出口_IP> --dport 12324 -j ACCEPT
  rule_del iptables -t filter -D SB-EGRESS \
    -m cgroup --path "$LEAF_PATH" -m owner ! --uid-owner "$uid" \
    -j REJECT --reject-with "$rej4"
  rule_del ip6tables -t filter -D SB-EGRESS \
    -m cgroup --path "$LEAF_PATH" -m owner ! --uid-owner "$uid" \
    -j REJECT --reject-with "$rej6"
  ino_now=$(stat -c '%i' "$LEAF_DIR")
  [ "$ino" = "$ino_now" ] || fail "cgroup replaced while withdrawing --path"
  iptables -t filter -I SB-EGRESS 1 \
    -m cgroup --path "$LEAF_PATH" -m owner ! --uid-owner "$uid" \
    -j REJECT --reject-with "$rej4"
  iptables -t filter -I SB-EGRESS 1 \
    -m owner --uid-owner "$uid" -m cgroup --path "$LEAF_PATH" \
    -p tcp -d <出口_IP> --dport 12324 -j ACCEPT
  ip6tables -t filter -I SB-EGRESS 1 \
    -m cgroup --path "$LEAF_PATH" -m owner ! --uid-owner "$uid" \
    -j REJECT --reject-with "$rej6"
  iptables -t filter -C SB-EGRESS \
    -m owner --uid-owner "$uid" -m cgroup --path "$LEAF_PATH" \
    -p tcp -d <出口_IP> --dport 12324 -j ACCEPT \
    || fail "egress accept not confirmed after insert"
  iptables -t filter -C SB-EGRESS \
    -m cgroup --path "$LEAF_PATH" -m owner ! --uid-owner "$uid" \
    -j REJECT --reject-with "$rej4" \
    || fail "v4 non-owner leaf reject not confirmed after insert"
  ip6tables -t filter -C SB-EGRESS \
    -m cgroup --path "$LEAF_PATH" -m owner ! --uid-owner "$uid" \
    -j REJECT --reject-with "$rej6" \
    || fail "v6 non-owner leaf reject not confirmed after insert"
  ino_after=$(stat -c '%i' "$LEAF_DIR")
  [ "$ino" = "$ino_after" ] || fail "cgroup replaced during --path insert"
  mkdir -p "$STATE_DIR"
  printf '%s\n' "$ino_after" > "$INO_FILE"
  # 写事实文件（代次仅内容变化时递增，见 §4.4）并应用防护层（不带 --allow-e，永不产生 forward 许可）。
  # 端点常量与本函数 OUTPUT ACCEPT 规则同一来源（真实出口，E 批次与配置同批替换）。
  cfg_sha=$(sha256sum "$CONF" 2>/dev/null | awk '{print $1}') || fail "cannot hash config"
  [ -n "$cfg_sha" ] || fail "cannot hash config"
  write_facts "$ino_after" "<出口_IP>" "12324" "$cfg_sha"
  sbguard_apply || fail "cannot apply sbguard rules"
}

refresh_leaf_only() {
  w_rc=0
  c_rc=0
  ( withdraw_e ) || w_rc=$?
  ( cleanup_guard ) || c_rc=$?
  if [ "$w_rc" -ne 0 ]; then
    printf 'sing-box-egress-net: refresh-leaf-only: withdraw_e did not succeed (rc=%s)\n' "$w_rc" >&2
  fi
  if [ "$c_rc" -ne 0 ]; then
    printf 'sing-box-egress-net: refresh-leaf-only: cleanup_guard did not succeed (rc=%s)\n' "$c_rc" >&2
  fi
  [ "$w_rc" -eq 0 ] && [ "$c_rc" -eq 0 ] || fail "refresh-leaf-only: withdraw_e / cleanup_guard did not both succeed; refusing to refresh"
  rule_absent iptables filter SB-FWD -i wg0 -o tun0 -s 10.66.0.2/32 -j ACCEPT \
    || fail "stage E accept is still present; refresh-leaf-only is not permitted"
  rule_absent iptables filter SB-FWD -i wg0 -o tun0 -s 10.66.0.3/32 -j ACCEPT \
    || fail "phone stage E accept is still present; refresh-leaf-only is not permitted"
  check_deny
  refresh_leaf
  check_leaf
}

check_leaf() {
  [ -d "$LEAF_DIR" ] || fail "leaf cgroup missing"
  [ -f "$INO_FILE" ] || fail "cgroup inode was not recorded"
  live=$(stat -c '%i' "$LEAF_DIR")
  saved=$(cat "$INO_FILE")
  [ "$live" = "$saved" ] || fail "cgroup inode changed; same path string is not a pass"
}

install_e() {
  check_deny
  check_leaf
  iptables -t filter -C SB-FWD -i tun0 -o wg0 -d 10.66.0.2/32 -j ACCEPT
  iptables -t filter -C SB-FWD -i tun0 -o wg0 -d 10.66.0.3/32 -j ACCEPT
  if rule_present iptables filter SB-FWD -i tun0 -o wg0 -d 10.66.0.0/24 -j ACCEPT; then
    fail "/24 return accept is still present"
  fi
  assert_table_167
  iptables -t filter -C SB-FWD -i wg0 -o tun0 -s 10.66.0.2/32 -j ACCEPT 2>/dev/null \
    || iptables -t filter -I SB-FWD 1 -i wg0 -o tun0 -s 10.66.0.2/32 -j ACCEPT
  iptables -t filter -C SB-FWD -i wg0 -o tun0 -s 10.66.0.3/32 -j ACCEPT 2>/dev/null \
    || iptables -t filter -I SB-FWD 1 -i wg0 -o tun0 -s 10.66.0.3/32 -j ACCEPT
  rules6=$(ip6tables -S SB-FWD) || fail "ip6tables -S SB-FWD failed"
  if printf '%s\n' "$rules6" | grep -q -- '-j ACCEPT'; then
    rule_del iptables -t filter -D SB-FWD -i wg0 -o tun0 -s 10.66.0.2/32 -j ACCEPT
    rule_del iptables -t filter -D SB-FWD -i wg0 -o tun0 -s 10.66.0.3/32 -j ACCEPT
    fail "ip6 SB-FWD has an accept"
  fi
  assert_fwd_accepts
  # 独立层 E 许可：全部放行核对成功后的最后一步（v6 检查已过）。
  # 此前任何失败均已删除 v4 UFW 许可并 fail，不会到达此处。
  sbguard_apply --allow-e || fail "cannot enable guard forward accepts"
}

on_err() {
  trap - EXIT
  w_rc=0
  r_rc=0
  # 串行化：on_err 只在持有锁时清理（分发器经 with_lock 进入 up/ufw-after 时 LOCK_HELD=1）。
  # 未持有锁（锁竞争失败）时不触碰任何状态——另一持有者正在做自己的状态变更，
  # 此时清理会与之交错；如实报告"清理延后"，由持有者自己的路径收尾。
  if [ "${LOCK_HELD:-0}" != "1" ]; then
    printf 'sing-box-egress-net: on_err: guard lock not held; cleanup deferred to the lock holder\n' >&2
    exit 1
  fi
  ( withdraw_e ) || w_rc=$?
  ( cleanup_guard ) || r_rc=$?
  if [ "$w_rc" -ne 0 ]; then
    printf 'sing-box-egress-net: on_err: withdraw_e did not succeed (rc=%s); stage E closure is uncertain\n' "$w_rc" >&2
  fi
  if [ "$r_rc" -ne 0 ]; then
    printf 'sing-box-egress-net: on_err: cleanup_guard did not succeed (rc=%s); guard/credential cleanup is uncertain; residual not cleared\n' "$r_rc" >&2
  fi
  exit 1
}

revoke_release() {
  if [ -L "$REL_FILE" ]; then
    rm -f "$REL_FILE" || fail "cannot revoke release credential (symbolic link)"
  elif [ -d "$REL_FILE" ]; then
    fail "release credential is a directory; refusing to remove"
  elif [ -e "$REL_FILE" ]; then
    rm -f "$REL_FILE" || fail "cannot revoke release credential"
  fi
  if [ -e "$REL_FILE" ] || [ -L "$REL_FILE" ]; then
    fail "release credential is still present after revoke"
  fi
}

require_release() {
  [ -d "$STATE_DIR" ] || fail "release state directory is missing"
  [ ! -L "$STATE_DIR" ] || fail "release state directory is a symbolic link"
  dir_owner=$(stat -c %U "$STATE_DIR" 2>/dev/null) \
    || fail "cannot read release state directory owner"
  [ -n "$dir_owner" ] || fail "cannot read release state directory owner"
  [ "$dir_owner" = root ] || fail "release state directory is not root-owned"
  dir_perms=$(stat -c %A "$STATE_DIR" 2>/dev/null) \
    || fail "cannot read release state directory permissions"
  [ -n "$dir_perms" ] || fail "cannot read release state directory permissions"
  case "$dir_perms" in
    ?????w*|????????w?) fail "release state directory is group- or world-writable" ;;
  esac
  [ ! -L "$REL_FILE" ] || fail "release credential is a symbolic link"
  [ -f "$REL_FILE" ] || fail "no release credential; install_e is not permitted"
  file_owner=$(stat -c %U "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential owner"
  [ -n "$file_owner" ] || fail "cannot read release credential owner"
  [ "$file_owner" = root ] || fail "release credential is not root-owned"
  file_mode=$(stat -c %a "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential mode"
  [ -n "$file_mode" ] || fail "cannot read release credential mode"
  [ "$file_mode" = 600 ] || fail "release credential is not mode 600"
  line_count=$(wc -l < "$REL_FILE" 2>/dev/null | awk '{print $1}') \
    || fail "cannot read release credential"
  [ -n "$line_count" ] || fail "cannot read release credential"
  [ "$line_count" -eq 5 ] || fail "release credential is malformed"
  [ -d "$LEAF_DIR" ] || fail "leaf cgroup missing"
  live=$(stat -c '%i' "$LEAF_DIR" 2>/dev/null) \
    || fail "cannot read leaf cgroup inode"
  [ -n "$live" ] || fail "cannot read leaf cgroup inode"
  saved_ino=$(sed -n '1p' "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential inode"
  saved_ref=$(sed -n '2p' "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential reference"
  saved_cfg=$(sed -n '3p' "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential config digest"
  saved_ver=$(sed -n '4p' "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential facts version"
  saved_digest=$(sed -n '5p' "$REL_FILE" 2>/dev/null) \
    || fail "cannot read release credential facts digest"
  [ -n "$saved_ino" ] || fail "release credential has no inode"
  [ -n "$saved_ref" ] || fail "release credential has no verification reference"
  [ -n "$saved_cfg" ] || fail "release credential has no config digest"
  [ "$live" = "$saved_ino" ] \
    || fail "release credential is for a different cgroup leaf; re-verify before install_e"
  [ -f "$CONF" ] || fail "config missing"
  cfg_now=$(sha256sum "$CONF" 2>/dev/null | awk '{print $1}') \
    || fail "cannot hash config"
  [ -n "$cfg_now" ] || fail "cannot hash config"
  [ "$cfg_now" = "$saved_cfg" ] \
    || fail "release credential is for a different config; re-verify before install_e"
  # 事实文件代次严格相等核对：放行信第四行须等于当前事实文件的 version。
  read_facts || fail "cannot read facts for release check"
  [ -n "$saved_ver" ] || fail "release credential has no facts version"
  [ "$F_VERSION" = "$saved_ver" ] \
    || fail "release credential is for a different facts generation; re-verify before install_e"
  # 事实内容摘要绑定（第五行）：规范化授权事实内容的 sha256，须与当前事实文件逐字段一致。
  # 代次只作辅助核对；内容摘要才是跨生命周期不复用的绑定——facts 删除后 version 从 1 重置，
  # 相同 version 不能证明内容相同。
  [ -n "$saved_digest" ] || fail "release credential has no facts digest"
  body_now=$(facts_body_digest) || fail "cannot hash facts body"
  [ -n "$body_now" ] || fail "cannot hash facts body"
  [ "$body_now" = "$saved_digest" ] \
    || fail "release credential is for different facts content; re-verify before install_e"
  # 事实文件所记 inode/配置摘要须与当前实读相符（不只比 version）：
  [ "$F_LEAF_INO" = "$live" ] \
    || fail "facts leaf inode does not match the live leaf; re-verify before install_e"
  [ "$F_CONFIG_SHA" = "$cfg_now" ] \
    || fail "facts config digest does not match the live config; re-verify before install_e"
}

up() {
  withdraw_e
  check_deny
  iface_ready
  install_return
  refresh_routes
  refresh_leaf
  require_release
  install_e
}

ufw_after() {
  ensure_phase_a iptables
  ensure_phase_a ip6tables
  ensure_mark iptables
  ensure_mark ip6tables
  check_deny
  if systemctl is-active --quiet sing-box-egress.service; then
    up
  fi
}

nat_down() {
  rule_del iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o enp1s0 -j MASQUERADE
}

cmd=${1:-}
case "$cmd" in
  pre-start) with_lock pre_start ;;
  up)
    trap on_err EXIT
    with_lock up
    trap - EXIT
    ;;
  down) with_lock down_cmd ;;
  ufw-after)
    trap on_err EXIT
    with_lock ufw_after
    trap - EXIT
    ;;
  sbguard-apply) with_lock sbguard_apply ;;
  nat-down) with_lock nat_down ;;
  refresh-leaf-only) with_lock refresh_leaf_only ;;
  revoke-release) with_lock revoke_release ;;
  *) fail "usage: pre-start|up|down|ufw-after|nat-down|refresh-leaf-only|revoke-release|sbguard-apply" ;;
esac
