#!/bin/zsh
export PATH=/opt/homebrew/bin:$PATH
export LIMA_HOME=/Volumes/<VM卷名>/lima
if [ ! -d /Volumes/<VM卷名>/lima ]; then
  hdiutil attach "/Volumes/<外置盘>/ClaudeVM.sparseimage" >/dev/null 2>&1
fi
limactl start claude-vm >/dev/null 2>&1
echo "正在进入 Claude 虚拟机（Ubuntu），输入 exit 可回到 Mac…"
limactl shell claude-vm
