#!/bin/zsh
export PATH=/opt/homebrew/bin:$PATH
export LIMA_HOME=/Volumes/<VM卷名>/lima
if [ ! -d /Volumes/<VM卷名>/lima ]; then
  hdiutil attach "/Volumes/<外置盘>/ClaudeVM.sparseimage" >/dev/null 2>&1
fi
limactl start claude-vm >/dev/null 2>&1
limactl shell claude-vm -- bash -c "pgrep -x Xtigervnc >/dev/null || vncserver :1 -geometry 1440x900 -depth 24 -localhost no -SecurityTypes VncAuth" >/dev/null 2>&1
sleep 2
open "vnc://127.0.0.1:5901"
