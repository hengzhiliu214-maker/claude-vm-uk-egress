#!/bin/sh
# 开源分享版注：来宾机原件为单行字面转义形式（写入时换行未生效），本文件按原意恢复为正常格式，逻辑未改。
printf '' | gnome-keyring-daemon --daemonize --unlock --components=pkcs11,secrets,ssh
