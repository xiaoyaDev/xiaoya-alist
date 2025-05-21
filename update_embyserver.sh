#!/bin/bash
# shellcheck shell=bash
PATH=${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin:/opt/homebrew/bin
export PATH
#
# ——————————————————————————————————————————————————————————————————————————————————
# __   ___                                    _ _     _
# \ \ / (_)                             /\   | (_)   | |
#  \ V / _  __ _  ___  _   _  __ _     /  \  | |_ ___| |_
#   > < | |/ _` |/ _ \| | | |/ _` |   / /\ \ | | / __| __|
#  / . \| | (_| | (_) | |_| | (_| |  / ____ \| | \__ \ |_
# /_/ \_\_|\__,_|\___/ \__, |\__,_| /_/    \_\_|_|___/\__|
#                       __/ |
#                      |___/
#
# Copyright (c) 2024 DDSRem <https://blog.ddsrem.com>
#
# This is free software, licensed under the GNU General Public License v3.0.
#
# ——————————————————————————————————————————————————————————————————————————————————

Sky_Blue="\033[36m"
Green="\033[32m"
Red="\033[31m"
Yellow='\033[33m'
Font="\033[0m"
INFO="[${Green}INFO${Font}]"
ERROR="[${Red}ERROR${Font}]"
WARN="[${Yellow}WARN${Font}]"
DEBUG="[${Sky_Blue}DEBUG${Font}]"
function INFO() {
    echo -e "${INFO} ${1}"
}
function ERROR() {
    echo -e "${ERROR} ${1}"
}
function WARN() {
    echo -e "${WARN} ${1}"
}
function DEBUG() {
    echo -e "${DEBUG} ${1}"
}

if [ -z "${1}" ]; then
    EMBY_NAME=emby
fi

if [ -z "${2}" ]; then
    XIAOYA_NAME=xiaoya
fi

INFO "获取 ${EMBY_NAME} 容器 IP"
emby_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${EMBY_NAME}")"
if [ -n "${emby_ip}" ]; then
    INFO "${EMBY_NAME} 容器 IP：${emby_ip}"
else
    ERROR "获取 ${EMBY_NAME} 容器 IP 错误！"
    exit 1
fi

INFO "配置 emby_server.txt 文件中"
config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "${XIAOYA_NAME}" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
if [ -z "${config_dir}" ]; then
    WARN "小雅容器配置目录获取失败，请手动重启！"
    exit 1
fi
echo "http://$emby_ip:6908" > "${config_dir}"/emby_server.txt

INFO "重启小雅容器"
docker restart "${XIAOYA_NAME}"
