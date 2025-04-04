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
#
DATE_VERSION="v1.0.2-2024_04_13_20_37"
#
# ——————————————————————————————————————————————————————————————————————————————————

Sky_Blue="\033[36m"
Blue="\033[34m"
Green="\033[32m"
Red="\033[31m"
Yellow='\033[33m'
Font="\033[0m"
INFO="[${Green}INFO${Font}]"
ERROR="[${Red}ERROR${Font}]"
WARN="[${Yellow}WARN${Font}]"
function INFO() {
    echo -e "${INFO} ${1}"
}
function ERROR() {
    echo -e "${ERROR} ${1}"
}
function WARN() {
    echo -e "${WARN} ${1}"
}

function sedsh() {

    if [[ "$(uname -s)" = "Darwin" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi

}

function get_dev_dri() {

    if [ "${dev_dri}" == "no" ]; then
        echo -e "${Red}关闭${Font}"
    elif [ "${dev_dri}" == "yes" ]; then
        echo -e "${Green}开启${Font}"
    else
        echo -e "${Red}错误${Font}"
    fi

}

function set_dev_dri() {

    if [ "${dev_dri}" == "no" ]; then
        new_dev_dri=yes
    elif [ "${dev_dri}" == "yes" ]; then
        new_dev_dri=no
    else
        new_dev_dri=no
    fi

    sedsh "s/dev_dri=.*/dev_dri=${new_dev_dri}/" "${config_dir}/emby_config.txt"

}

function set_mode() {

    if [ "${mode}" == "bridge" ]; then
        new_mode=host
    elif [ "${mode}" == "host" ]; then
        new_mode=bridge
    else
        new_mode=host
    fi

    sedsh "s/mode=.*/mode=${new_mode}/" "${config_dir}/emby_config.txt"

}

function set_image() {

    if [ "${image}" == "emby" ]; then
        new_image=amilys
    elif [ "${image}" == "amilys" ]; then
        new_image=emby
    else
        new_image=emby
    fi

    CPU_ARCH=$(uname -m)
    case $CPU_ARCH in
    "aarch64" | *"arm64"* | *"armv8"* | *"arm/v8"*)
        new_image=emby
        WARN "arm64 只支持官方镜像！"
        INFO "按任意键继续配置"
        read -rs -n 1 -p ""
        ;;
    esac

    sedsh "s/image=.*/image=${new_image}/" "${config_dir}/emby_config.txt"

}

function main_set_version() {

    # shellcheck disable=SC1091
    source "${config_dir}/emby_config.txt"

    local versiom_list
    interface=
    versiom_list=("4.8.9.0" "latest" "4.9.0.42")
    for i in "${!versiom_list[@]}"; do
        if [ "${versiom_list[$i]}" == "${version}" ]; then
            interface+="$((i + 1))、${Green}${versiom_list[$i]}${Font}\n"
        else
            interface+="$((i + 1))、${versiom_list[$i]}\n"
        fi
    done
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Emby镜像版本${Font}\n"
    echo -e "${Sky_Blue}绿色代表已选中，输入对应选项数字可勾选或取消勾选${Font}\n"
    echo -e "${interface}\c"
    if [ "${version}" != "4.8.9.0" ] && [ "${version}" != "latest" ] && [ "${version}" != "4.9.0.42" ]; then
        echo -e "4、${Green}用户自定义：${version}${Font}"
    else
        echo -e "4、用户自定义：无"
    fi
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-4]:" num
    case "$num" in
    1)
        sedsh "s/version=.*/version=4.8.9.0/" "${config_dir}/emby_config.txt"
        clear
        main_set_version
        ;;
    2)
        sedsh "s/version=.*/version=latest/" "${config_dir}/emby_config.txt"
        clear
        main_set_version
        ;;
    3)
        sedsh "s/version=.*/version=4.9.0.42/" "${config_dir}/emby_config.txt"
        clear
        main_set_version
        ;;
    4)
        local old_version new_version
        old_version="${version}"
        INFO "已读取当前Emby镜像版本：${old_version} (默认不更改回车继续，如果需要更改请输入新版本号)"
        read -erp "NEW_VERSION:" new_version
        [[ -z "${new_version}" ]] && new_version=${old_version}
        sedsh "s/version=.*/version=${new_version}/" "${config_dir}/emby_config.txt"
        clear
        main_set_version
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-4]'
        main_set_version
        ;;
    esac

}

function get_media_dir() {

    if [ "$media_dir" != "" ]; then
        OLD_MEDIA_DIR=${media_dir}
        INFO "已读取媒体库目录：${OLD_MEDIA_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
        read -erp "MEDIA_DIR:" MEDIA_DIR
        [[ -z "${MEDIA_DIR}" ]] && MEDIA_DIR=${OLD_MEDIA_DIR}
        sedsh "s#media_dir=.*#media_dir=${MEDIA_DIR}#" "${config_dir}/emby_config.txt"
    else
        INFO "请输入媒体库目录（默认 /media ）"
        read -erp "MEDIA_DIR:" MEDIA_DIR
        [[ -z "${MEDIA_DIR}" ]] && MEDIA_DIR="/media"
        sedsh "s#media_dir=.*#media_dir=${MEDIA_DIR}#" "${config_dir}/emby_config.txt"
    fi

}

function get_resilio() {

    if [ "${resilio}" == "no" ]; then
        echo -e "${Red}否${Font}"
    elif [ "${resilio}" == "yes" ]; then
        echo -e "${Green}是${Font}"
    else
        echo -e "${Red}错误${Font}"
    fi

}

function set_resilio() {

    if [ "${resilio}" == "no" ]; then
        new_resilio=yes
    elif [ "${resilio}" == "yes" ]; then
        new_resilio=no
    else
        new_resilio=no
    fi

    sedsh "s/resilio=.*/resilio=${new_resilio}/" "${config_dir}/emby_config.txt"

}

function main_return() {

    # shellcheck disable=SC1091
    source "${config_dir}/emby_config.txt"

    cat /tmp/xiaoya_alist

    echo -e "1、开启/关闭硬解GPU映射    当前配置：$(get_dev_dri)"
    echo -e "2、Emby容器网络模式        当前配置：${Sky_Blue}${mode}模式${Font}"
    echo -e "3、Emby镜像                当前配置：${Sky_Blue}${image}${Font}"
    echo -e "4、Emby镜像版本            当前配置：${Sky_Blue}${version}${Font}"
    echo -e "5、媒体库路径              当前配置：${Sky_Blue}${media_dir}${Font}"
    # echo -e "6、是否安装Resilio         当前配置：$(get_resilio)"
    echo -e "0、退出脚本 | Script info: ${DATE_VERSION} Thanks: ${Blue}xiaoyaLiu${Font}"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-5]:" num
    case "$num" in
    1)
        set_dev_dri
        clear
        main_return
        ;;
    2)
        set_mode
        clear
        main_return
        ;;
    3)
        set_image
        clear
        main_return
        ;;
    4)
        clear
        main_set_version
        ;;
    5)
        clear
        get_media_dir
        clear
        main_return
        ;;
    6)
        set_resilio
        clear
        main_return
        ;;
    0)
        clear
        exit 0
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-5]'
        main_return
        ;;
    esac
}

clear

if [[ $EUID -ne 0 ]]; then
    ERROR '此脚本必须以 root 身份运行！'
    exit 1
fi

if [[ "$(uname -s)" = "Darwin" ]]; then
    stty -icanon
fi

if [ ! "$1" ]; then
    ERROR "未设置xiaoya配置目录"
    exit 1
fi

config_dir=${1}

if [ ! -d "${config_dir}" ]; then
    mkdir -p "${config_dir}"
fi

find "${config_dir}" -type f -name "*.txt" -exec sed -i "s/\r$//g" {} \;

if [ ! -s "${config_dir}/emby_config.txt" ]; then
    {
        echo "dev_dri=no"
        echo "mode=host"
        echo "image=emby"
        echo "media_dir="
        echo "resilio=no"
        echo "version=4.9.0.42"
    } >> "${config_dir}/emby_config.txt"
else
    # shellcheck disable=SC1091
    source "${config_dir}/emby_config.txt"
    if [ -z "${dev_dri}" ]; then
        echo "dev_dri=no" >> "${config_dir}/emby_config.txt"
    fi
    if [ -z "${mode}" ]; then
        echo "mode=host" >> "${config_dir}/emby_config.txt"
    fi
    if [ -z "${image}" ]; then
        echo "image=emby" >> "${config_dir}/emby_config.txt"
    fi
    if [ -z "${media_dir}" ]; then
        echo "media_dir=" >> "${config_dir}/emby_config.txt"
    fi
    if [ -z "${resilio}" ]; then
        echo "resilio=no" >> "${config_dir}/emby_config.txt"
    fi
    if [ -z "${version}" ]; then
        echo "version=4.9.0.42" >> "${config_dir}/emby_config.txt"
    fi
fi

if [ -f /tmp/xiaoya_alist ]; then
    rm -rf /tmp/xiaoya_alist
fi
if ! curl -sL https://git.aginouxy.top/AngelababyXYG/xiaoya_alist -o /tmp/xiaoya_alist; then
    if ! curl -sL https://git.aginouxy.top/AngelababyXYG/xiaoya-alist@latest/xiaoya_alist -o /tmp/xiaoya_alist; then
        curl -sL https://github.com/AngelababyXYG/xiaoya-alist/blob/master/xiaoya_alist -o /tmp/xiaoya_alist
    fi
fi

main_return
