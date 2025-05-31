#!/bin/bash
# shellcheck disable=all
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

function main_casaos() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}CasaOS${Font}\n"
    echo -e "1、安装"
    echo -e "2、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-2]:" num
    case "$num" in
    1)
        clear
        curl -fsSL https://get.casaos.io | sudo bash
        return_menu "main_casaos"
        ;;
    2)
        clear
        casaos-uninstall
        return_menu "main_casaos"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-2]'
        main_casaos
        ;;
    esac

}
