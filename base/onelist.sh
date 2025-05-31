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

function install_onelist() {

    if [ -f ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt ]; then
        OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt)
        INFO "已读取Onelist配置文件路径：${OLD_CONFIG_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${OLD_CONFIG_DIR}
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt
    else
        INFO "请输入配置文件目录（默认 /etc/onelist ）"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR="/etc/onelist"
        touch ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt
    fi

    while true; do
        INFO "请输入后台管理端口（默认 5245 ）"
        read -erp "HT_PORT:" HT_PORT
        [[ -z "${HT_PORT}" ]] && HT_PORT="5245"
        if check_port "${HT_PORT}"; then
            break
        else
            ERROR "${HT_PORT} 此端口被占用，请输入其他端口！"
        fi
    done

    docker_pull "msterzhang/onelist:latest"

    docker run -itd \
        -p "${HT_PORT}":5245 \
        -e PUID=0 \
        -e PGID=0 \
        -e UMASK=022 \
        -e TZ=Asia/Shanghai \
        -v "${CONFIG_DIR}:/config" \
        --restart=always \
        --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt)" \
        msterzhang/onelist:latest

    INFO "安装完成！"

}

function update_onelist() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新Onelist${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt)"

}

function uninstall_onelist() {

    while true; do
        INFO "是否${Red}删除配置文件${Font} [Y/n]（默认 Y 删除）"
        read -erp "Clean config:" CLEAN_CONFIG
        [[ -z "${CLEAN_CONFIG}" ]] && CLEAN_CONFIG="y"
        if [[ ${CLEAN_CONFIG} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始卸载 Onelist${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt)"
    docker rmi msterzhang/onelist:latest
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/onelist_config_dir.txt)
            rm -rf "${OLD_CONFIG_DIR}"
        fi
    fi
    INFO "Onelist 卸载成功！"

}

function main_onelist() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Onelist${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_onelist
        return_menu "main_onelist"
        ;;
    2)
        clear
        update_onelist
        return_menu "main_onelist"
        ;;
    3)
        clear
        uninstall_onelist
        return_menu "main_onelist"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_onelist
        ;;
    esac

}
