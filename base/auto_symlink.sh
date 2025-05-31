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

function install_auto_symlink() {

    if [ -f ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt ]; then
        OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt)
        INFO "已读取Auto_Symlink配置文件路径：${OLD_CONFIG_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${OLD_CONFIG_DIR}
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt
    else
        INFO "请输入配置文件目录（默认 /etc/auto_symlink ）"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR="/etc/auto_symlink"
        touch ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt
    fi

    while true; do
        INFO "请输入后台管理端口（默认 8095 ）"
        read -erp "PORT:" PORT
        [[ -z "${PORT}" ]] && PORT="8095"
        if check_port "${PORT}"; then
            break
        else
            ERROR "${PORT} 此端口被占用，请输入其他端口！"
        fi
    done

    INFO "请输入挂载目录（可设置多个）（PS：-v /media:/media）"
    read -erp "Volumes:" volumes

    docker_pull "shenxianmq/auto_symlink:latest"

    if [ -n "${volumes}" ]; then
        docker run -d \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)" \
            -e TZ=Asia/Shanghai \
            -v "${CONFIG_DIR}:/app/config" \
            -p "${PORT}":8095 \
            --restart always \
            --log-opt max-size=10m \
            --log-opt max-file=3 \
            ${volumes} \
            shenxianmq/auto_symlink:latest
    else
        docker run -d \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)" \
            -e TZ=Asia/Shanghai \
            -v "${CONFIG_DIR}:/app/config" \
            -p "${PORT}":8095 \
            --restart always \
            --log-opt max-size=10m \
            --log-opt max-file=3 \
            shenxianmq/auto_symlink:latest
    fi

    INFO "安装完成！"

}

function update_auto_symlink() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新Auto_Symlink${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)"

}

function uninstall_auto_symlink() {

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
        echo -en "即将开始卸载 Auto_Symlink${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)"
    docker image rm shenxianmq/auto_symlink:latest
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/auto_symlink_config_dir.txt)
            rm -rf "${OLD_CONFIG_DIR}"
        fi
    fi
    INFO "Auto_Symlink 卸载成功！"

}

function main_auto_symlink() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Auto_Symlink${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_auto_symlink
        return_menu "main_auto_symlink"
        ;;
    2)
        clear
        update_auto_symlink
        return_menu "main_auto_symlink"
        ;;
    3)
        clear
        uninstall_auto_symlink
        return_menu "main_auto_symlink"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_auto_symlink
        ;;
    esac

}
