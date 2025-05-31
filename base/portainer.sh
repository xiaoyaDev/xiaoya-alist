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

function install_portainer() {

    if [ -f ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt ]; then
        OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt)
        INFO "已读取Portainer配置文件路径：${OLD_CONFIG_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${OLD_CONFIG_DIR}
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt
    else
        INFO "请输入配置文件目录（默认 /etc/portainer ）"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR="/etc/portainer"
        touch ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt
    fi

    while true; do
        INFO "请输入后台HTTP管理端口（默认 9000 ）"
        read -erp "HTTP_PORT:" HTTP_PORT
        [[ -z "${HTTP_PORT}" ]] && HTTP_PORT="9000"
        if check_port "${HTTP_PORT}"; then
            break
        else
            ERROR "${HTTP_PORT} 此端口被占用，请输入其他端口！"
        fi
    done

    while true; do
        INFO "请输入后台HTTP管理端口（默认 9443 ）"
        read -erp "HTTPS_PORT:" HTTPS_PORT
        [[ -z "${HTTPS_PORT}" ]] && HTTPS_PORT="9443"
        if check_port "${HTTPS_PORT}"; then
            break
        else
            ERROR "${HTTPS_PORT} 此端口被占用，请输入其他端口！"
        fi
    done

    INFO "请输入镜像TAG（默认 latest ）"
    read -erp "TAG:" TAG
    [[ -z "${TAG}" ]] && TAG="latest"

    docker_pull "portainer/portainer-ce:${TAG}"

    docker run -itd \
        -p "${HTTPS_PORT}":9443 \
        -p "${HTTP_PORT}":9000 \
        --name "$(cat ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt)" \
        -e TZ=Asia/Shanghai \
        --restart=always \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "${CONFIG_DIR}:/data" \
        portainer/portainer-ce:"${TAG}"

    INFO "安装完成！"

}

function update_portainer() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新Portainer${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt)"

}

function uninstall_portainer() {

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
        echo -en "即将开始卸载 Portainer${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt)"
    docker image rm "$(docker image ls --filter=reference="portainer/portainer-ce" -q)"
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/portainer_config_dir.txt)
            rm -rf "${OLD_CONFIG_DIR}"
        fi
    fi
    INFO "Portainer 卸载成功！"

}

function main_portainer() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Portainer${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_portainer
        return_menu "main_portainer"
        ;;
    2)
        clear
        update_portainer
        return_menu "main_portainer"
        ;;
    3)
        clear
        uninstall_portainer
        return_menu "main_portainer"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_portainer
        ;;
    esac

}
