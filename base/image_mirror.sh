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

function auto_choose_image_mirror() {

    for i in "${!mirrors[@]}"; do
        local output
        output=$(
            curl -s -o /dev/null -m 4 -w '%{time_total}' --head --request GET "${mirrors[$i]}"
            echo $? > /tmp/curl_exit_status_${i} &
        )
        # shellcheck disable=SC2004
        status[$i]=$!
        # shellcheck disable=SC2004
        delays[$i]=$output
    done
    better_time=9999999999
    for i in "${!mirrors[@]}"; do
        local time_compare result
        wait ${status[$i]}
        result=$(cat /tmp/curl_exit_status_${i})
        rm -f /tmp/curl_exit_status_${i}
        if [ $result -eq 0 ]; then
            if [ "${mirrors[$i]}" == "docker.io" ]; then
                time_compare=$(awk -v n1="1" -v n2="$result" 'BEGIN {print (n1>n2)? "1":"0"}')
                if [ $time_compare -eq 1 ]; then
                    better_mirror=${mirrors[$i]}
                    better_time=0
                fi
            else
                time_compare=$(awk -v n1="$better_time" -v n2="$result" 'BEGIN {print (n1>n2)? "1":"0"}')
                if [ $time_compare -eq 1 ]; then
                    better_mirror=${mirrors[$i]}
                    better_time=${delays[$i]}
                fi
            fi
        fi
    done
    if [ -z "${better_mirror}" ]; then
        return 1
    else
        echo -e "${better_mirror}" > ${DDSREM_CONFIG_DIR}/image_mirror.txt
        if docker pull "${better_mirror}/library/hello-world:latest" &> /dev/null; then
            docker rmi "${better_mirror}/library/hello-world:latest" &> /dev/null
            return 0
        else
            return 1
        fi
    fi

}

function choose_image_mirror() {

    local num
    local current_mirror interface
    current_mirror="$(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")"
    declare -i s
    local s=0
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Docker镜像源选择\n${Font}"
    echo -ne "${INFO} 界面加载中...${Font}\r"
    interface="${Sky_Blue}绿色字体代表当前选中的镜像源"
    interface="${interface}\n选择镜像源后会自动检测是否可连接，如果预选镜像源都无法使用请自定义镜像源${Font}\n"
    local status=()
    for i in "${!mirrors[@]}"; do
        local output
        output=$(
            curl -s -o /dev/null -m 4 -w '%{time_total}' --head --request GET "${mirrors[$i]}"
            echo $? > /tmp/curl_exit_status_${i} &
        )
        # shellcheck disable=SC2004
        status[$i]=$!
        # shellcheck disable=SC2004
        delays[$i]=$(printf "%.2f" $output)
    done
    for i in "${!mirrors[@]}"; do
        wait ${status[$i]}
        local result
        result=$(cat /tmp/curl_exit_status_${i})
        rm -f /tmp/curl_exit_status_${i}
        local color=
        local font=
        if [[ "${mirrors[$i]}" == "${current_mirror}" ]]; then
            color="${Green}"
            font="${Font}"
            s+=1
        fi
        if [ $result -eq 0 ]; then
            interface="${interface}\n$((i + 1))、${color}${mirrors[$i]}${font} (${Green}可用${Font} ${Sky_Blue}延迟: ${delays[$i]}秒${Font})"
        else
            interface="${interface}\n$((i + 1))、${color}${mirrors[$i]}${font} (${Red}不可用${Font})"
        fi
        z=$((i + 2))
    done
    if [ -n "$(cat "${DDSREM_CONFIG_DIR}/image_mirror_user.txt")" ]; then
        if user_delay=$(curl -s -o /dev/null -m 4 -w '%{time_total}' --head --request GET "$(cat "${DDSREM_CONFIG_DIR}/image_mirror_user.txt")"); then
            USER_TEST_STATUS="(${Green}可用${Font} ${Sky_Blue}延迟: ${user_delay}秒${Font})"
        else
            USER_TEST_STATUS="(${Red}不可用${Font})"
        fi
    else
        USER_TEST_STATUS="(${Blue}未配置${Font})"
    fi
    if [ "${s}" == "1" ]; then
        interface="${interface}\n${z}、自定义源：$(cat "${DDSREM_CONFIG_DIR}/image_mirror_user.txt") ${USER_TEST_STATUS}"
    else
        interface="${interface}\n${z}、${Green}自定义源：$(cat "${DDSREM_CONFIG_DIR}/image_mirror_user.txt")${Font} ${USER_TEST_STATUS}"
    fi
    echo -e "${interface}\n0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-${z}]:" num
    if [ "${num}" == "0" ]; then
        clear
        "${1}"
    elif [ "${num}" == "${z}" ]; then
        clear
        INFO "请输入自定义源地址（当前自定义源地址为：$(cat "${DDSREM_CONFIG_DIR}/image_mirror_user.txt")，回车默认不修改）"
        read -erp "custom_url:" custom_url
        [[ -z "${custom_url}" ]] && custom_url=$(cat "${DDSREM_CONFIG_DIR}/image_mirror_user.txt")
        echo "${custom_url}" > ${DDSREM_CONFIG_DIR}/image_mirror.txt
        echo "${custom_url}" > ${DDSREM_CONFIG_DIR}/image_mirror_user.txt
    else
        for i in "${!mirrors[@]}"; do
            if [[ "$((i + 1))" == "${num}" ]]; then
                echo -e "${mirrors[$i]}" > ${DDSREM_CONFIG_DIR}/image_mirror.txt
                break
            fi
        done
    fi
    clear
    INFO "开始镜像源地址连通性测试..."
    local retries=0
    local max_retries=3
    IMAGE_MIRROR=$(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")
    while [ $retries -lt $max_retries ]; do
        if docker pull "${IMAGE_MIRROR}/library/hello-world:latest"; then
            INFO "地址连通性测试正常！"
            break
        else
            WARN "地址连通性测试失败，正在进行第 $((retries + 1)) 次重试..."
            retries=$((retries + 1))
        fi
    done
    if [ $retries -eq $max_retries ]; then
        ERROR "地址连通性测试失败，已达到最大重试次数，请选择镜像源或者自定义镜像源！"
    else
        docker rmi "${IMAGE_MIRROR}/library/hello-world:latest"
    fi
    INFO "按任意键返回 Docker镜像源选择 菜单"
    read -rs -n 1 -p ""
    clear
    choose_image_mirror "${1}"

}
