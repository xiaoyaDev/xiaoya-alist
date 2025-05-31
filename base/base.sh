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

function ___install_docker() {

    if ! command -v docker; then
        WARN "docker 未安装，脚本尝试自动安装..."
        wget -qO- get.docker.com | bash
        if command -v docker; then
            INFO "docker 安装成功！"
        else
            ERROR "docker 安装失败，请手动安装！"
            exit 1
        fi
    fi

}

function packages_apt_install() {

    if ! command -v ${1}; then
        WARN "${1} 未安装，脚本尝试自动安装..."
        apt update -y
        if apt install -y ${1}; then
            INFO "${1} 安装成功！"
        else
            ERROR "${1} 安装失败，请手动安装！"
            exit 1
        fi
    fi

}

function packages_yum_install() {

    if ! command -v ${1}; then
        WARN "${1} 未安装，脚本尝试自动安装..."
        if yum install -y ${1}; then
            INFO "${1} 安装成功！"
        else
            ERROR "${1} 安装失败，请手动安装！"
            exit 1
        fi
    fi

}

function packages_zypper_install() {

    if ! command -v ${1}; then
        WARN "${1} 未安装，脚本尝试自动安装..."
        zypper refresh
        if zypper install ${1}; then
            INFO "${1} 安装成功！"
        else
            ERROR "${1} 安装失败，请手动安装！"
            exit 1
        fi
    fi

}

function packages_apk_install() {

    if ! command -v ${1}; then
        WARN "${1} 未安装，脚本尝试自动安装..."
        if apk add ${1}; then
            INFO "${1} 安装成功！"
        else
            ERROR "${1} 安装失败，请手动安装！"
            exit 1
        fi
    fi

}

function packages_pacman_install() {

    if ! command -v ${1}; then
        WARN "${1} 未安装，脚本尝试自动安装..."
        if pacman -Sy --noconfirm ${1}; then
            INFO "${1} 安装成功！"
        else
            ERROR "${1} 安装失败，请手动安装！"
            exit 1
        fi
    fi

}

function packages_need() {

    if [ "$1" == "apt" ]; then
        packages_apt_install curl
        packages_apt_install wget
        ___install_docker
    elif [ "$1" == "yum" ]; then
        packages_yum_install curl
        packages_yum_install wget
        ___install_docker
    elif [ "$1" == "zypper" ]; then
        packages_zypper_install curl
        packages_zypper_install wget
        ___install_docker
    elif [ "$1" == "apk_alpine" ]; then
        packages_apk_install curl
        packages_apk_install wget
        packages_apk_install docker
    elif [ "$1" == "pacman" ]; then
        packages_pacman_install curl
        packages_pacman_install wget
        packages_pacman_install docker
    else
        if ! command -v curl; then
            ERROR "curl 未安装，请手动安装！"
            exit 1
        fi
        if ! command -v wget; then
            ERROR "wget 未安装，请手动安装！"
            exit 1
        fi
        if ! command -v docker; then
            ERROR "docker 未安装，请手动安装！"
            exit 1
        fi
    fi

}

function get_os() {

    if command -v getconf > /dev/null 2>&1; then
        is64bit="$(getconf LONG_BIT)bit"
    else
        is64bit="unknow"
    fi
    _os=$(uname -s)
    _os_all=$(uname -a)
    if [ "${_os}" == "Darwin" ]; then
        OSNAME='macos'
        DDSREM_CONFIG_DIR=/etc/DDSRem
        stty -icanon
    # 必须先判断的系统
    # 绿联旧版UGOS 基于 OpenWRT
    elif [ -f /etc/openwrt_version ] && echo -e "${_os_all}" | grep -Eqi "UGREEN"; then
        OSNAME='ugos'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    # 绿联UGOS Pro 基于 Debian
    elif grep -Eqi "Debian" /etc/os-release && grep -Eqi "UGOSPRO" /etc/issue; then
        OSNAME='ugos pro'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    # fnOS 基于 Debian
    elif grep -Eqi "Debian" /etc/os-release && grep -Eqi "fnOS" /etc/issue; then
        OSNAME='fnos'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    # OpenMediaVault 基于 Debian
    elif grep -Eqi "openmediavault" /etc/issue || grep -Eqi "openmediavault" /etc/os-release; then
        OSNAME='openmediavault'
        packages_need "apt"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    # FreeNAS（TrueNAS CORE）基于 FreeBSD
    elif echo -e "${_os_all}" | grep -Eqi "FreeBSD" | grep -Eqi "TRUENAS"; then
        OSNAME='truenas core'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    # TrueNAS SCALE 基于 Debian
    elif grep -Eqi "Debian" /etc/issue && [ -f /etc/version ]; then
        OSNAME='truenas scale'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif [ -f /etc/synoinfo.conf ]; then
        OSNAME='synology'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif [ -f /etc/openwrt_release ]; then
        OSNAME='openwrt'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "QNAP" /etc/issue; then
        OSNAME='qnap'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif [ -f /etc/unraid-version ]; then
        OSNAME='unraid'
        packages_need
        DDSREM_CONFIG_DIR=/mnt/user/appdata/DDSRem
        # 目录迁移
        if [ ! -d "${DDSREM_CONFIG_DIR}" ]; then
            mkdir -p "${DDSREM_CONFIG_DIR}"
        fi
        local FILES_LIST PATHS_LIST
        FILES_LIST=(
            "xiaoya_alist_tvbox_config_dir.txt"
            "xiaoya_alist_media_dir.txt"
            "xiaoya_alist_config_dir.txt"
            "resilio_config_dir.txt"
            "portainer_config_dir.txt"
            "onelist_config_dir.txt"
            "container_run_extra_parameters.txt"
            "auto_symlink_config_dir.txt"
            "data_downloader.txt"
            "disk_capacity_detection.txt"
            "xiaoya_connectivity_detection.txt"
            "image_mirror.txt"
            "image_mirror_user.txt"
            "default_network.txt"
        )
        PATHS_LIST=(
            "container_name"
            "data_crep"
        )
        for __file in "${FILES_LIST[@]}"; do
            if [ -f "/etc/DDSRem/${__file}" ]; then
                INFO "迁移文件 ${__file} 中..."
                mv "/etc/DDSRem/${__file}" "${DDSREM_CONFIG_DIR}/${__file}"
            fi
        done
        for __path in "${PATHS_LIST[@]}"; do
            if [ -d "/etc/DDSRem/${__path}" ]; then
                INFO "迁移文件夹 ${__path} 中..."
                if [ -d "${DDSREM_CONFIG_DIR}/${__path}" ]; then
                    # 默认保留 /etc/DDSRem 的配置项
                    rm -rf "${DDSREM_CONFIG_DIR}/${__path}"
                fi
                mv "/etc/DDSRem/${__path}" "${DDSREM_CONFIG_DIR}/${__path}"
            fi
        done
    elif grep -Eqi "LibreELEC" /etc/issue || grep -Eqi "LibreELEC" /etc/*-release; then
        OSNAME='libreelec'
        DDSREM_CONFIG_DIR=/storage/DDSRem
        ERROR "LibreELEC 系统目前不支持！"
        exit 1
    elif grep -Eqi "openSUSE" /etc/*-release; then
        OSNAME='opensuse'
        packages_need "zypper"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "FreeBSD" /etc/*-release; then
        OSNAME='freebsd'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "EulerOS" /etc/*-release || grep -Eqi "openEuler" /etc/*-release; then
        OSNAME='euler'
        packages_need "yum"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "CentOS" /etc/issue || grep -Eqi "CentOS" /etc/*-release; then
        OSNAME='centos'
        packages_need "yum"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Fedora" /etc/issue || grep -Eqi "Fedora" /etc/*-release; then
        OSNAME='fedora'
        packages_need "yum"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Rocky" /etc/issue || grep -Eqi "Rocky" /etc/*-release; then
        OSNAME='rocky'
        packages_need "yum"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "AlmaLinux" /etc/issue || grep -Eqi "AlmaLinux" /etc/*-release; then
        OSNAME='almalinux'
        packages_need "yum"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Arch Linux" /etc/issue || grep -Eqi "Arch Linux" /etc/*-release; then
        OSNAME='archlinux'
        packages_need "pacman"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Amazon Linux" /etc/issue || grep -Eqi "Amazon Linux" /etc/*-release; then
        OSNAME='amazon'
        packages_need "yum"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Debian" /etc/issue || grep -Eqi "Debian" /etc/os-release; then
        OSNAME='debian'
        packages_need "apt"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eqi "Ubuntu" /etc/os-release; then
        OSNAME='ubuntu'
        packages_need "apt"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    elif grep -Eqi "Alpine" /etc/issue || grep -Eq "Alpine" /etc/*-release; then
        OSNAME='alpine'
        packages_need "apk_alpine"
        DDSREM_CONFIG_DIR=/etc/DDSRem
    else
        OSNAME='unknow'
        packages_need
        DDSREM_CONFIG_DIR=/etc/DDSRem
    fi

    HOSTS_FILE_PATH=/etc/hosts

}

function sedsh() {

    if [[ "${OSNAME}" = "macos" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi

}

function show_disk_mount() {

    df -h | grep -E -v "Avail|loop|boot|overlay|tmpfs|proc" | sort -nr -k 4

}

function judgment_container() {

    if docker container inspect "${1}" > /dev/null 2>&1; then
        local container_status
        container_status=$(docker inspect --format='{{.State.Status}}' "${1}")
        case "${container_status}" in
        "created")
            echo -e "${Blue}已创建${Font}"
            ;;
        "running")
            echo -e "${Green}运行中${Font}"
            ;;
        "paused")
            echo -e "${Blue}已暂停${Font}"
            ;;
        "restarting")
            echo -e "${Blue}重启中${Font}"
            ;;
        "removing")
            echo -e "${Blue}删除中${Font}"
            ;;
        "exited")
            echo -e "${Yellow}已停止${Font}"
            ;;
        "dead")
            echo -e "${Red}不可用${Font}"
            ;;
        *)
            echo -e "${Red}未知状态${Font}"
            ;;
        esac
    else
        echo -e "${Red}未安装${Font}"
    fi

}

function return_menu() {

    INFO "是否返回菜单继续配置 [Y/n]"
    answer=""
    t=60
    while [[ -z "$answer" && $t -gt 0 ]]; do
        printf "\r%2d 秒后将自动退出脚本：" $t
        read -r -t 1 -n 1 answer
        t=$((t - 1))
    done
    [[ -z "${answer}" ]] && answer="n"
    if [[ ${answer} == [Yy] ]]; then
        clear
        "${@}"
    else
        echo -e "\n"
        exit 0
    fi

}

function docker_pull() {

    retries=0
    max_retries=3

    IMAGE_MIRROR=$(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")

    if docker inspect "${1}" > /dev/null 2>&1; then
        INFO "发现旧 ${1} 镜像，删除中..."
        docker rmi "${1}" > /dev/null 2>&1
    fi

    while [ $retries -lt $max_retries ]; do
        if docker pull "${IMAGE_MIRROR}/${1}"; then
            INFO "${1} 镜像拉取成功！"
            break
        else
            WARN "${1} 镜像拉取失败，正在进行第 $((retries + 1)) 次重试..."
            retries=$((retries + 1))
        fi
    done

    if [ $retries -eq $max_retries ]; then
        ERROR "镜像拉取失败，已达到最大重试次数！"
        ERROR "请进入主菜单选择数字 ${Sky_Blue}6 6${Font} 进入 ${Sky_Blue}Docker镜像源选择${Font} 配置镜像源地址！"
        exit 1
    else
        if [ "${IMAGE_MIRROR}" != "docker.io" ]; then
            docker tag "${IMAGE_MIRROR}/${1}" "${1}" > /dev/null 2>&1
            docker rmi "${IMAGE_MIRROR}/${1}" > /dev/null 2>&1
        fi
        return 0
    fi

}

function container_update() {

    local run_image remove_image IMAGE_MIRROR pull_image
    if docker inspect ddsderek/runlike:latest > /dev/null 2>&1; then
        local_sha=$(docker inspect --format='{{index .RepoDigests 0}}' ddsderek/runlike:latest 2> /dev/null | cut -f2 -d:)
        remote_sha=$(curl -s -m 10 "https://hub.docker.com/v2/repositories/ddsderek/runlike/tags/latest" | grep -o '"digest":"[^"]*' | grep -o '[^"]*$' | tail -n1 | cut -f2 -d:)
        if [ "$local_sha" != "$remote_sha" ]; then
            docker rmi ddsderek/runlike:latest
            docker_pull "ddsderek/runlike:latest"
        fi
    else
        docker_pull "ddsderek/runlike:latest"
    fi
    INFO "获取 ${1} 容器信息中..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp ddsderek/runlike -p "${@}" > "/tmp/container_update_${*}"
    if [ -n "${container_update_extra_command}" ]; then
        eval "${container_update_extra_command}"
    fi
    run_image=$(docker container inspect -f '{{.Config.Image}}' "${@}")
    remove_image=$(docker images -q ${run_image})
    local retries=0
    local max_retries=3
    IMAGE_MIRROR=$(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")
    while [ $retries -lt $max_retries ]; do
        if docker pull "${IMAGE_MIRROR}/${run_image}"; then
            INFO "${1} 镜像拉取成功！"
            break
        else
            WARN "${1} 镜像拉取失败，正在进行第 $((retries + 1)) 次重试..."
            retries=$((retries + 1))
        fi
    done
    if [ $retries -eq $max_retries ]; then
        ERROR "镜像拉取失败，已达到最大重试次数！"
        return 1
    else
        if [ "${IMAGE_MIRROR}" != "docker.io" ]; then
            pull_image=$(docker images -q "${IMAGE_MIRROR}/${run_image}")
        else
            pull_image=$(docker images -q "${run_image}")
        fi
        if ! docker stop "${@}" > /dev/null 2>&1; then
            if ! docker kill "${@}" > /dev/null 2>&1; then
                docker rmi "${IMAGE_MIRROR}/${run_image}"
                ERROR "更新失败，停止 ${*} 容器失败！"
                return 1
            fi
        fi
        INFO "停止 ${*} 容器成功！"
        if ! docker rm --force "${@}" > /dev/null 2>&1; then
            ERROR "更新失败，删除 ${*} 容器失败！"
            return 1
        fi
        INFO "删除 ${*} 容器成功！"
        if [ "${pull_image}" != "${remove_image}" ]; then
            INFO "删除 ${remove_image} 镜像中..."
            docker rmi "${remove_image}" > /dev/null 2>&1
        fi
        if [ "${IMAGE_MIRROR}" != "docker.io" ]; then
            docker tag "${IMAGE_MIRROR}/${run_image}" "${run_image}" > /dev/null 2>&1
            docker rmi "${IMAGE_MIRROR}/${run_image}" > /dev/null 2>&1
        fi
        if bash "/tmp/container_update_${*}"; then
            rm -f "/tmp/container_update_${*}"
            INFO "${*} 更新成功"
            return 0
        else
            ERROR "更新失败，创建 ${*} 容器失败！"
            return 1
        fi
    fi

}

function data_crep() { # container_run_extra_parameters

    local MODE="${1}"
    local DATA="${2}"
    local DIR="${DDSREM_CONFIG_DIR}/data_crep"

    if [ "${MODE}" == "read" ] || [ "${MODE}" == "r" ]; then
        if [ -f "${DIR}/${DATA}.txt" ]; then
            cat ${DIR}/${DATA}.txt | head -n1
        else
            echo "None"
        fi
    elif [ "${MODE}" == "write" ] || [ "${MODE}" == "w" ]; then
        if [ "${extra_parameters}" == "None" ]; then
            echo > ${DIR}/${DATA}.txt
        else
            echo "${extra_parameters}" > ${DIR}/${DATA}.txt
        fi
        cat ${DIR}/${DATA}.txt | head -n1
    else
        return 1
    fi

}

function pull_glue_python_ddsrem() {

    if docker inspect ddsderek/xiaoya-glue:python > /dev/null 2>&1; then
        local_sha=$(docker inspect --format='{{index .RepoDigests 0}}' ddsderek/xiaoya-glue:python 2> /dev/null | cut -f2 -d:)
        remote_sha=$(curl -s -m 10 "https://hub.docker.com/v2/repositories/ddsderek/xiaoya-glue/tags/python" | grep -o '"digest":"[^"]*' | grep -o '[^"]*$' | tail -n1 | cut -f2 -d:)
        if [ "$local_sha" != "$remote_sha" ]; then
            docker rmi ddsderek/xiaoya-glue:python
            INFO "拉取镜像中..."
            docker_pull "ddsderek/xiaoya-glue:python"
        fi
    else
        INFO "拉取镜像中..."
        docker_pull "ddsderek/xiaoya-glue:python"
    fi

}

function check_port() {

    local check_command result

    if [[ "${OSNAME}" = "macos" ]]; then
        check_command=lsof
    else
        if ! command -v netstat > /dev/null 2>&1; then
            if ! command -v lsof > /dev/null 2>&1; then
                WARN "未检测到 netstat 或 lsof 命令，跳过 ${1} 端口检查！"
                return 0
            else
                check_command=lsof
            fi
        else
            check_command=netstat
        fi
    fi

    if [ "${check_command}" == "netstat" ]; then
        if result=$(netstat -tuln | awk -v port="${1}" '$4 ~ ":"port"$"'); then
            if [ -z "${result}" ]; then
                INFO "${1} 端口通过检测！"
                return 0
            else
                ERROR "${1} 端口被占用！"
                echo "$(netstat -tulnp | awk -v port="${1}" '$4 ~ ":"port"$"')"
                return 1
            fi
        else
            WARN "检测命令执行错误，跳过 ${1} 端口检查！"
            return 0
        fi
    elif [ "${check_command}" == "lsof" ]; then
        if ! lsof -i :"${1}" > /dev/null; then
            INFO "${1} 端口通过检测！"
            return 0
        else
            ERROR "${1} 端口被占用！"
            echo "$(lsof -i :"${1}")"
            return 1
        fi
    fi

}

function clear_qrcode_container() {

    # shellcheck disable=SC2046
    docker rm -f $(docker ps -a -q --filter ancestor=ddsderek/xiaoya-glue:python) > /dev/null 2>&1

}

function check_path() {

    if [ -z "${1}" ]; then
        return 1
    fi

    # 目录不能为‘/’
    if [ "${1}" == "/" ]; then
        return 1
    fi

    # 目录结尾不能有空格
    if [ "${1: -1}" == " " ]; then
        return 1
    fi

    # 目录必须以`/`开头，不能包含`//`或`./`或`..`
    if [[ "${1}" =~ ^/ && ! "${1}" =~ // && ! "${1}" =~ (\./|\.\.) ]]; then
        return 0
    else
        return 1
    fi

}

function command_run_in_xiaoya() {

    if [ "${1}" == "sort" ]; then
        # 判断本地命令是否有 r V 参数
        if echo -e "v1.0.0\nv1.0.1" | sort -rV > /dev/null 2>&1; then
            return 0
        fi
    else
        echo -e "未知的命令：${1}"
        return 1
    fi
    local xiaoya_name
    xiaoya_name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    if docker container inspect "${xiaoya_name}" > /dev/null 2>&1; then
        if [ "$(docker inspect --format='{{.State.Status}}' "${xiaoya_name}")" == "running" ]; then
            echo -e "docker exec -i ${xiaoya_name}"
            return 0
        fi
    fi
    echo -e "${1} 命令无法在主机环境运行，请启动小雅容器后再次运行！"
    return 1

}

function version_gt() {
    local version_cmd
    if ! version_cmd="$(command_run_in_xiaoya "sort")"; then
        ERROR "${version_cmd}"
        exit 1
    fi
    if [ -n "${version_cmd}" ]; then
        DEBUG "小雅容器内运行比较命令：version_gt"
        test "$(echo "$@" | tr " " "\n" | ${version_cmd} sort -V | head -n 1)" != "$1"
    else
        DEBUG "主机运行比较命令：version_gt"
        test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
    fi
}

function version_le() {
    local version_cmd
    if ! version_cmd="$(command_run_in_xiaoya "sort")"; then
        ERROR "${version_cmd}"
        exit 1
    fi
    if [ -n "${version_cmd}" ]; then
        DEBUG "小雅容器内运行比较命令：version_le"
        test "$(echo "$@" | tr " " "\n" | ${version_cmd} sort -V | head -n 1)" == "$1"
    else
        DEBUG "主机运行比较命令：version_le"
        test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" == "$1"
    fi
}

function version_lt() {
    local version_cmd
    if ! version_cmd="$(command_run_in_xiaoya "sort")"; then
        ERROR "${version_cmd}"
        exit 1
    fi
    if [ -n "${version_cmd}" ]; then
        DEBUG "小雅容器内运行比较命令：version_lt"
        test "$(echo "$@" | tr " " "\n" | ${version_cmd} sort -rV | head -n 1)" != "$1"
    else
        DEBUG "主机运行比较命令：version_lt"
        test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1"
    fi
}

function version_ge() {
    local version_cmd
    if ! version_cmd="$(command_run_in_xiaoya "sort")"; then
        ERROR "${version_cmd}"
        exit 1
    fi
    if [ -n "${version_cmd}" ]; then
        DEBUG "小雅容器内运行比较命令：version_ge"
        test "$(echo "$@" | tr " " "\n" | ${version_cmd} sort -rV | head -n 1)" == "$1"
    else
        DEBUG "主机运行比较命令：version_ge"
        test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
    fi
}

function touch_chmod() {

    touch "${1}"
    chmod 777 "${1}"
    auto_chown "${1}"

}

function auto_chown() {

    if [ -n "${2}" ]; then
        if [ -n "${GLOBAL_PUID}" ] && [ -n "${GLOBAL_PGID}" ]; then
            chown "${2}" "${GLOBAL_PUID}":"${GLOBAL_PGID}" "${1}"
        else
            chown "${2}" 0:0 "${1}"
        fi
    else
        if [ -n "${GLOBAL_PUID}" ] && [ -n "${GLOBAL_PGID}" ]; then
            chown "${GLOBAL_PUID}":"${GLOBAL_PGID}" "${1}"
        else
            chown 0:0 "${1}"
        fi
    fi

}

function auto_privileged() {

    if [[ "${OSNAME}" = "macos" ]]; then
        echo "--privileged=true"
    fi

}
