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

function wait_jellyfin_start() {

    start_time=$(date +%s)
    CONTAINER_NAME="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)"
    while true; do
        if [ "$(docker inspect --format='{{json .State.Health.Status}}' "${CONTAINER_NAME}" | sed 's/"//g')" == "healthy" ]; then
            break
        fi
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))
        if [ "$elapsed_time" -gt 900 ]; then
            WARN "Jellyfin 未正常启动超时 15 分钟！"
            break
        fi
        sleep 10
        INFO "等待 Jellyfin 初始化完成中..."
    done

}

function download_wget_unzip_xiaoya_all_jellyfin() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    mkdir -p "${MEDIA_DIR}/temp"
    if [ -d "${MEDIA_DIR}/config" ]; then
        rm -rf ${MEDIA_DIR}/config
    fi

    test_disk_capacity

    mkdir -p "${MEDIA_DIR}/xiaoya"
    mkdir -p "${MEDIA_DIR}/temp"
    chown 0:0 "${MEDIA_DIR}"
    chmod 777 "${MEDIA_DIR}"

    local files=("config_jf.mp4" "all_jf.mp4" "PikPak_jf.mp4")
    for file in "${files[@]}"; do
        if [ -f "${MEDIA_DIR}/temp/${file}.aria2" ]; then
            rm -rf "${MEDIA_DIR}/temp/${file}.aria2"
        fi
    done

    INFO "开始下载解压..."

    extra_parameters="--workdir=/media/temp"
    if ! pull_run_glue wget -c --show-progress "${xiaoya_addr}/d/元数据/Jellyfin/config_jf.mp4"; then
        ERROR "config_jf.mp4 下载失败！"
        exit 1
    fi
    if ! pull_run_glue wget -c --show-progress "${xiaoya_addr}/d/元数据/Jellyfin/all_jf.mp4"; then
        ERROR "all_jf.mp4 下载失败！"
        exit 1
    fi
    if ! pull_run_glue wget -c --show-progress "${xiaoya_addr}/d/元数据/Jellyfin/PikPak_jf.mp4"; then
        ERROR "PikPak_jf.mp4 下载失败！"
        exit 1
    fi

    start_time1=$(date +%s)

    config_size=$(du -k ${MEDIA_DIR}/temp/config_jf.mp4 | cut -f1)
    if [[ "$config_size" -le 3200000 ]]; then
        ERROR "config_jf.mp4 下载不完整，文件大小(in KB):$config_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media"
    pull_run_glue 7z x -aoa -mmt=16 temp/config_jf.mp4
    mv ${MEDIA_DIR}/jf_config ${MEDIA_DIR}/config

    all_size=$(du -k ${MEDIA_DIR}/temp/all_jf.mp4 | cut -f1)
    if [[ "$all_size" -le 30000000 ]]; then
        ERROR "all_jf.mp4 下载不完整，文件大小(in KB):$all_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media/xiaoya"
    pull_run_glue 7z x -aoa -mmt=16 /media/temp/all_jf.mp4

    pikpak_size=$(du -k ${MEDIA_DIR}/temp/PikPak_jf.mp4 | cut -f1)
    if [[ "$pikpak_size" -le 14000000 ]]; then
        ERROR "PikPak_jf.mp4 下载不完整，文件大小(in KB):$pikpak_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media/xiaoya"
    pull_run_glue 7z x -aoa -mmt=16 /media/temp/PikPak_jf.mp4

    end_time1=$(date +%s)
    total_time1=$((end_time1 - start_time1))
    total_time1=$((total_time1 / 60))
    INFO "解压执行时间：$total_time1 分钟"

    INFO "设置目录权限..."
    INFO "这可能需要一定时间，请耐心等待！"
    chmod -R 777 "${MEDIA_DIR}"

}

function download_unzip_xiaoya_all_jellyfin() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    mkdir -p "${MEDIA_DIR}/temp"
    if [ -d "${MEDIA_DIR}/config" ]; then
        rm -rf ${MEDIA_DIR}/config
    fi

    test_disk_capacity

    mkdir -p "${MEDIA_DIR}/xiaoya"
    mkdir -p "${MEDIA_DIR}/temp"
    chown 0:0 "${MEDIA_DIR}"
    chmod 777 "${MEDIA_DIR}"

    local files=("config_jf.mp4" "all_jf.mp4" "PikPak_jf.mp4")
    for file in "${files[@]}"; do
        if [ -f "${MEDIA_DIR}/temp/${file}.aria2" ]; then
            rm -rf "${MEDIA_DIR}/temp/${file}.aria2"
        fi
    done

    INFO "开始下载解压..."

    extra_parameters="--workdir=/media/temp"
    if pull_run_glue aria2c -o config_jf.mp4 --allow-overwrite=true --auto-file-renaming=false --enable-color=false -c -x6 "${xiaoya_addr}/d/元数据/Jellyfin/config_jf.mp4"; then
        if [ -f "${MEDIA_DIR}/temp/config_jf.mp4.aria2" ]; then
            ERROR "存在 ${MEDIA_DIR}/temp/config_jf.mp4.aria2 文件，下载不完整！"
            exit 1
        else
            INFO "config_jf.mp4 下载成功！"
        fi
    else
        ERROR "config_jf.mp4 下载失败！"
        exit 1
    fi
    if pull_run_glue aria2c -o all_jf.mp4 --allow-overwrite=true --auto-file-renaming=false --enable-color=false -c -x6 "${xiaoya_addr}/d/元数据/Jellyfin/all_jf.mp4"; then
        if [ -f "${MEDIA_DIR}/temp/all_jf.mp4.aria2" ]; then
            ERROR "存在 ${MEDIA_DIR}/temp/all_jf.mp4.aria2 文件，下载不完整！"
            exit 1
        else
            INFO "all_jf.mp4 下载成功！"
        fi
    else
        ERROR "all_jf.mp4 下载失败！"
        exit 1
    fi
    if pull_run_glue aria2c -o PikPak_jf.mp4 --allow-overwrite=true --auto-file-renaming=false --enable-color=false -c -x6 "${xiaoya_addr}/d/元数据/Jellyfin/PikPak_jf.mp4"; then
        if [ -f "${MEDIA_DIR}/temp/PikPak_jf.mp4.aria2" ]; then
            ERROR "存在 ${MEDIA_DIR}/temp/PikPak_jf.mp4.aria2 文件，下载不完整！"
            exit 1
        else
            INFO "PikPak_jf.mp4 下载成功！"
        fi
    else
        ERROR "PikPak_jf.mp4 下载失败！"
        exit 1
    fi

    start_time1=$(date +%s)

    config_size=$(du -k ${MEDIA_DIR}/temp/config_jf.mp4 | cut -f1)
    if [[ "$config_size" -le 3200000 ]]; then
        ERROR "config_jf.mp4 下载不完整，文件大小(in KB):$config_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media"
    pull_run_glue 7z x -aoa -mmt=16 temp/config_jf.mp4
    mv ${MEDIA_DIR}/jf_config ${MEDIA_DIR}/config

    all_size=$(du -k ${MEDIA_DIR}/temp/all_jf.mp4 | cut -f1)
    if [[ "$all_size" -le 30000000 ]]; then
        ERROR "all_jf.mp4 下载不完整，文件大小(in KB):$all_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media/xiaoya"
    pull_run_glue 7z x -aoa -mmt=16 /media/temp/all_jf.mp4

    pikpak_size=$(du -k ${MEDIA_DIR}/temp/PikPak_jf.mp4 | cut -f1)
    if [[ "$pikpak_size" -le 14000000 ]]; then
        ERROR "PikPak_jf.mp4 下载不完整，文件大小(in KB):$pikpak_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media/xiaoya"
    pull_run_glue 7z x -aoa -mmt=16 /media/temp/PikPak_jf.mp4

    end_time1=$(date +%s)
    total_time1=$((end_time1 - start_time1))
    total_time1=$((total_time1 / 60))
    INFO "解压执行时间：$total_time1 分钟"

    INFO "设置目录权限..."
    INFO "这可能需要一定时间，请耐心等待！"
    chmod -R 777 "${MEDIA_DIR}"

}

function unzip_xiaoya_all_jellyfin() {

    get_config_dir

    get_media_dir

    if [ -d "${MEDIA_DIR}/config" ]; then
        rm -rf ${MEDIA_DIR}/config
    fi
    mkdir -p "${MEDIA_DIR}/xiaoya"

    INFO "开始解压..."

    start_time1=$(date +%s)

    config_size=$(du -k ${MEDIA_DIR}/temp/config_jf.mp4 | cut -f1)
    if [[ "$config_size" -le 3200000 ]]; then
        ERROR "config_jf.mp4 下载不完整，文件大小(in KB):$config_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media"
    pull_run_glue 7z x -aoa -mmt=16 temp/config_jf.mp4
    mv ${MEDIA_DIR}/jf_config ${MEDIA_DIR}/config

    all_size=$(du -k ${MEDIA_DIR}/temp/all_jf.mp4 | cut -f1)
    if [[ "$all_size" -le 30000000 ]]; then
        ERROR "all_jf.mp4 下载不完整，文件大小(in KB):$all_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media/xiaoya"
    pull_run_glue 7z x -aoa -mmt=16 /media/temp/all_jf.mp4

    pikpak_size=$(du -k ${MEDIA_DIR}/temp/PikPak_jf.mp4 | cut -f1)
    if [[ "$pikpak_size" -le 14000000 ]]; then
        ERROR "PikPak_jf.mp4 下载不完整，文件大小(in KB):$pikpak_size 小于预期"
        exit 1
    fi
    extra_parameters="--workdir=/media/xiaoya"
    pull_run_glue 7z x -aoa -mmt=16 /media/temp/PikPak_jf.mp4

    end_time1=$(date +%s)
    total_time1=$((end_time1 - start_time1))
    total_time1=$((total_time1 / 60))
    INFO "解压执行时间：$total_time1 分钟"

    INFO "设置目录权限..."
    INFO "这可能需要一定时间，请耐心等待！"
    chmod -R 777 "${MEDIA_DIR}"

    INFO "解压完成！"

}

function download_xiaoya_jellyfin() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    mkdir -p "${MEDIA_DIR}"/temp
    chown 0:0 "${MEDIA_DIR}"/temp
    chmod 777 "${MEDIA_DIR}"/temp
    free_size=$(df -P "${MEDIA_DIR}" | tail -n1 | awk '{print $4}')
    free_size=$((free_size))
    free_size_G=$((free_size / 1024 / 1024))
    INFO "磁盘容量：${free_size_G}G"

    if [ -f "${MEDIA_DIR}/temp/${1}" ]; then
        INFO "清理旧 ${1} 中..."
        rm -f ${MEDIA_DIR}/temp/${1}
        if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
            rm -rf ${MEDIA_DIR}/temp/${1}.aria2
        fi
    fi

    INFO "开始下载 ${1} ..."
    INFO "下载路径：${MEDIA_DIR}/temp/${1}"

    extra_parameters="--workdir=/media/temp"

    if pull_run_glue aria2c -o "${1}" --allow-overwrite=true --auto-file-renaming=false --enable-color=false -c -x6 "${xiaoya_addr}/d/元数据/Jellyfin/${1}"; then
        if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
            ERROR "存在 ${MEDIA_DIR}/temp/${1}.aria2 文件，下载不完整！"
            exit 1
        else
            INFO "${1} 下载成功！"
        fi
    else
        ERROR "${1} 下载失败！"
        exit 1
    fi

    INFO "设置目录权限..."
    chmod 777 "${MEDIA_DIR}"/temp/"${1}"
    chown 0:0 "${MEDIA_DIR}"/temp/"${1}"

    INFO "下载完成！"

}

function download_wget_xiaoya_jellyfin() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    mkdir -p "${MEDIA_DIR}"/temp
    chown 0:0 "${MEDIA_DIR}"/temp
    chmod 777 "${MEDIA_DIR}"/temp
    free_size=$(df -P "${MEDIA_DIR}" | tail -n1 | awk '{print $4}')
    free_size=$((free_size))
    free_size_G=$((free_size / 1024 / 1024))
    INFO "磁盘容量：${free_size_G}G"

    if [ -f "${MEDIA_DIR}/temp/${1}" ]; then
        INFO "清理旧 ${1} 中..."
        rm -f ${MEDIA_DIR}/temp/${1}
        if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
            rm -rf ${MEDIA_DIR}/temp/${1}.aria2
        fi
    fi

    INFO "开始下载 ${1} ..."
    INFO "下载路径：${MEDIA_DIR}/temp/${1}"

    extra_parameters="--workdir=/media/temp"

    if pull_run_glue wget -c --show-progress "${xiaoya_addr}/d/元数据/Jellyfin/${1}"; then
        if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
            ERROR "存在 ${MEDIA_DIR}/temp/${1}.aria2 文件，下载不完整！"
            exit 1
        else
            INFO "${1} 下载成功！"
        fi
    else
        ERROR "${1} 下载失败！"
        exit 1
    fi

    INFO "设置目录权限..."
    chmod 777 "${MEDIA_DIR}"/temp/"${1}"
    chown 0:0 "${MEDIA_DIR}"/temp/"${1}"

    INFO "下载完成！"

}

function unzip_xiaoya_jellyfin() {

    get_config_dir

    get_media_dir

    free_size=$(df -P "${MEDIA_DIR}" | tail -n1 | awk '{print $4}')
    free_size=$((free_size))
    free_size_G=$((free_size / 1024 / 1024))
    INFO "磁盘容量：${free_size_G}G"

    chmod 777 "${MEDIA_DIR}"
    chown root:root "${MEDIA_DIR}"

    INFO "开始解压 ${MEDIA_DIR}/temp/${1} ..."

    if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
        ERROR "存在 ${MEDIA_DIR}/temp/${1}.aria2 文件，文件不完整！"
        exit 1
    fi

    start_time1=$(date +%s)

    if [ "${1}" == "config_jf.mp4" ]; then
        extra_parameters="--workdir=/media"

        if [ -d "${MEDIA_DIR}/config" ]; then
            rm -rf ${MEDIA_DIR}/config
        fi

        config_size=$(du -k ${MEDIA_DIR}/temp/config_jf.mp4 | cut -f1)
        if [[ "$config_size" -le 3200000 ]]; then
            ERROR "config_jf.mp4 下载不完整，文件大小(in KB):$config_size 小于预期"
            exit 1
        else
            INFO "config_jf.mp4 文件大小验证正常"
            pull_run_glue 7z x -aoa -mmt=16 temp/config_jf.mp4
            mv ${MEDIA_DIR}/jf_config ${MEDIA_DIR}/config
        fi

        INFO "设置目录权限..."
        chmod 777 "${MEDIA_DIR}"/config
    elif [ "${1}" == "all_jf.mp4" ]; then
        extra_parameters="--workdir=/media/xiaoya"

        mkdir -p "${MEDIA_DIR}"/xiaoya

        all_size=$(du -k ${MEDIA_DIR}/temp/all_jf.mp4 | cut -f1)
        if [[ "$all_size" -le 30000000 ]]; then
            ERROR "all_jf.mp4 下载不完整，文件大小(in KB):$all_size 小于预期"
            exit 1
        else
            INFO "all_jf.mp4 文件大小验证正常"
            pull_run_glue 7z x -aoa -mmt=16 /media/temp/all_jf.mp4
        fi

        INFO "设置目录权限..."
        chmod 777 "${MEDIA_DIR}"/xiaoya
    elif [ "${1}" == "PikPak_jf.mp4" ]; then
        extra_parameters="--workdir=/media/xiaoya"

        mkdir -p "${MEDIA_DIR}"/xiaoya

        pikpak_size=$(du -k ${MEDIA_DIR}/temp/PikPak_jf.mp4 | cut -f1)
        if [[ "$pikpak_size" -le 14000000 ]]; then
            ERROR "PikPak_jf.mp4 下载不完整，文件大小(in KB):$pikpak_size 小于预期"
            exit 1
        else
            INFO "PikPak_jf.mp4 文件大小验证正常"
            pull_run_glue 7z x -aoa -mmt=16 /media/temp/PikPak_jf.mp4
        fi

        INFO "设置目录权限..."
        chmod 777 "${MEDIA_DIR}"/xiaoya
    fi

    end_time1=$(date +%s)
    total_time1=$((end_time1 - start_time1))
    total_time1=$((total_time1 / 60))
    INFO "解压执行时间：$total_time1 分钟"

    INFO "解压完成！"

}

function main_download_unzip_xiaoya_jellyfin() {

    __data_downloader=$(cat ${DDSREM_CONFIG_DIR}/data_downloader.txt)

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}下载/解压 元数据${Font}\n"
    echo -e "1、下载并解压 全部元数据"
    echo -e "2、解压 全部元数据"
    echo -e "3、下载 all_jf.mp4"
    echo -e "4、解压 all_jf.mp4"
    echo -e "5、解压 all_jf.mp4 的指定元数据目录【非全部解压】"
    echo -e "6、下载 config_jf.mp4"
    echo -e "7、解压 config_jf.mp4"
    echo -e "8、下载 PikPak_jf.mp4"
    echo -e "9、解压 PikPak_jf.mp4"
    echo -e "10、当前下载器【aria2/wget】                  当前状态：${Green}${__data_downloader}${Font}"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-10]:" num
    case "$num" in
    1)
        clear
        if [ "${__data_downloader}" == "wget" ]; then
            download_wget_unzip_xiaoya_all_jellyfin
        else
            download_unzip_xiaoya_all_jellyfin
        fi
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    2)
        clear
        unzip_xiaoya_all_jellyfin
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    3)
        clear
        if [ "${__data_downloader}" == "wget" ]; then
            download_wget_xiaoya_jellyfin "all_jf.mp4"
        else
            download_xiaoya_jellyfin "all_jf.mp4"
        fi
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    4)
        clear
        unzip_xiaoya_jellyfin "all_jf.mp4"
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    5)
        clear
        unzip_appoint_xiaoya_emby_jellyfin "all_jf.mp4"
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    6)
        clear
        if [ "${__data_downloader}" == "wget" ]; then
            download_wget_xiaoya_jellyfin "config_jf.mp4"
        else
            download_xiaoya_jellyfin "config_jf.mp4"
        fi
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    7)
        clear
        unzip_xiaoya_jellyfin "config_jf.mp4"
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    8)
        clear
        if [ "${__data_downloader}" == "wget" ]; then
            download_wget_xiaoya_jellyfin "PikPak_jf.mp4"
        else
            download_xiaoya_jellyfin "PikPak_jf.mp4"
        fi
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    9)
        clear
        unzip_xiaoya_jellyfin "PikPak_jf.mp4"
        return_menu "main_download_unzip_xiaoya_jellyfin"
        ;;
    10)
        if [ "${__data_downloader}" == "wget" ]; then
            echo 'aria2' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
        elif [ "${__data_downloader}" == "aria2" ]; then
            echo 'wget' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
        else
            echo 'aria2' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
        fi
        clear
        main_download_unzip_xiaoya_jellyfin
        ;;
    0)
        clear
        main_xiaoya_all_jellyfin
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-10]'
        main_download_unzip_xiaoya_jellyfin
        ;;
    esac

}

function install_jellyfin_xiaoya_all_jellyfin() {

    get_docker0_url

    MODE=bridge

    get_xiaoya_hosts

    get_nsswitch_conf_path

    echo "http://$docker0:6909" > "${CONFIG_DIR}"/jellyfin_server.txt

    if [ ! -f "${CONFIG_DIR}"/infuse_api_key.txt ]; then
        echo "e825ed6f7f8f44ffa0563cddaddce14d" > "${CONFIG_DIR}"/infuse_api_key.txt
    fi

    cpu_arch=$(uname -m)
    INFO "您的架构是：$cpu_arch"
    case $cpu_arch in
    "x86_64" | *"amd64"*)
        docker_pull "nyanmisaka/jellyfin:240220-amd64-legacy"
        docker run -d \
            --name "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v "${MEDIA_DIR}/config/cache:/cache" \
            --user 0:0 \
            -p 6909:8096 \
            -p 6920:8920 \
            -p 1909:1900/udp \
            -p 7369:7359/udp \
            --privileged=true \
            --restart=always \
            -e TZ=Asia/Shanghai \
            nyanmisaka/jellyfin:240220-amd64-legacy
        ;;
    "aarch64" | *"arm64"* | *"armv8"* | *"arm/v8"*)
        docker_pull "nyanmisaka/jellyfin:240220-arm64"
        docker run -d \
            --name "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v "${MEDIA_DIR}/config/cache:/cache" \
            --user 0:0 \
            -p 6909:8096 \
            -p 6920:8920 \
            -p 1909:1900/udp \
            -p 7369:7359/udp \
            --privileged=true \
            --restart=always \
            -e TZ=Asia/Shanghai \
            nyanmisaka/jellyfin:240220-arm64
        ;;
    *)
        ERROR "全家桶 Jellyfin 目前只支持 amd64 和 arm64 架构，你的架构是：$cpu_arch"
        exit 1
        ;;
    esac

    wait_jellyfin_start

    sleep 4

    if ! curl -I -s http://$docker0:2346/ | grep -q "302"; then
        INFO "重启小雅容器中..."
        docker restart "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
        wait_xiaoya_start
    fi

    INFO "Jellyfin 安装完成！"
    if command -v ifconfig > /dev/null 2>&1; then
        localip=$(ifconfig -a | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1)
    else
        localip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
    fi
    INFO "请浏览器访问 ${Sky_Blue}http://${localip}:2346${Font} 登入 Jellyfin，用户名：${Sky_Blue}ailg${Font}   密码：${Sky_Blue}5678${Font}"

}

function uninstall_xiaoya_all_jellyfin() {

    OLD_MEDIA_DIR=$(docker inspect \
        --format='{{range .Mounts}}{{if eq .Destination "/config"}}{{.Source}}{{end}}{{end}}' \
        "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)" |
        sed 's!/[^/]*$!!')
    INFO "是否${Red}删除配置文件${Font} [Y/n]（默认 Y 删除）"
    INFO "配置文件路径：${OLD_MEDIA_DIR}"
    read -erp "Clean config:" CLEAN_CONFIG
    [[ -z "${CLEAN_CONFIG}" ]] && CLEAN_CONFIG="y"

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始卸载小雅Jellyfin全家桶${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)"
    cpu_arch=$(uname -m)
    case $cpu_arch in
    "x86_64" | *"amd64"*)
        docker rmi nyanmisaka/jellyfin:240220-amd64-legacy
        ;;
    "aarch64" | *"arm64"* | *"armv8"* | *"arm/v8"*)
        docker rmi nyanmisaka/jellyfin:240220-arm64
        ;;
    esac
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        rm -rf "${OLD_MEDIA_DIR}"
    fi

    INFO "Jellyfin 全家桶卸载成功！"

}

function main_xiaoya_all_jellyfin() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Jellyfin全家桶${Font}\n"
    echo -e "${Sky_Blue}Jellyfin 全家桶元数据由 AI老G 更新维护，在此表示感谢！"
    echo -e "Jellyfin 全家桶安装前提条件："
    echo -e "1. 硬盘140G以上（如果无需完整安装则 60G 以上即可）"
    echo -e "2. 内存3.5G以上空余空间${Font}"
    echo -e "\n${Red}注意：目前官方 Jellyfin 安装方案已经长久未维护！"
    echo -e "如果您需要安装 小雅Jellyfin 全家桶，请使用 AI老G 的脚本安装，风险自担。"
    echo -e "脚本命令：bash <(curl -sSLf https://xy.ggbond.org/xy/xy_install.sh)${Font}"
    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        local container_status
        container_status=$(docker inspect --format='{{.State.Status}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)")
        case "${container_status}" in
        "running")
            echo
            ;;
        *)
            echo -e "\n${Red}警告：您的小雅容器未正常启动，请先检查小雅容器后再安装全家桶${Font}\n"
            ;;
        esac
    else
        echo -e "${Red}\n警告：您未安装小雅容器，请先安装小雅容器后再安装全家桶${Font}\n"
    fi
    echo -e "1、一键安装Jellyfin全家桶"
    echo -e "2、下载/解压 元数据"
    echo -e "3、安装Jellyfin"
    echo -e "4、卸载Jellyfin全家桶"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-4]:" num
    case "$num" in
    1)
        clear
        download_unzip_xiaoya_all_jellyfin
        install_jellyfin_xiaoya_all_jellyfin
        INFO "Jellyfin 全家桶安装完成！ "
        return_menu "main_xiaoya_all_jellyfin"
        ;;
    2)
        clear
        main_download_unzip_xiaoya_jellyfin
        ;;
    3)
        clear
        get_config_dir
        get_media_dir
        install_jellyfin_xiaoya_all_jellyfin
        return_menu "main_xiaoya_all_jellyfin"
        ;;
    4)
        clear
        uninstall_xiaoya_all_jellyfin
        return_menu "main_xiaoya_all_jellyfin"
        ;;
    0)
        clear
        main_deprecation
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-4]'
        main_xiaoya_all_jellyfin
        ;;
    esac

}
