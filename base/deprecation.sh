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

function install_xiaoya_notify_cron() {

    if [ ! -f ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt ]; then
        INFO "请输入Resilio-Sync配置文件目录"
        WARN "注意：Resilio-Sync 并且必须安装，本次获取目录只用于存放日志文件！"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        touch ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt
    fi
    if [ ! -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
        get_config_dir
    fi
    if [ ! -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt ]; then
        get_media_dir
    fi

    # 配置定时任务Cron
    while true; do
        INFO "请输入您希望的同步时间"
        read -erp "注意：24小时制，格式：hh:mm，小时分钟之间用英文冒号分隔 （示例：23:45，默认：06:00）：" sync_time
        [[ -z "${sync_time}" ]] && sync_time="06:00"
        read -erp "您希望几天同步一次？（单位：天）（默认：7）" sync_day
        [[ -z "${sync_day}" ]] && sync_day="7"
        # 中文冒号纠错
        time_value=${sync_time//：/:}
        # 提取小时位
        hour=${time_value%%:*}
        # 提取分钟位
        minu=${time_value#*:}
        if [[ "$hour" -ge 0 && "$hour" -le 23 && "$minu" -ge 0 && "$minu" -le 59 ]]; then
            break
        else
            ERROR "输入错误，请重新输入。小时必须为0-23的正整数，分钟必须为0-59的正整数。"
        fi
    done

    while true; do
        INFO "是否开启Emby config自动同步 [Y/n]（默认 Y 开启）"
        read -erp "Auto update config:" AUTO_UPDATE_CONFIG
        [[ -z "${AUTO_UPDATE_CONFIG}" ]] && AUTO_UPDATE_CONFIG="y"
        if [[ ${AUTO_UPDATE_CONFIG} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${AUTO_UPDATE_CONFIG} == [Yy] ]]; then
        auto_update_config=yes
    else
        auto_update_config=no
    fi

    while true; do
        INFO "是否开启自动同步 all pikpak 和 115 元数据 [Y/n]（默认 Y 开启）"
        read -erp "Auto update all & pikpak:" AUTO_UPDATE_ALL_PIKPAK
        [[ -z "${AUTO_UPDATE_ALL_PIKPAK}" ]] && AUTO_UPDATE_ALL_PIKPAK="y"
        if [[ ${AUTO_UPDATE_ALL_PIKPAK} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${AUTO_UPDATE_ALL_PIKPAK} == [Yy] ]]; then
        auto_update_all_pikpak=yes
    else
        auto_update_all_pikpak=no
    fi

    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA
        RETURN_DATA="$(data_crep "r" "install_xiaoya_notify_cron")"
        if [ "${RETURN_DATA}" == "None" ]; then
            INFO "请输入其他参数（默认 无 ）"
            read -erp "Extra parameters:" extra_parameters
        else
            INFO "已读取您上次设置的参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
        fi
        extra_parameters=$(data_crep "w" "install_xiaoya_notify_cron")
    fi

    # 组合定时任务命令
    CRON="${minu} ${hour} */${sync_day} * *   bash -c \"\$(curl -k https://ddsrem.com/xiaoya/xiaoya_notify.sh)\" -s \
--auto_update_all_pikpak=${auto_update_all_pikpak} \
--auto_update_config=${auto_update_config} \
--media_dir=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt) \
--config_dir=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt) \
--emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt) \
--resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt) \
--xiaoya_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt) \
${extra_parameters} >> \
$(cat ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt)/cron.log 2>&1"
    if command -v crontab > /dev/null 2>&1; then
        crontab -l | grep -v sync_emby_config | grep -v xiaoya_notify > /tmp/cronjob.tmp
        echo -e "${CRON}" >> /tmp/cronjob.tmp
        crontab /tmp/cronjob.tmp
        INFO '已经添加下面的记录到crontab定时任务'
        INFO "${CRON}"
        rm -rf /tmp/cronjob.tmp
    elif [ -f /etc/synoinfo.conf ]; then
        # 群晖单独支持
        cp /etc/crontab /etc/crontab.bak
        INFO "已创建/etc/crontab.bak备份文件"
        sedsh '/sync_emby_config/d; /xiaoya_notify/d' /etc/crontab
        echo -e "${CRON}" >> /etc/crontab
        INFO '已经添加下面的记录到crontab定时任务'
        INFO "${CRON}"
    else
        INFO '已经添加下面的记录到crontab定时任务容器'
        INFO "${CRON}"
        docker_pull "ddsderek/xiaoya-cron:latest"
        CRON_PARAMETERS="--auto_update_all_pikpak=${auto_update_all_pikpak} \
--auto_update_config=${auto_update_config} \
--media_dir=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt) \
--config_dir=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt) \
--emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt) \
--resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt) \
--xiaoya_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt) \
${extra_parameters}"
        docker run -itd \
            --name=xiaoya-cron \
            -e TZ=Asia/Shanghai \
            -e CRON="${minu} ${hour} */${sync_day} * *" \
            -e parameters="${CRON_PARAMETERS}" \
            -v "$(cat ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt):/config" \
            -v "$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt):$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt)" \
            -v "$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt):$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)" \
            -v /tmp:/tmp \
            -v /var/run/docker.sock:/var/run/docker.sock:ro \
            --net=host \
            --restart=always \
            ddsderek/xiaoya-cron:latest
    fi

}

function install_resilio() {

    get_media_dir

    if [ -f ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt ]; then
        OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt)
        INFO "已读取Resilio-Sync配置文件路径：${OLD_CONFIG_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${OLD_CONFIG_DIR}
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt
    else
        INFO "请输入配置文件目录（默认 ${MEDIA_DIR}/resilio ）"
        read -erp "CONFIG_DIR:" CONFIG_DIR
        [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR="${MEDIA_DIR}/resilio"
        touch ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt
        echo "${CONFIG_DIR}" > ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt
    fi

    INFO "请输入后台管理端口（默认 8888 ）"
    read -erp "HT_PORT:" HT_PORT
    [[ -z "${HT_PORT}" ]] && HT_PORT="8888"

    INFO "请输入同步端口（默认 55555 ）"
    read -erp "SYNC_PORT:" SYNC_PORT
    [[ -z "${SYNC_PORT}" ]] && SYNC_PORT="55555"

    INFO "resilio容器内存上限（单位：MB，默认：2048）"
    WARN "PS: 部分系统有可能不支持内存限制设置，请输入 n 取消此设置！"
    read -erp "mem_size:" mem_size
    [[ -z "${mem_size}" ]] && mem_size="2048"
    if [[ ${mem_size} == [Nn] ]]; then
        mem_set=
    else
        mem_set="-m ${mem_size}M"
    fi

    INFO "resilio日志文件大小上限（单位：MB；默认：2；设置为 0 则代表关闭日志；设置为 n 则代表取消此设置）"
    read -erp "log_size:" log_size
    [[ -z "${log_size}" ]] && log_size="2"

    if [ "${log_size}" == "0" ]; then
        log_opinion="--log-driver none"
    elif [[ ${log_size} == [Nn] ]]; then
        log_opinion=
    else
        log_opinion="--log-opt max-size=${log_size}m --log-opt max-file=1"
    fi

    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA
        RETURN_DATA="$(data_crep "r" "install_xiaoya_resilio")"
        if [ "${RETURN_DATA}" == "None" ]; then
            INFO "请输入其他参数（默认 无 ）"
            read -erp "Extra parameters:" extra_parameters
        else
            INFO "已读取您上次设置的参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
        fi
        extra_parameters=$(data_crep "w" "install_xiaoya_resilio")
    fi

    while true; do
        INFO "是否自动配置系统 inotify watches & instances 的数值 [Y/n]（默认 Y）"
        read -erp "inotify:" inotify_set
        [[ -z "${inotify_set}" ]] && inotify_set="y"
        if [[ ${inotify_set} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${inotify_set} == [Yy] ]]; then
        if ! grep -q "fs.inotify.max_user_watches=524288" /etc/sysctl.conf; then
            echo fs.inotify.max_user_watches=524288 | tee -a /etc/sysctl.conf
        else
            INFO "系统 inotify watches 数值已存在！"
        fi
        if ! grep -q "fs.inotify.max_user_instances=524288" /etc/sysctl.conf; then
            echo fs.inotify.max_user_instances=524288 | tee -a /etc/sysctl.conf
        else
            INFO "系统 inotify instances 数值已存在！"
        fi
        # 清除多余的inotify设置
        awk \
            '!seen[$0]++ || !/^(fs\.inotify\.max_user_instances|fs\.inotify\.max_user_watches)/' /etc/sysctl.conf > \
            /tmp/sysctl.conf.tmp && mv /tmp/sysctl.conf.tmp /etc/sysctl.conf
        sysctl -p
        INFO "系统 inotify watches & instances 数值配置成功！"
    fi

    INFO "开始安装resilio..."
    if [ ! -d "${CONFIG_DIR}" ]; then
        mkdir -p "${CONFIG_DIR}"
    fi
    if [ ! -d "${CONFIG_DIR}/downloads" ]; then
        mkdir -p "${CONFIG_DIR}/downloads"
    fi
    docker_pull "linuxserver/resilio-sync:latest"
    if [ -n "${extra_parameters}" ]; then
        docker run -d \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)" \
            ${mem_set} \
            ${log_opinion} \
            -e PUID=0 \
            -e PGID=0 \
            -e TZ=Asia/Shanghai \
            -p ${HT_PORT}:8888 \
            -p ${SYNC_PORT}:${SYNC_PORT} \
            -v "${CONFIG_DIR}:/config" \
            -v "${CONFIG_DIR}/downloads:/downloads" \
            -v "${MEDIA_DIR}:/sync" \
            ${extra_parameters} \
            --restart=always \
            linuxserver/resilio-sync:latest
    else
        docker run -d \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)" \
            ${mem_set} \
            ${log_opinion} \
            -e PUID=0 \
            -e PGID=0 \
            -e TZ=Asia/Shanghai \
            -p ${HT_PORT}:8888 \
            -p ${SYNC_PORT}:${SYNC_PORT} \
            -v "${CONFIG_DIR}:/config" \
            -v "${CONFIG_DIR}/downloads:/downloads" \
            -v "${MEDIA_DIR}:/sync" \
            --restart=always \
            linuxserver/resilio-sync:latest
    fi

    if [ "${SYNC_PORT}" != "55555" ]; then
        start_time=$(date +%s)
        while true; do
            if [ -f "${CONFIG_DIR}/sync.conf" ]; then
                sedsh "/\"listening_port\"/c\    \"listening_port\": ${SYNC_PORT}," ${CONFIG_DIR}/sync.conf
                docker restart "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)"
                break
            fi
            current_time=$(date +%s)
            elapsed_time=$((current_time - start_time))
            if ((elapsed_time >= 300)); then
                break
            fi
            sleep 1
        done
    fi

    install_xiaoya_notify_cron

    INFO "安装完成！"
    INFO "请浏览器访问 ${Sky_Blue}http://IP:${HT_PORT}${Font} 进行 Resilio 设置并自行添加下面的同步密钥："
    echo -e "/每日更新/电视剧 （保存到 /sync/xiaoya/每日更新/电视剧 ）
${Sky_Blue}BHB7NOQ4IQKOWZPCLK7BIZXDGIOVRKBUL${Font}
/每日更新/电影 （保存到 /sync/xiaoya/每日更新/电影 ）
${Sky_Blue}BCFQAYSMIIDJBWJ6DB7JXLHBXUGYKEQ43${Font}
/电影/2023 （保存到 /sync/xiaoya/电影/2023 ）
${Sky_Blue}BGUXZBXWJG6J47XVU4HSNJEW4HRMZGOPL${Font}
/纪录片（已刮削） （保存到 /sync/xiaoya/纪录片（已刮削） ）
${Sky_Blue}BDBOMKR6WP7A4X55Z6BY7IA4HUQ3YO4BH${Font}
/音乐 （保存到 /sync/xiaoya/音乐 ）
${Sky_Blue}BHAYCNF5MJSGUF2RVO6XDA55X5PVBKDUB${Font}
/每日更新/动漫 （保存到 /sync/xiaoya/每日更新/动漫 ）
${Sky_Blue}BQEIV6B3DKPZWAFHO7V6QQJO2X3DOQSJ4${Font}
/每日更新/动漫剧场版 （保存到 /sync/xiaoya/每日更新/动漫剧场版 ）
${Sky_Blue}B42SOXBKLMRWHRZMCAIQZWNOBLUUH3HO3${Font}"

}

function update_resilio() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新Resilio-Sync${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)"

}

function uninstall_xiaoya_notify_cron() {

    # 清理定时同步任务
    if command -v crontab > /dev/null 2>&1; then
        crontab -l > /tmp/cronjob.tmp
        sedsh '/sync_emby_config/d; /xiaoya_notify/d' /tmp/cronjob.tmp
        crontab /tmp/cronjob.tmp
        rm -f /tmp/cronjob.tmp
    elif [ -f /etc/synoinfo.conf ]; then
        sedsh '/sync_emby_config/d; /xiaoya_notify/d' /etc/crontab
    else
        if docker container inspect xiaoya-cron > /dev/null 2>&1; then
            docker stop xiaoya-cron
            docker rm xiaoya-cron
            docker rmi ddsderek/xiaoya-cron:latest
        fi
    fi

}

function unisntall_resilio() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始卸载 Resilio-Sync${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)"
    docker rmi linuxserver/resilio-sync:latest
    if [ -f ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt ]; then
        OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/resilio_config_dir.txt)
        rm -rf "${OLD_CONFIG_DIR}"
    fi

    uninstall_xiaoya_notify_cron

    INFO "Resilio-Sync 卸载成功！"

}

function main_resilio() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Resilio-Sync${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_resilio
        return_menu "main_resilio"
        ;;
    2)
        clear
        update_resilio
        return_menu "main_resilio"
        ;;
    3)
        clear
        unisntall_resilio
        return_menu "main_resilio"
        ;;
    0)
        clear
        main_deprecation_xiaoya_all_emby
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_resilio
        ;;
    esac

}

function once_sync_emby_config() {

    if command -v crontab > /dev/null 2>&1; then
        COMMAND_1=$(crontab -l | grep 'xiaoya_notify' | sed 's/^.*-s//; s/>>.*$//' | sed 's/--auto_update_all_pikpak=yes/--auto_update_all_pikpak=no/g')
        if [[ $COMMAND_1 == *"--force_update_config"* ]]; then
            if [[ $COMMAND_1 == *"--force_update_config=no"* ]]; then
                COMMAND_1="${COMMAND_1/--force_update_config=no/--force_update_config=yes}"
            fi
        else
            COMMAND_1="$COMMAND_1 --force_update_config=yes"
        fi
        if [ -z "$COMMAND_1" ]; then
            get_config_dir
            get_media_dir
            COMMAND="bash -c \"\$(curl -k https://ddsrem.com/xiaoya/xiaoya_notify.sh | head -n -2 && echo detection_config_update)\" -s \
--auto_update_all_pikpak=no \
--auto_update_config=yes \
--force_update_config=yes \
--media_dir=${MEDIA_DIR} \
--config_dir=${CONFIG_DIR} \
--emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt) \
--resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt) \
--xiaoya_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
        else
            COMMAND="bash -c \"\$(curl -k https://ddsrem.com/xiaoya/xiaoya_notify.sh | head -n -2 && echo detection_config_update)\" -s ${COMMAND_1}"
        fi
    elif [ -f /etc/synoinfo.conf ]; then
        COMMAND_1=$(grep 'xiaoya_notify' /etc/crontab | sed 's/^.*-s//; s/>>.*$//' | sed 's/--auto_update_all_pikpak=yes/--auto_update_all_pikpak=no/g')
        if [[ $COMMAND_1 == *"--force_update_config"* ]]; then
            if [[ $COMMAND_1 == *"--force_update_config=no"* ]]; then
                COMMAND_1="${COMMAND_1/--force_update_config=no/--force_update_config=yes}"
            fi
        else
            COMMAND_1="$COMMAND_1 --force_update_config=yes"
        fi
        if [ -z "$COMMAND_1" ]; then
            get_config_dir
            get_media_dir
            COMMAND="bash -c \"\$(curl -k https://ddsrem.com/xiaoya/xiaoya_notify.sh | head -n -2 && echo detection_config_update)\" -s \
--auto_update_all_pikpak=no \
--auto_update_config=yes \
--force_update_config=yes \
--media_dir=${MEDIA_DIR} \
--config_dir=${CONFIG_DIR} \
--emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt) \
--resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt) \
--xiaoya_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
        else
            COMMAND="bash -c \"\$(curl -k https://ddsrem.com/xiaoya/xiaoya_notify.sh | head -n -2 && echo detection_config_update)\" -s ${COMMAND_1}"
        fi
    else
        if docker container inspect xiaoya-cron > /dev/null 2>&1; then
            # 先更新 xiaoya-cron，再运行立刻同步
            container_update xiaoya-cron
            sleep 10
            COMMAND="docker exec -it xiaoya-cron bash /app/command.sh"
        else
            get_config_dir
            get_media_dir
            COMMAND="bash -c \"\$(curl -k https://ddsrem.com/xiaoya/xiaoya_notify.sh | head -n -2 && echo detection_config_update)\" -s \
--auto_update_all_pikpak=no \
--auto_update_config=yes \
--force_update_config=yes \
--media_dir=${MEDIA_DIR} \
--config_dir=${CONFIG_DIR} \
--emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt) \
--resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt) \
--xiaoya_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
        fi
    fi
    echo -e "${COMMAND}" > /tmp/sync_command.sh
    echo -e "${COMMAND}"

    while true; do
        INFO "是否前台输出运行日志 [Y/n]（默认 Y）"
        read -erp "Log out:" LOG_OUT
        [[ -z "${LOG_OUT}" ]] && LOG_OUT="y"
        if [[ ${LOG_OUT} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始同步小雅Emby的config目录${Blue} $i ${Font}\r"
        sleep 1
    done

    echo > /tmp/sync_config.log
    # 后台运行
    bash /tmp/sync_command.sh > /tmp/sync_config.log 2>&1 &
    # 获取pid
    pid=$!
    if [[ ${LOG_OUT} == [Yy] ]]; then
        clear
        # 实时输出模式
        while ps ${pid} > /dev/null; do
            clear
            cat /tmp/sync_config.log
            sleep 4
        done
        sleep 2
        rm -f /tmp/sync_command.sh
    else
        # 后台运行模式
        clear
        INFO "Emby config同步后台运行中..."
        INFO "运行日志存于 /tmp/sync_config.log 文件内。"
        # 守护进程，最终清理运行产生的文件
        {
            while ps ${pid} > /dev/null; do sleep 4; done
            sleep 2
            rm -f /tmp/sync_command.sh
        } &
    fi

}

function judgment_xiaoya_notify_status() {

    if command -v crontab > /dev/null 2>&1; then
        if crontab -l | grep 'xiaoya_notify\|sync_emby_config' > /dev/null 2>&1; then
            echo -e "${Green}已创建${Font}"
        else
            echo -e "${Red}未创建${Font}"
        fi
    elif [ -f /etc/synoinfo.conf ]; then
        if grep 'xiaoya_notify\|sync_emby_config' /etc/crontab > /dev/null 2>&1; then
            echo -e "${Green}已创建${Font}"
        else
            echo -e "${Red}未创建${Font}"
        fi
    else
        if docker container inspect xiaoya-cron > /dev/null 2>&1; then
            echo -e "${Green}已创建${Font}"
        else
            echo -e "${Red}未创建${Font}"
        fi
    fi

}

function main_deprecation_xiaoya_alist() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Alist（弃用菜单）${Font}\n"
    echo -e "1、创建/删除 定时同步更新数据（${Red}功能已弃用，只提供删除${Font}）  当前状态：$(judgment_xiaoya_alist_sync_data_status)"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-1]:" num
    case "$num" in
    1)
        clear
        if command -v crontab > /dev/null 2>&1; then
            if crontab -l | grep xiaoya_data_downloader > /dev/null 2>&1; then
                for i in $(seq -w 3 -1 0); do
                    echo -en "即将删除同步定时任务${Blue} $i ${Font}\r"
                    sleep 1
                done
                uninstall_xiaoya_alist_sync_data
                clear
                INFO "已删除"
            else
                INFO "功能已弃用，目前只提供删除！"
            fi
        elif [ -f /etc/synoinfo.conf ]; then
            if grep 'xiaoya_data_downloader' /etc/crontab > /dev/null 2>&1; then
                for i in $(seq -w 3 -1 0); do
                    echo -en "即将删除同步定时任务${Blue} $i ${Font}\r"
                    sleep 1
                done
                uninstall_xiaoya_alist_sync_data
                clear
                INFO "已删除"
            else
                INFO "功能已弃用，目前只提供删除！"
            fi
        else
            INFO "功能已弃用，目前只提供删除！"
        fi
        return_menu "main_deprecation_xiaoya_alist"
        ;;
    0)
        clear
        main_deprecation
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-1]'
        main_deprecation_xiaoya_alist
        ;;
    esac

}

function main_deprecation_xiaoya_all_emby() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Emby全家桶（弃用菜单）${Font}\n"
    echo -ne "${INFO} 界面加载中...${Font}\r"
    echo -e "1、替换DOCKER_ADDRESS（${Red}已弃用${Font}）
2、安装/更新/卸载 Resilio-Sync（${Red}已弃用${Font}）      当前状态：$(judgment_container "${xiaoya_resilio_name}")
3、立即同步小雅Emby config目录（${Red}已弃用${Font}）
4、创建/删除 同步定时更新任务（${Red}已弃用${Font}）       当前状态：$(judgment_xiaoya_notify_status)"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-4]:" num
    case "$num" in
    1)
        clear
        WARN "此功能已弃用！"
        return_menu "main_deprecation_xiaoya_all_emby"
        ;;
    2)
        clear
        main_resilio
        ;;
    3)
        clear
        once_sync_emby_config
        ;;
    4)
        clear
        if command -v crontab > /dev/null 2>&1; then
            if crontab -l | grep xiaoya_notify > /dev/null 2>&1; then
                for i in $(seq -w 3 -1 0); do
                    echo -en "即将删除Emby config同步定时任务${Blue} $i ${Font}\r"
                    sleep 1
                done
                uninstall_xiaoya_notify_cron
                clear
                INFO "已删除"
            else
                install_xiaoya_notify_cron
            fi
        elif [ -f /etc/synoinfo.conf ]; then
            if grep 'xiaoya_notify' /etc/crontab > /dev/null 2>&1; then
                for i in $(seq -w 3 -1 0); do
                    echo -en "即将删除Emby config同步定时任务${Blue} $i ${Font}\r"
                    sleep 1
                done
                uninstall_xiaoya_notify_cron
                clear
                INFO "已删除"
            else
                install_xiaoya_notify_cron
            fi
        else
            if docker container inspect xiaoya-cron > /dev/null 2>&1; then
                for i in $(seq -w 3 -1 0); do
                    echo -en "即将删除Emby config同步定时任务${Blue} $i ${Font}\r"
                    sleep 1
                done
                uninstall_xiaoya_notify_cron
                clear
                INFO "已删除"
            else
                install_xiaoya_notify_cron
            fi
        fi
        return_menu "main_deprecation_xiaoya_all_emby"
        ;;
    0)
        clear
        main_deprecation
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-11]'
        main_deprecation_xiaoya_all_emby
        ;;
    esac

}

function main_deprecation() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————
${Blue}弃用菜单${Font}\n
1、安装/更新/卸载 小雅Alist & 账号管理        当前状态：$(judgment_container "${xiaoya_alist_name}")
2、安装/更新/卸载 小雅Emby全家桶              当前状态：$(judgment_container "${xiaoya_emby_name}")
3、安装/卸载 小雅Jellyfin全家桶              当前状态：$(judgment_container "${xiaoya_jellyfin_name}")
0、返回上级
——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        main_deprecation_xiaoya_alist
        ;;
    2)
        clear
        main_deprecation_xiaoya_all_emby
        ;;
    3)
        clear
        main_xiaoya_all_jellyfin
        ;;
    0)
        clear
        main_advanced_configuration
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_deprecation
        ;;
    esac

}
