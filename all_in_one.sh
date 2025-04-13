#!/bin/bash
# shellcheck shell=bash
# shellcheck disable=SC2086
# shellcheck source=/dev/null
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
DATE_VERSION="v1.8.3-2025_01_28_16_08"
#
# ——————————————————————————————————————————————————————————————————————————————————
amilys_embyserver_latest_version=4.8.11.0
emby_embyserver_latest_version=4.8.11.0
amilys_embyserver_beta_version=4.9.0.46
emby_embyserver_beta_version=4.9.0.47
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

function __unzip_metadata_debug() {

    DEBUG "${OSNAME} $(uname -a)"
    # if [ -f "${CONFIG_DIR}/ali2115.txt" ]; then
    #     DEBUG "ali2115 配置情况：已开启！"
    # else
    #     DEBUG "ali2115 配置情况：未配置！"
    # fi
    # DEBUG "$(pull_run_glue xxd -g 1 -l 256 "/media/temp/${1}")"
    # DEBUG "$(pull_run_glue xxd -g 1 -s -256 "/media/temp/${1}")"
    ERROR "解压元数据失败！"
    exit 1

}

# shellcheck disable=SC2034
mirrors=(
    "docker.io"
    "hub.rat.dev"
    "dockerhub.ggbox.us.kg"
    "docker.fxxk.dedyn.io"
    "docker.jsdelivr.fyi"
    "dockerhub.anzu.vip"
    "freeno.xyz"
    "docker.anyhub.us.kg"
    "dockerhub.icu"
    "dk.nastool.de"
    "func.ink"
    "proxy.1panel.live"
    "docker-0.unsee.tech"
    "docker.zhai.cm"
    "a.ussh.net"
    "docker.1ms.run"
    "lispy.org"
    "docker.kejilion.pro"
)

pikpakshare_list_base64="6auY5riF55S15b2xL+WQiOmbhjEgICAgICAgIFZOUmxOTEFSTG15eTFWbTI1Q0pQcGMwWG8xICAgICBWTlJsTVd3aUxteXkxVm0yNUNKUHBSek1vMQrpq5jmuIXnlLXlvbEv5ZCI6ZuGMiAgICAgICAgVk5SbFZ3UVlRZ3F2Mzk1a3hHQmhQbURvbzEgICBWTlJsT2ZKMFVVOW5qSk9SaHVyemJzZHBvMQrpq5jmuIXnlLXlvbEv5ZCI6ZuGMyAgICAgICAgVk5SbTN5WnRCR3l3S2ExMTh2enZnQWc2bzEgICAgVk5SbGtETExVVTluakpPUmh1cnpoNEZRbzEK6auY5riF55S15b2xL+WQiOmbhjQgICAgICAgIFZOUm1XT21RQkd5d0thMTE4dnp2bFJpWm8xICBWTlJtOEZwZzdhV04zSFdKR1ZHcDhheFRvMSAK6auY5riF55S15b2xL+WQiOmbhjUgICAgICAgICBWTlJtb0Ztb3JvUlJPaEVraG9fOGtZXzFvMSAgICBWTlJtWk1QMVFncXYzOTVreEdCaGQteVFvMQrpq5jmuIXnlLXlvbEv5ZCI6ZuGNiAgICAgICAgICBWTlJuNkhxaUJHeXdLYTExOHZ6dnVxRnFvMSAgICAgVk5SbXJmVEFCR3l3S2ExMTh2enZxYmN0bzEK6auY5riF55S15b2xL+WQiOmbhjcgICAgICAgICAgVk5SbkpBU1Vyb1JST2hFa2hvXzh0cEdmbzEgICAgVk5SbkF6dm5CR3l3S2ExMTh2enZ3RzFXbzEK6auY5riF55S15b2xL+WQiOmbhjggICAgICAgICAgVk5SbGcwcFM3YVdOM0hXSkdWR3AycFpUbzEgIFZOUmxadzRqVVU5bmpKT1JodXJ6ZVYzRW8xCumrmOa4heeUteW9sS/lkIjpm4Y5ICAgICAgIFZOUm5RYk1ON2FXTjNIV0pHVkdwU2t4Rm8xICBWTlJuTmE0cHlNMk5RWWxLbzc4UTcwRl9vMQrpq5jmuIXnlLXlvbEv5ZCI6ZuGMTAgICAgICAgICBWTlJuYWdCVUNmT2lwQkZvV0NYOEVHU2RvMSAgVk5Sblk3dG9nM2Jfb3J3a29IM2F4ZlBCbzEK6auY5riF55S15b2xL+WQiOmbhjExICAgICAgICAgVk5SUjFjYzBMbXl5R0RlMjFBb0s2VWxobzEgICAgVk5SUXpSbmJMbXl5R0RlMjFBb0s1ZC05bzEK6auY5riF5Ymn6ZuGQS/lkIjpm4YxICAgICAgICAgVk5SVDhXcjhCR3l3MWt0MUhraWpLUjRRbzEgICAgVk5RZjZabVdFM3BWV0dwdUZyaUdxeVB6bzEK6auY5riF5Ymn6ZuGQS/lkIjpm4YyICAgICAgICAgVk5SVDhXcjhCR3l3MWt0MUhraWpLUjRRbzEgICAgVk5RZjZaNDVvaGdlWk8xc21vZEtneGxxbzEK6auY5riF5Ymn6ZuGQS/lkIjpm4YzICAgICAgICAgVk5SVDh6WlhnM2JfVllzbjBiQ3dsVmg1bzEgICAgVk5RZjdIdjhFM3BWV0dwdUZyaUdyN25ubzEK6auY5riF5Ymn6ZuGQS/lkIjpm4Y0ICAgICAgICAgVk5SVDh6WlhnM2JfVllzbjBiQ3dsVmg1bzEgICAgVk5RZjdBMFllSV81bU5uaXA3QjJJdllwbzEgIArpq5jmuIXliafpm4ZBL+WQiOmbhjUgICAgICAgICBWTlJUOWVZZUJHeXcxa3QxSGtpakttTF9vMSAgICBWTlFmQW5jSUhWX3EwdmU2X19TOUh3UllvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjYgICAgICAgICBWTlJUOWVZZUJHeXcxa3QxSGtpakttTF9vMSAgICBWTlFmQXdkTkUzcFZXR3B1RnJpR3NMNVBvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjcgICAgICAgICBWTlJUOWVZZUJHeXcxa3QxSGtpakttTF9vMSAgICBWTlFmQjhBWTktc0YzcVdjT09KRDlPSkZvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjggICAgICAgICBWTlJUQTJIT2czYl9WWXNuMGJDd2xoS3lvMSAgICBWTlFmQnJVcm9oZ2V2d1E2WmFWWkUxXzBvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjkgICAgICAgICBWTlJUQTJIT2czYl9WWXNuMGJDd2xoS3lvMSAgICBWTlFmQzVTR0UzcFZXR3B1RnJpR3NnQWNvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjEwICAgICAgICBWTlJUQTJIT2czYl9WWXNuMGJDd2xoS3lvMSAgICBWTlFmQ0FCeDktc0YzcVdjT09KRDlnaHJvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjExICAgICAgICBWTlJUQU1OdkJHeXcxa3QxSGtpakwtbjBvMSAgICBWTlFmQ19FWk9fZTA1dVJIT1Z6UUR1ODNvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjEyICAgICAgICBWTlJUQU1OdkJHeXcxa3QxSGtpakwtbjBvMSAgICBWTlFmQ3EySVR1NVFTMnB1TU8taDNpRUVvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjEzICAgICAgICBWTlJUQU1OdkJHeXcxa3QxSGtpakwtbjBvMSAgICBWTlFmQ3pGNkFlWmpSMy14YkYtSVBBMTJvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjE0ICAgICAgICBWTlJUQWhPWkxteXlYN3lpQ2I2dDFqVHVvMSAgICBWTlFmRFVvbUhWX3FKb2RCMkdCTDg4R2ZvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjE1ICAgICAgICBWTlJUQWhPWkxteXlYN3lpQ2I2dDFqVHVvMSAgICBWTlFmRGN5ck9fZTA1dVJIT1Z6UUVKbndvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjE2ICAgICAgICBWTlJUQWhPWkxteXlYN3lpQ2I2dDFqVHVvMSAgICBWTlFmRUlLOU9fZTBlVl9GX1RNWE53QTlvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjE3ICAgICAgICBWTlJUQWhPWkxteXlYN3lpQ2I2dDFqVHVvMSAgICBWTlFmRWpqYUhWX3FKb2RCMkdCTDhkZUNvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjE4ICAgICAgICBWTlJUQkNLUExteXlYN3lpQ2I2dDFxRUtvMSAgICBWTlFmR25yaVR1NVFjUVN4VVFXblVWVldvMQrpq5jmuIXliafpm4ZBL+WQiOmbhjE5ICAgICAgICBWTlJUQkNLUExteXlYN3lpQ2I2dDFxRUtvMSAgICBWTlFmR3RENmVJXzVieXdtaUkwLVJvcU1vMQrpq5jmuIXliafpm4ZBL+WQiOmbhjIwICAgICAgICBWTlJUQkNLUExteXlYN3lpQ2I2dDFxRUtvMSAgICBWTlFmSDFmczFvZ1dGYVppT3pmNFNxX21vMQrpq5jmuIXliafpm4ZCL+WQiOmbhjIxICAgICAgICBWTlJUQkNLUExteXlYN3lpQ2I2dDFxRUtvMSAgICBWTlFmSDJ5aEFlWmpiVUxuQTFzZmZZQVhvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjIyICAgICAgICBWTlJUQkNLUExteXlYN3lpQ2I2dDFxRUtvMSAgICBWTlFmSERCNWVJXzVieXdtaUkwLVJ0cWRvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjIzICAgICAgICBWTlJUQkNLUExteXlYN3lpQ2I2dDFxRUtvMSAgICBWTlFmSFhmSUUzcFZ5Vy1oMWllaWhmaUZvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjI0ICAgICAgICBWTlJUQ0s0TGczYl9WWXNuMGJDd21lV1hvMSAgICBWTlFmSVRwNk9fZTBzRTlSV3BIdmVFODRvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjI1ICAgICAgICBWTlJUQ0s0TGczYl9WWXNuMGJDd21lV1hvMSAgICBWTlFmSVhWakhWX3EzXzBMNnVwYVdMU3RvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjI2ICAgICAgICBWTlJUQ0s0TGczYl9WWXNuMGJDd21lV1hvMSAgICBWTlFmSV93UlR1NVFoUXRQOHRhMEpGVW5vMQrpq5jmuIXliafpm4ZCL+WQiOmbhjI3ICAgICAgICBWTlJUQ0s0TGczYl9WWXNuMGJDd21lV1hvMSAgICBWTlFmSWNyc1R1NVFoUXRQOHRhMEpHWDRvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjI4ICAgICAgICBWTlJUQ0s0TGczYl9WWXNuMGJDd21lV1hvMSAgICBWTlFmSWY0TW9oZ2VCV3lVaHR5TU5mcW8xCumrmOa4heWJp+mbhkIv5ZCI6ZuGMjkgICAgICAgIFZOUlRDSzRMZzNiX1ZZc24wYkN3bWVXWG8xICAgIFZOUWk2SkIxT19lMGNQd0MwMnJCbERadm8xCumrmOa4heWJp+mbhkIv5ZCI6ZuGMzAgICAgICAgIFZOUlRDbWJuQ2ZPaTFabDJGdDI1U2p3OG8xICAgIFZOUWlBaElfRTNwVlVJQlc1NkJlQV9qQ28xCumrmOa4heWJp+mbhkIv5ZCI6ZuGMzEgICAgICAgIFZOUlRDbWJuQ2ZPaTFabDJGdDI1U2p3OG8xICAgIFZOUWlEd25FM3BWVUlCVzU2QmVBelo2bzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzMiAgICAgICAgVk5SVEQyY2V5TTJOUVlsS283OE1FelkwbzEgICAgVk5RaUZtOHRIVl9xcTJ5MEY4cGdMbzBDbzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzMyAgICAgICAgVk5SVEQyY2V5TTJOUVlsS283OE1FelkwbzEgICAgVk5RaUdKQzJvaGdlTnlGNy1vTHI4Q190bzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzNCAgICAgICAgVk5SVERIX0tCR3l3MWt0MUhraWpNSEc1bzEgICAgVk5RaUlaZXhPX2UwY1B3QzAyckJubnNMbzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzNSAgICAgICAgVk5SVERoOWZRZ3F2XzZsU1k1Wjc1WjVZbzEgICAgVk5RaUprR3BFM3BWVUlCVzU2QmVDRk53bzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzNiAgICAgICAgVk5SVERoOWZRZ3F2XzZsU1k1Wjc1WjVZbzEgICAgVk5RaUtqZWpvaGdlTnlGNy1vTHI5M3ZvbzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzNyAgICAgICAgVk5SVER5c2hRZ3F2XzZsU1k1Wjc1YTQybzEgICAgVk5RaU5QMnFFM3BWVUlCVzU2QmVEMHRIbzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzOCAgICAgICAgVk5SVER5c2hRZ3F2XzZsU1k1Wjc1YTQybzEgICAgVk5RaU1LWU1PX2UwY1B3QzAyckJvWU5jbzEK6auY5riF5Ymn6ZuGQi/lkIjpm4YzOSAgICAgICAgVk5SVEVHMTFyb1JST2hFa2hvXzRxRlBZbzEgICAgVk5RaVFwNGJvaGdlTnlGN29MckFVbXVvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjQwICAgICAgICBWTlJURUcxMXJvUlJPaEVraG9fNHFGUFlvMSAgICBWTlFpUmZuREhWX3FxMnkwRjhwZ052RGJvMQrpq5jmuIXliafpm4ZCL+WQiOmbhjQxICAgICAgICBWTlJURlZiUEJHeXcxa3QxSGtpak1vQmtvMSAgICBWTlFpVjBuS09fZTBjUHdDMDJyQnE0dmJvMQoK"
pan115share_list_base64="NEtSZW11eCBzdzZwdzc5M3dmcCAyNjI4NDc4MjA5Nzg3MjY0MzE1IHc4MTYK55S15b2xMTA4MFAgc3c2OGZ1dTNubncgMTkyNjk2ODEwNTcyMjgyMzAzMSBwYjU3CueUteW9seaMiea8lOWRmOWvvOa8lOWIhuexuyBzd3owNHByM3poOSAyOTY2MzAyMDA0NDE5NDM4ODA2IHozODEK55S16KeG5YmnIHN3NjhlODEzbm53IDI2NTkwNjMxNzgxMTcyNTAzNzQgbjllMArlkIjpm4YxIHN3enlpd3czd245IDI1MjQ4MTE1NTc1MDA4NTIyNzQgdzFlMArlkIjpm4YyIHN3enlpd3Ezd245IDI2Mzc4OTAyNTgzNzg5MjI3NzcgeDcxNgrlkIjpm4YzIHN3enlpd2Izd245IDI2Mzc4OTYzNjAyMjcyMTU3NDkgcWZlOArliqjnlLvnlLXlvbEgc3d6NmdtbDNmd28gMjc4Mzc1MzU5ODE2NzY3ODE3NiA4ODg4Cuasp+e+jueUteW9sSBzdzY4d3o5M25jYiAyNjU2MjMyMDYwNDAwMzY1NzY4IDY2NjYK576O5YmnIHN3NnBsdDIzbmNiIDI2Mjk4MzAxODUzMjk1NTM3OTYgNjY2NgrljYPpg6jmipbpn7Pnn63liaflkIjpm4Ygc3d6cWg2NzNoNHkgMjg0NDM4ODU0NTQ4Nzk2MTIxMSA1Mjk2CuaKlumfs+efreWJp+WQiOmbhjEuNzdUIHN3eng3NmYzd2ZhIDI5NTUyMjA1NzY3MzcwMDk5NTggbjcyNArmrKfnvo7liacgc3d6bm0zNzN3MXAgMjc3NTU2NzExNjY5NjI0NTQxMiBwZTM1Cumfs+S5kDIy5LiH6aaWIHN3em1xY3IzZnM2ICAyNzgzMzA0NDAzNTg1NTk2NTY2IHhkNjcK6Z+z5LmQMjLkuIfpppYvRERTK0hpUmVzIHN3NjU4dXEzNngyIDI1NjU2NzI0MDM3NjYwMDE0MzUgbWQ5OArpn7PkuZAyMuS4h+mmli/mr43luKbns7vliJcgc3c2NTh1cTM2eDIgMjU2NTQxNjQ3OTcwOTExNzg0MyBtZDk4Cumfs+S5kDIy5LiH6aaWL+e0ouWwvOeyvumAiSBzdzY1OHVxMzZ4MiAyNTY1OTE3Mzc5NTE1MDM5MTc2IG1kOTgK6Z+z5LmQMjLkuIfpppYv5ZCE57G76aOO5qC8IHN3NjU4dXEzNngyIDI1NjU0NjY1ODY5NTM0NjQ4NTcgbWQ5OArpn7PkuZAyMuS4h+mmli/ljY7or60yNzAwMOmmluaXoOaNnyBzdzY1OHViMzZ4MiAyNTY1Mjc0MDU1NzgzMzk4NzM0IHE3ZTAK6Z+z5LmQMjLkuIfpppYv5oyJ5q2M5omL5YiG57G7IHN3aGdldHMzemg5IDI5NjQ1OTI2MjY0OTQ1NDg1NTAgbjZlNgrml6Xpn6nnlLXlvbEgc3d6ZzhkZDN3eWUgMjkzMjI3Mjg1NzEzNDEzNzEwNyBtNWIzCuaXpemfqeWJpyBzd3pqeGNwM3dmYSAyOTUxODcwNjYzMTk4MzUxNjg2IG9mODkgCuWbveS6p+WJpyBzd3owb2ZsM3poOSAyOTU2ODE4MDgwOTY2MzIyMjAzIHE1ZjgK55S15b2xL+WOn+ebmCBzd3pldzRtM25jNiAyOTIwNjE5NTc4NzUwOTI1OTQ2IGkwZDcK55S15b2xL+mfqeWbveWOn+ebmCBzd2hpZDV4M3dmYSAzMDQyOTM2NTE2NzE0NTM3MTA1IHhkZjkK55S15b2xL+WPsOa5vuWOn+ebmCBzd2gzcmloM3dmYSAyOTgxNTAzMjEwMTQ0MjQ0NDg2IGc1MTIK55S15b2xL+mmmea4r+WOn+ebmCBzd2hiZnkzM3dmYSAzMDI1MTI0NTg1MTY5NTkyNTcyIGEzNzIK55S15b2xL1VIROWOn+ebmCBzd2hiczRyM3poOSAzMDIzMzMyMDQxNzgxNjE4NzYzIGVjMzgK5ryU5ZSx5LyaL+WOn+ebmCBzd3oxOHduM3poOSAyOTU5NzI0NzQ5NTI2MzQ1OTAwIHlmNjEK5ryU5ZSx5LyaL+WQiOmbhiBzd3oxODA3M3poOSAyOTU2ODk5ODkwOTA3Nzg2MTMwIHM1OTcKCg=="
quarkshare_list_base64="5Yqo5ryrL+WbveWGheWklue7j+WFuOWKqOeUu+WKqOa8q+Wkp+WFqCA2Yjc5NTIxODM0MmQgMjNkOTUxMjcxZDQ2NDY5N2JlMjMyZGJiNzQ2YjIyN2UK5Yqo5ryrL+W3suWujOe7k+Wbvea8qyA2Yjc5NTIxODM0MmQgZjZhYjZkYzAyMTBhNDJiZWEyZGMyYmZlYTM4YzJiZTQK5Yqo5ryrL+W3suWujOe7k+aXpea8qyA2Yjc5NTIxODM0MmQgZDI2NTk1NmUyNDFlNDlkYmJiN2JmNWU3MTYzMGIxOTMK5Yqo5ryrL+W3suWujOe7k+e+jua8qyA2Yjc5NTIxODM0MmQgYzRkNDI5ZGZjNjQ0NDczNzg2YmRiMjJhYTY3NDIxOTAK5bCP5ZOB55u45aOwLzIwMjTlvrfkupHnpL4gZWNlNTJkNjNiNjk4IGRhZTJmMzZkMzZkMDQ3M2I4OWZmODRkYWE4MWI4MzAzCuWwj+WTgeebuOWjsC/lsI/lk4HlpKflkIjpm4YgZTgyNzI2NGVhNDUzIDYwOWM1ZWI4YjMyNDRkYzI5NThiYzEzZjE2ZDQ1NGVkCuWwj+WTgeebuOWjsC/lsI/lk4Hnuq/kuqvlkIjpm4YgZDhiNGE1ODRmZDFhIGE1Mjk5MzQ5ZDM2OTQyMDY4YWRjODhiOTUyYzdjNDYxCueUteW9sS/lkIjpm4Yv5LulQUJDROW8gOWktOWQiOmbhiBhNjMyOTY3NzYwY2YgN2RhNGZkMmRjMDhmNGZhNTg1MmY5OTcyMTU1OTI1MTcK55S15b2xL+WQiOmbhi/ku6VFRkdI5byA5aS05ZCI6ZuGIDJmNTliYjVkOTZiOSA3YjcxNzM3ZTNjZDg0M2M1YTkzN2FjOTdhNTM1NDJkZArnlLXlvbEv5ZCI6ZuGL+S7pUlKS0zlvIDlpLTlkIjpm4YgNTA4MjhjMzY4ZGVmIDA5Njk1MGUzZDEwMjQyYjE5NjZiNzc3ODExMTVhMDdhCueUteW9sS/lkIjpm4Yv5LulTU5PUOW8gOWktOWQiOmbhiBlMDdlMjZhZWNjMDggYTJiMzA1MzE2MzFjNDZkY2IzOWYzMjA2OTc4OTgyOTUK55S15b2xL+WQiOmbhi/ku6VRUlNU5byA5aS05ZCI6ZuGIDA1MzZhMzhhMzU2ZSAxZDE3NWRiMzBlYWE0NTRlOWRiYzVlYWEwOWUxZTQ1NArnlLXlvbEv5ZCI6ZuGL+S7pVVWV1jlvIDlpLTlkIjpm4YgZTI3M2VmNjk3NDAzIDZkYmRhNmU4MTdlYjQxNDViYTJkZDY4MWU1N2FhNjc1CueUteW9sS/lkIjpm4Yv5LulWVrlvIDlpLTlkIjpm4YgYzhhYzZjODhlNWQ4IDQ4YzQ3OWUyNGJhZTRlYzNhNGE5ZDU2ZmNiMDZmY2Y0CueUteW9sS/lkIjpm4Yv5Lul5pWw5a2X5byA5aS05ZCI6ZuGIDQ5YWI3NWQ1MmUwMCBjZWMwNzAyZGIyNmI0N2M1YWJkNDJjYTc5YWJiNjVlMQrnlLXlvbEv5a+85ryUL+WMl+mHjuatpiBmYWIxZWRiOWU1ZWIgZDdiYmZmYzQ1ZWY2NDEwODhmZTRiMjAyOTEwOGJjYWMK55S15b2xL+WvvOa8lC/mtKrph5Hlrp0gYmUyNjFjOGE3ZWI4IGUxZGI5ZDc4NDgyMjQyYzI5NzNkMWNjMjMwNjBjYzFlCueUteW9sS/mvJTlkZgv5YiY5b635Y2OIDE3NjRjMmM4MTYwMyBhYmFlMmY3ZTYxZjU0OTgwODUxNjdlMDdlZjhkZWMzNArnlLXlvbEv5ryU5ZGYL+WRqOaYn+mpsCA2MGRjYTU4MDA5YWYgN2RhNTAyZDI0ZjQ3NGI2MGFmY2MzNDJmZDVhYzBkZTMK55S15b2xL+a8lOWRmC/lkajmtqblj5EgZTU4M2ZhYzQ1NTkyIDgyYzA0OWMxNDA1MDRkNGFhMzFjYmZlMTY0NWNiOWQ4CueUteW9sS/mvJTlkZgv5byg5Zu96I2jIGQzMDAwZjE0OTQyZSA4YzM1ZmNiYjRlODU0ZTUwYjM4NWRmNzAyNjA0ZDM4MgrnlLXlvbEv5ryU5ZGYL+aIkOm+mSBlNWI2NGRmYjFjODMgNjA3Yjg3OWRhMjVjNDQ2NDgzYmM3Zjg5NTBjZDczM2YK55S15b2xL+a8lOWRmC/mnY7kuL3nj40gNDczMzcwZTY1N2MwIGMzOWE1NjYwMDkyZTRiYmFhYzdjYWQzY2YwNjRlMjNjCueUteW9sS/mvJTlkZgv5p2O6L+e5p2wIGJmYzBhNjE1MGFmYyA2ZWViMDM2YzdkN2E0NTgwYWI5NWMxNjViYmVlNzRjMwrnlLXlvbEv5ryU5ZGYL+iIkua3hyA4NGU1M2RkMzc4ZjIgYzU5Yzc4MzU4NGU3NGQ3MDk0Yjk4YTY0OTg0OTI4NzYK55S15b2xL+a8lOWRmC/pgrHmt5HotJ4gYzRiMDQwM2MwZGZhIGE5MjBlMDY1NTVmYjRkNTA5NzU3MGNhMWI0MTBiZDAyCueUteW9sS/nsr7pgInpq5jnlLvotKjpq5jliIbnlLXlvbEgOGYxYjRiN2RjNjllIGQyZTVlOTE2NzRmOTQzNTJiMzMxMGFiODZiOGMyMzhlCueUteW9sS/pn6nlm71S57qnIDU0MzJiZWFlNGYxYSA1MTI0ZjQ3ODlkYWY0NTAwOWJkMTMzYWY1MDk5ODEwMgrnlLXop4bliacvVFZC44CBQVRW5Lqa6KeGIDA4NTIxMmRmMzg1ZCAxNzJiN2VjY2MzODQ0YWU0YTExNDUxZDZhMTQ1ZmZlMArnlLXop4bliacv5bey5a6M57uTL+aVsOWtl+W8gOWktCBjZDRjNWFjN2U4MzAgZGZhMDFjYjE4OTU4NDA4Y2EwZGE3MmIxMzkzMTlhZjMK55S16KeG5YmnL+W3suWujOe7ky/osYbnk6Por4TliIY5LjDku6XkuIrlm73kuqfliacgZDE5YzRlYmUxZmY3IDdiNDI5NDNkNGYyMDQyYWJiOTA3Yzk5ZGRiYjM1NDBkCueUteinhuWJpy/lt7Llroznu5Mv6aaW5a2X5q+NQUJDRCBlMWIyYmE4YjZkNmMgYzg5MjQ2N2IwY2MyNGFhYmFjYmVjNzFhMGI2ZjRkM2MK55S16KeG5YmnL+W3suWujOe7ky/pppblrZfmr41FRkdIIDE2NmZhMGE3Y2E2ZiBmZjU3MDgzZDg5MjM0ZWQzODkzMmRjMDYwOTdkMTE1ZArnlLXop4bliacv5bey5a6M57uTL+mmluWtl+avjUlKS0wgMzdhOTJjMGI3ZjEwIDU4NTkwN2FiYTBlZjQ2NGJhMDBhMGYyMGI0N2ZhMTE2CueUteinhuWJpy/lt7Llroznu5Mv6aaW5a2X5q+NTk1PUCBmYjMzODZlNDJhZjIgMzZlMmY4MWZmNDE0NGE5YzhjMTQ5ODhlZDg5YTg2MGQK55S16KeG5YmnL+W3suWujOe7ky/pppblrZfmr41RUlNUIDQ2Y2UyMTRmNGVkNyAzYjRmOWUwYzY3NTk0OWM5OTI2OTQ3NmU1ZjljMDdhOArnlLXop4bliacv5bey5a6M57uTL+mmluWtl+avjVVWV1ggZmU0NjgxZDdmYjQzIGJjYmNmZDM4ZDI1NDRmNWY5NTFlY2ZlNDMwNDgzMjAzCueUteinhuWJpy/lt7Llroznu5Mv6aaW5a2X5q+NWVogOGQ2NWU4ODViMDU5IDAzNmZkOTg5NWM0YjRhNDdhNTliMTcwNDY3MTU4MTZmCumfs+S5kC/kuabpppnpn7PkuZDkuJbnuqrlhbjol48gZDJkZmEzMjY0N2Y2IDE2N2FlOWVkZDNmZTQ2NjJhMmNlMzc3NTU5ZTM1ZjU4Cumfs+S5kC/lj6Tlhbjpn7PkuZDnsr7pgInlkIjpm4YgMmI0OTc4MjEzYjI5IDY5MDM4ZmYwOTAwNTRhMWViODgwMzEyYmU0Nzc1MzkyCumfs+S5kC/lpKfoh6rnhLbpn7PkuZDns7vliJflkIjpm4YgNjUxZTVmYTkzMDU3IDljOWYzMzM2NzgzZTQ4YWY5ZjQ3YzVlY2Q5OThlOTE0Cumfs+S5kC/nuq/pn7PkuZDlkIjpm4YgMTI4NDgzODFkY2UxIGFlMmNhZWI3ODQ2ZDRmODU4NDY3ZDJiNjI2ZDc4Y2EzCumfs+S5kC/ovabovb3ml6DmjZ/njq/nu5Xpn7PmlYjpn7PkuZDlkIjpm4YgODA1ZDc2YTA4MDYzIDU5M2Y5ODEwNGYxOTQzMDJhMjdhZTkxYmE3Y2QxOGRiCumfs+S5kC/pnIfmkrzlv4PngbXnmoTlj7Lor5fpn7PkuZDlkIjpm4YgZDFhMGI3MDQ2YjIwIDI5NGE1M2EzYzllODRlZjBhMGFjYzA0MTk1YzAyNWQ4Cgo="

GLOBAL_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" # MacOS
GLOBAL_UA_2="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"     # Windows
QUARK_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch"
UC_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) uc-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch"

ALL_METADATA_FILES=("all.mp4" "config.mp4" "115.mp4")

function get_default_network() {

    _default_network=$(cat "${DDSREM_CONFIG_DIR}/default_network.txt")

    if [ "${_default_network}" == "host" ]; then
        echo '--net=host'
    else
        case "${1}" in
        qrcode)
            echo '-p 34256:34256'
            ;;
        xiaoya-proxy)
            echo '-p 9988:9988'
            ;;
        xiaoya-aliyuntvtoken_connector)
            echo '-p 34278:34278'
            ;;
        esac
    fi

}

function get_path() {

    case "${OSNAME}" in
    synology)
        path_lib=/volume1/docker
        ;;
    unraid)
        path_lib=/mnt/user/appdata
        ;;
    fnos)
        if [ -d "/vol1/1000" ]; then
            path_lib=/vol1/1000
        fi
        ;;
    macos)
        if [ -n "${RUN_USER}" ]; then
            path_lib="/Users/${RUN_USER}/Documents"
        fi
        ;;
    *)
        if auto_path="$(df -h | awk '$2 ~ /G/ && $2+0 > 200 {print $6}' | grep -E -v "Avail|loop|boot|overlay|tmpfs|proc" | head -n 1)" > /dev/null 2>&1; then
            if check_path "${auto_path}"; then
                path_lib="${auto_path}"
            fi
        fi
        ;;
    esac

    if [ -z "${path_lib}" ]; then
        case "${1}" in
        xiaoya_alist_config_dir)
            echo '/etc/xiaoya'
            ;;
        xiaoya_alist_media_dir)
            echo '/opt/media'
            ;;
        esac
    else
        case "${1}" in
        xiaoya_alist_config_dir)
            echo "${path_lib}/xiaoya"
            ;;
        xiaoya_alist_media_dir)
            echo "${path_lib}/xiaoya_emby"
            ;;
        esac
    fi

}

function wait_emby_start() {

    local CONTAINER_NAME TARGET_LOG_LINE_SUCCESS start_time
    start_time=$(date +%s)
    CONTAINER_NAME="$(cat "${DDSREM_CONFIG_DIR}"/container_name/xiaoya_emby_name.txt)"
    TARGET_LOG_LINE_SUCCESS="All entry points have started"
    while true; do
        line=$(docker logs "$CONTAINER_NAME" 2>&1 | tail -n 10)
        echo -e "$line"
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))
        if [[ "$line" == *"$TARGET_LOG_LINE_SUCCESS"* ]] && [ "$elapsed_time" -gt 60 ]; then
            break
        fi
        if [ "$elapsed_time" -gt 900 ]; then
            WARN "Emby 未正常启动超时 15 分钟！"
            break
        fi
        sleep 8
    done

}

function wait_xiaoya_start() {

    local TARGET_LOG_LINE_SUCCESS start_time
    start_time=$(date +%s)
    TARGET_LOG_LINE_SUCCESS="success load storage: [/©️"
    while true; do
        line=$(docker logs "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" 2>&1 | tail -n 10)
        echo -e "$line"
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))
        if [[ "$line" == *"$TARGET_LOG_LINE_SUCCESS"* ]] && [ "$elapsed_time" -gt 60 ]; then
            break
        fi
        if [ "$elapsed_time" -gt 600 ]; then
            WARN "小雅alist 未正常启动超时 10 分钟！"
            break
        fi
        sleep 8
    done

}

function check_quark_cookie() {

    if [[ ! -f "${1}/quark_cookie.txt" ]] && [[ ! -s "${1}/quark_cookie.txt" ]]; then
        return 1
    fi
    local cookie url headers response status url2 response2 member member_type vip_88
    cookie=$(head -n1 "${1}/quark_cookie.txt")
    url="https://drive-pc.quark.cn/1/clouddrive/config?pr=ucpro&fr=pc&uc_param_str="
    headers="Cookie: $cookie; User-Agent: $QUARK_UA; Referer: https://pan.quark.cn"
    response=$(curl -s -D - -H "$headers" "$url")
    status=$(echo "$response" | grep -i status | cut -f2 -d: | cut -f1 -d,)
    if [ "$status" == "401" ] || grep -qv "__puus" "${1}/quark_cookie.txt"; then
        ERROR "无效夸克 Cookie"
        return 1
    elif [ "$status" == "200" ]; then
        url2="https://drive-pc.quark.cn/1/clouddrive/member?pr=ucpro&fr=pc&uc_param_str=&fetch_subscribe=true&_ch=home&fetch_identity=true"
        response2=$(curl -s -H "$headers" "$url2")
        member=$(echo $response2 | grep -o '"member_type":"[^"]*"' | sed 's/"member_type":"\(.*\)"/\1/')
        if [ $member == 'EXP_SVIP' ] || [ $member == 'SVIP' ]; then
            vip_88=$(echo $response2 | grep -o '"vip88_new":[t|f]' | cut -f2 -d:)
            if [ $vip_88 == 't' ]; then
                member_type="88VIP会员"
            else
                member_type="SVIP会员"
            fi
        elif [ $member == 'NORMAL' ]; then
            member_type="普通用户"
        else
            member_type="${member//\"/}会员"
        fi
        INFO "有效 夸克 Cookie，${member_type}"
        return 0
    else
        ERROR "请求失败，请检查 Cookie 或网络连接是否正确。"
        return 1
    fi

}

function check_uc_cookie() {

    if [[ ! -f "${1}/uc_cookie.txt" ]] && [[ ! -s "${1}/uc_cookie.txt" ]]; then
        return 1
    fi
    local cookie url headers response status referer set_cookie
    cookie=$(head -n1 "${1}/uc_cookie.txt")
    referer="https://drive.uc.cn"
    url="https://pc-api.uc.cn/1/clouddrive/file/sort?pr=UCBrowser&fr=pc&pdir_fid=0&_page=1&_size=50&_fetch_total=1&_fetch_sub_dirs=0&_sort=file_type:asc,updated_at:desc"
    headers="Cookie: $cookie; User-Agent: $UC_UA; Referer: $referer"
    response=$(curl -s -D - -H "$headers" "$url")
    set_cookie=$(echo "$response" | grep -i "^Set-Cookie:" | sed 's/Set-Cookie: //')
    status=$(echo "$response" | grep -i status | cut -f2 -d: | cut -f1 -d,)
    if [ "$status" == "401" ] || grep -qv "__puus" "${1}/uc_cookie.txt"; then
        ERROR "无效 UC Cookie"
        return 1
    elif [ -n "${set_cookie}" ]; then
        local new_puus new_cookie
        new_puus=$(echo "$set_cookie" | cut -f2 -d: | cut -f1 -d\;)
        new_cookie=${cookie//__puus=[^;]*/$new_puus}
        echo "$new_cookie" > ${1}/uc_cookie.txt
        INFO "有效 UC Cookie 并更新"
        return 0
    elif [ -z "${set_cookie}" ] && [ "${status}" == "200" ]; then
        INFO "有效 UC Cookie"
        return 0
    else
        ERROR "请求失败，请检查 Cookie 或网络连接是否正确。"
        return 1
    fi

}

function check_115_cookie() {

    if [[ ! -f "${1}/115_cookie.txt" ]] && [[ ! -s "${1}/115_cookie.txt" ]]; then
        return 1
    fi
    local cookie url headers response vip
    cookie=$(head -n1 "${1}/115_cookie.txt")
    url="https://my.115.com/?ct=ajax&ac=nav"
    headers="Cookie: $cookie; User-Agent: $GLOBAL_UA_2; Referer: https://115.com/"
    response=$(curl -s -D - -H "$headers" "$url")
    vip=$(echo -e "$response" | grep -o '"vip":[^,]*' | sed 's/"vip"://')
    if echo -e "${response}" | grep -q "user_id"; then
        if [ $vip == "0" ]; then
            INFO "有效 115 Cookie，普通用户"
        else
            INFO "有效 115 Cookie，VIP用户"
        fi
        return 0
    else
        ERROR "请求失败，请检查 Cookie 或网络连接是否正确。"
        return 1
    fi

}

function check_aliyunpan_tvtoken() {

    local token url response refresh_token data_dir
    data_dir="${1}"
    if [ -n "${2}" ]; then
        token="${2}"
    else
        token=$(head -n1 "${data_dir}/myopentoken.txt")
    fi
    url=$(head -n1 "${data_dir}/open_tv_token_url.txt")
    if ! response=$(curl -s "${url}" -X POST -H "User-Agent: $GLOBAL_UA" -H "Rererer: https://www.aliyundrive.com/" -H "Content-Type: application/json" -d '{"refresh_token":"'$token'", "grant_type": "refresh_token"}'); then
        WARN "网络问题，无法检测 阿里云盘 TV Token 有效性"
        return 0
    fi
    refresh_token=$(echo "$response" | sed 's/:\s*/:/g' | sed -n 's/.*"refresh_token":"\([^"]*\).*/\1/p')
    if [ -n "${refresh_token}" ]; then
        echo "${refresh_token}" > "${data_dir}/myopentoken.txt"
        INFO "有效 阿里云盘 TV Token"
        return 0
    else
        ERROR "无效 阿里云盘 TV Token"
        return 1
    fi

}

function check_aliyunpan_refreshtoken() {

    local token referer response refresh_token data_dir
    data_dir="${1}"
    if [ -n "${2}" ]; then
        token="${2}"
    else
        token=$(head -n1 "${data_dir}/mytoken.txt")
    fi
    referer=https://www.aliyundrive.com/
    if ! response=$(curl -s https://auth.aliyundrive.com/v2/account/token -X POST -H "User-Agent: $GLOBAL_UA_2" -H "Content-Type:application/json" -H "Referer: $referer" -d '{"refresh_token":"'$token'", "grant_type": "refresh_token"}'); then
        WARN "网络问题，无法检测 阿里云盘 Refresh Token 有效性"
        return 0
    fi
    refresh_token=$(echo "$response" | sed 's/:\s*/:/g' | sed -n 's/.*"refresh_token":"\([^"]*\).*/\1/p')
    if [ -n "${refresh_token}" ]; then
        echo "${refresh_token}" > "${data_dir}/mytoken.txt"
        INFO "有效 阿里云盘 Refresh Token"
        return 0
    else
        ERROR "无效 阿里云盘 Refresh Token"
        return 1
    fi

}

function check_aliyunpan_opentoken() {

    function cache_result() {

        local file_path cache_path last_modified current_time difference current_hash
        file_path="${1}"
        cache_path="${2}"
        if command -v md5sum > /dev/null 2>&1; then
            current_hash=$(md5sum "$file_path" | awk '{ print $1 }')
        else
            current_hash=$(head -n 1 "$file_path")
        fi
        if [ -f "$cache_path" ] && [ "$(head -n 1 "$cache_path")" == "$current_hash" ]; then
            last_modified=$(date -r "$cache_path" +%s)
            current_time=$(date +%s)
            difference=$(((current_time - last_modified) / 60))
            if [ "$difference" -lt 60 ]; then
                # 文件未更改且操作在60分钟内已执行，跳过此次执行
                return 1
            fi
        fi
        echo "$current_hash" > "$cache_path"
        return 0

    }

    function cache_update() {

        if [ "${3}" == true ]; then
            if command -v md5sum > /dev/null 2>&1; then
                md5sum "${1}" | awk '{ print $1 }' > "${2}"
            else
                head -n 1 "${1}" > "${2}"
            fi
        else
            rm -f "${2}"
        fi

    }

    local token code response refresh_token data_dir url_host
    data_dir="${1}"
    if [ -n "${2}" ]; then
        token="${2}"
    else
        token=$(head -n1 "${data_dir}/myopentoken.txt")
    fi
    if cache_result "${data_dir}/myopentoken.txt" "${DDSREM_CONFIG_DIR}/cache_data/check_aliyunpan_opentoken.txt"; then
        if curl -Is https://api.xhofe.top/alist/ali_open/qr | head -n 1 | grep -q '200'; then
            url_host="api.xhofe.top"
        elif curl -Is https://api.nn.ci/alist/ali_open/qr | head -n 1 | grep -q '200'; then
            url_host="api.nn.ci"
        else
            url_host="api-cf.nn.ci"
        fi
        if ! response=$(curl -s "https://${url_host}/alist/ali_open/token" -X POST -H "User-Agent: $GLOBAL_UA" -H "Rererer: https://www.aliyundrive.com/" -H "Content-Type: application/json" -d '{"refresh_token":"'$token'", "grant_type": "refresh_token"}'); then
            WARN "网络问题，无法检测 阿里云盘 Open Token 有效性"
            cache_update "${data_dir}/myopentoken.txt" "${DDSREM_CONFIG_DIR}/cache_data/check_aliyunpan_opentoken.txt" "false"
            return 0
        fi
        code=$(echo "$response" | sed -n 's/.*"code":"\([^"]*\).*/\1/p')
        refresh_token=$(echo "$response" | sed 's/:\s*/:/g' | sed -n 's/.*"refresh_token":"\([^"]*\).*/\1/p')
        if [ -n "${refresh_token}" ]; then
            echo "${refresh_token}" > "${data_dir}/myopentoken.txt"
            INFO "有效 阿里云盘 Open Token"
            cache_update "${data_dir}/myopentoken.txt" "${DDSREM_CONFIG_DIR}/cache_data/check_aliyunpan_opentoken.txt" "true"
            return 0
        elif [ "${code}" == "Too Many Requests" ]; then
            WARN "已被限流，无法检测 阿里云盘 Open Token 有效性"
            cache_update "${data_dir}/myopentoken.txt" "${DDSREM_CONFIG_DIR}/cache_data/check_aliyunpan_opentoken.txt" "false"
            return 0
        else
            ERROR "无效 阿里云盘 Open Token"
            cache_update "${data_dir}/myopentoken.txt" "${DDSREM_CONFIG_DIR}/cache_data/check_aliyunpan_opentoken.txt" "false"
            return 1
        fi
    else
        INFO "有效 阿里云盘 Open Token（缓存结果）"
        return 0
    fi

}

function qrcode_mode_choose() {

    extra_parameters=

    function qrcode_web() {

        if ! check_port "34256"; then
            ERROR "34256 端口被占用，请关闭占用此端口的程序！"
            exit 1
        fi

        local local_ip
        if [[ "${OSNAME}" = "macos" ]]; then
            local_ip=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
        else
            local_ip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
        fi
        if [ -z "${local_ip}" ]; then
            local_ip="小雅服务器IP"
        fi
        INFO "请浏览器访问 http://${local_ip}:34256 并使用手机APP扫描二维码！"
        # shellcheck disable=SC2046
        docker run -i --rm \
            -v "${1}:/data" \
            -e LANG=C.UTF-8 \
            $(auto_privileged) \
            $(get_default_network "qrcode") \
            ddsderek/xiaoya-glue:python \
            "${2}" --qrcode_mode=web ${extra_parameters}

    }

    if [ "${2}" == "/115cookie/115cookie.py" ]; then
        while true; do
            qrcode_apps=('alipaymini' 'web' 'ios' 'android' 'windows' 'mac' 'linux' 'wechatmini')
            find_qrcode_app=false
            interface=
            for i in "${!qrcode_apps[@]}"; do
                interface="${interface}$((i + 1))、${qrcode_apps[$i]}\n"
            done
            INFO "请选择扫码绑定的设备（默认 1）"
            echo -e "${interface}\c"
            read -erp "QRCODE_APP:" QRCODE_APP_NUM
            [[ -z "${QRCODE_APP_NUM}" ]] && QRCODE_APP_NUM="1"
            for i in "${!qrcode_apps[@]}"; do
                if [[ "$((i + 1))" == "${QRCODE_APP_NUM}" ]]; then
                    qrcode_app="${qrcode_apps[$i]}"
                    find_qrcode_app=true
                    break
                fi
            done
            if [ "${find_qrcode_app}" == true ]; then
                break
            else
                ERROR "输入无效，请重新选择"
            fi
        done
        extra_parameters="--qrcode_app=${qrcode_app}"
    elif [ "${2}" == "/aliyunopentoken/aliyunopentoken.py" ]; then
        if curl -Is https://api.xhofe.top/alist/ali_open/qr | head -n 1 | grep -q '200'; then
            extra_parameters="--api_url=api.xhofe.top"
            INFO "使用 api.xhofe.top 地址"
        elif curl -Is https://api.nn.ci/alist/ali_open/qr | head -n 1 | grep -q '200'; then
            extra_parameters="--api_url=api.nn.ci"
            INFO "使用 api.nn.ci 地址"
        else
            extra_parameters="--api_url=api-cf.nn.ci"
            INFO "使用 api-cf.nn.ci 地址"
        fi
    elif [ "${2}" == "/aliyuntoken/aliyuntoken.py" ]; then
        if curl -Is https://api.xhofe.top/alist/ali/qr | head -n 1 | grep -q '200'; then
            extra_parameters="--api_url=api.xhofe.top"
            INFO "使用 api.xhofe.top 地址"
        elif curl -Is https://api.nn.ci/alist/ali/qr | head -n 1 | grep -q '200'; then
            extra_parameters="--api_url=api.nn.ci"
            INFO "使用 api.nn.ci 地址"
        elif curl -Is https://api-cf.nn.ci/alist/ali/qr | head -n 1 | grep -q '200'; then
            extra_parameters="--api_url=api-cf.nn.ci"
            INFO "使用 api-cf.nn.ci 地址"
        else
            extra_parameters="--api_url=aliyuntoken.vercel.app"
            INFO "使用 aliyuntoken.vercel.app 地址"
        fi
    fi

    while true; do
        INFO "请选择扫码模式 [ 1: 命令行扫码 | 2: 浏览器扫码 ]（默认 2）"
        read -erp "QRCODE_MODE:" QRCODE_MODE
        [[ -z "${QRCODE_MODE}" ]] && QRCODE_MODE="2"
        if [[ ${QRCODE_MODE} == [1] ]]; then
            # shellcheck disable=SC2046
            docker run -i --rm \
                -v "${1}:/data" \
                -e LANG=C.UTF-8 \
                $(auto_privileged) \
                ddsderek/xiaoya-glue:python \
                "${2}" --qrcode_mode=shell ${extra_parameters}
            return 0
        elif [[ ${QRCODE_MODE} == [2] ]]; then
            qrcode_web "${1}" "${2}"
            return 0
        else
            ERROR "输入无效，请重新选择"
        fi
    done

}

function qrocde_common() {

    clear_qrcode_container
    if [ "${DOCKER_ARCH}" == "linux/amd64" ] || [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        INFO "${1} 扫码获取"
        pull_glue_python_ddsrem
        qrcode_mode_choose "${2}" "${3}"
        INFO "操作全部完成！"
    else
        WARN "目前 ${1} 扫码获取只支持amd64和arm64架构，你的架构是：$CPU_ARCH"
    fi

}

function enter_aliyunpan_refreshtoken() {

    while true; do
        INFO "是否使用扫码自动获取 阿里云盘 Token [Y/n]（默认 Y）"
        read -erp "Token:" choose_qrcode_aliyunpan_refreshtoken
        [[ -z "${choose_qrcode_aliyunpan_refreshtoken}" ]] && choose_qrcode_aliyunpan_refreshtoken="y"
        if [[ ${choose_qrcode_aliyunpan_refreshtoken} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${choose_qrcode_aliyunpan_refreshtoken} == [Yy] ]]; then
        qrocde_common "阿里云盘 Refresh Token" "${1}" "/aliyuntoken/aliyuntoken.py"
    fi
    mytokenfilesize=$(cat "${1}"/mytoken.txt)
    mytokenstringsize=${#mytokenfilesize}
    if [ "$mytokenstringsize" -le 31 ] || ! check_aliyunpan_refreshtoken "${1}"; then
        if [[ ${choose_qrcode_aliyunpan_refreshtoken} == [Yy] ]]; then
            WARN "扫码获取 阿里云盘 Token 失败，请手动获取！"
        fi
        while true; do
            INFO "输入你的 阿里云盘 Token（32位长）"
            read -erp "TOKEN:" token
            token_len=${#token}
            if [ "$token_len" -ne 32 ]; then
                ERROR "长度不对,阿里云盘 Token是32位长"
                ERROR "请参考指南配置文件: https://xiaoyaliu.notion.site/xiaoya-docker-69404af849504fa5bcf9f2dd5ecaa75f"
            else
                echo "$token" > "${1}"/mytoken.txt
                if check_aliyunpan_refreshtoken "${1}"; then
                    break
                fi
            fi
        done
    fi

}

function settings_aliyunpan_refreshtoken() {

    if [ "${2}" == "force" ]; then
        enter_aliyunpan_refreshtoken "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/mytoken.txt" ]; then
            rm -f "${1}/mytoken.txt"
        fi
        INFO "删除 mytoken.txt 成功！"
        sleep 2
    else
        mytokenfilesize=$(cat "${1}"/mytoken.txt)
        mytokenstringsize=${#mytokenfilesize}
        if [ "$mytokenstringsize" -le 31 ] || ! check_aliyunpan_refreshtoken "${1}"; then
            enter_aliyunpan_refreshtoken "${1}"
        fi
    fi

}

function enter_aliyunpan_opentoken() {

    while true; do
        INFO "是否使用扫码自动获取 阿里云盘 Open Token [Y/n]（默认 Y）"
        read -erp "Token:" choose_qrcode_aliyunpan_opentoken
        [[ -z "${choose_qrcode_aliyunpan_opentoken}" ]] && choose_qrcode_aliyunpan_opentoken="y"
        if [[ ${choose_qrcode_aliyunpan_opentoken} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${choose_qrcode_aliyunpan_opentoken} == [Yy] ]]; then
        qrocde_common "阿里云盘 Open Token" "${1}" "/aliyunopentoken/aliyunopentoken.py"
    fi
    myopentokenfilesize=$(cat "${1}"/myopentoken.txt)
    myopentokenstringsize=${#myopentokenfilesize}
    if [ "$myopentokenstringsize" -le 279 ] || ! check_aliyunpan_opentoken "${1}"; then
        if [[ ${choose_qrcode_aliyunpan_opentoken} == [Yy] ]]; then
            WARN "扫码获取 阿里云盘 Open Token 失败，请手动获取！"
        fi
        while true; do
            INFO "输入你的 阿里云盘 Open Token（280位长或者335位长）"
            read -erp "OPENTOKEN:" opentoken
            opentoken_len=${#opentoken}
            if [[ "$opentoken_len" -ne 280 ]] && [[ "$opentoken_len" -ne 335 ]]; then
                ERROR "长度不对,阿里云盘 Open Token是280位长或者335位"
                ERROR "请参考指南配置文件: https://xiaoyaliu.notion.site/xiaoya-docker-69404af849504fa5bcf9f2dd5ecaa75f"
            else
                echo "$opentoken" > "${1}"/myopentoken.txt
                if check_aliyunpan_opentoken "${1}"; then
                    break
                fi
            fi
        done
    fi

}

function settings_aliyunpan_opentoken() {

    if [ -f "${1}/open_tv_token_url.txt" ]; then
        mv "${1}/open_tv_token_url.txt" "${1}/open_tv_token_url.txt.bak"
    fi

    if [ "${2}" == "force" ]; then
        enter_aliyunpan_opentoken "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/myopentoken.txt" ]; then
            rm -f "${1}/myopentoken.txt"
        fi
        INFO "删除 myopentoken.txt 成功！"
        sleep 2
    else
        myopentokenfilesize=$(cat "${1}"/myopentoken.txt)
        myopentokenstringsize=${#myopentokenfilesize}
        if [ "$myopentokenstringsize" -le 279 ] || ! check_aliyunpan_opentoken "${1}"; then
            enter_aliyunpan_opentoken "${1}"
        fi
    fi

}

function enter_115_cookie() {

    touch_chmod "${1}/115_cookie.txt"
    while true; do
        INFO "是否使用扫码自动获取 115 Cookie [Y/n]（默认 Y）"
        read -erp "Cookie:" choose_qrcode_115_cookie
        [[ -z "${choose_qrcode_115_cookie}" ]] && choose_qrcode_115_cookie="y"
        if [[ ${choose_qrcode_115_cookie} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${choose_qrcode_115_cookie} == [Yy] ]]; then
        qrocde_common "115 Cookie" "${1}" "/115cookie/115cookie.py"
    fi
    if ! check_115_cookie "${1}"; then
        if [[ ${choose_qrcode_115_cookie} == [Yy] ]]; then
            WARN "扫码获取 115 Cookie 失败，请手动获取！"
        fi
        while true; do
            INFO "输入你的 115 Cookie"
            read -erp "Cookie:" set_115_cookie
            echo -e "${set_115_cookie}" > ${1}/115_cookie.txt
            if check_115_cookie "${1}"; then
                break
            fi
        done
    fi

}

function settings_115_cookie() {

    if [ "${2}" == "force" ]; then
        enter_115_cookie "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/115_cookie.txt" ]; then
            rm -f "${1}/115_cookie.txt"
        fi
        INFO "删除 115_cookie.txt 成功！"
        sleep 2
    else
        if [ ! -f "${1}/115_cookie.txt" ] || ! check_115_cookie "${1}"; then
            while true; do
                INFO "是否配置 115 Cookie [Y/n]（默认 n 不配置）"
                read -erp "Cookie:" choose_115_cookie
                [[ -z "${choose_115_cookie}" ]] && choose_115_cookie="n"
                if [[ ${choose_115_cookie} == [YyNn] ]]; then
                    break
                else
                    ERROR "非法输入，请输入 [Y/n]"
                fi
            done
            if [[ ${choose_115_cookie} == [Yy] ]]; then
                enter_115_cookie "${1}"
            fi
        fi
    fi

}

function enter_quark_cookie() {

    touch_chmod "${1}/quark_cookie.txt"
    while true; do
        INFO "是否使用扫码自动获取 夸克 Cookie [Y/n]（默认 Y）"
        read -erp "Cookie:" choose_qrcode_quark_cookie
        [[ -z "${choose_qrcode_quark_cookie}" ]] && choose_qrcode_quark_cookie="y"
        if [[ ${choose_qrcode_quark_cookie} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${choose_qrcode_quark_cookie} == [Yy] ]]; then
        qrocde_common "夸克 Cookie" "${1}" "/quark_cookie/quark_cookie.py"
    fi
    if ! check_quark_cookie "${1}"; then
        if [[ ${choose_qrcode_quark_cookie} == [Yy] ]]; then
            WARN "扫码获取 夸克 Cookie 失败，请手动获取！"
        fi
        while true; do
            INFO "输入你的 夸克 Cookie"
            read -erp "Cookie:" quark_cookie
            echo -e "${quark_cookie}" > ${1}/quark_cookie.txt
            if check_quark_cookie "${1}"; then
                break
            fi
        done
    fi

}

function settings_quark_cookie() {

    if [ "${2}" == "force" ]; then
        enter_quark_cookie "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/quark_cookie.txt" ]; then
            rm -f "${1}/quark_cookie.txt"
        fi
        INFO "删除 quark_cookie.txt 成功！"
        sleep 2
    else
        if [ ! -f "${1}/quark_cookie.txt" ] || ! check_quark_cookie "${1}"; then
            while true; do
                INFO "是否配置 夸克 Cookie [Y/n]（默认 n 不配置）"
                read -erp "Cookie:" choose_quark_cookie
                [[ -z "${choose_quark_cookie}" ]] && choose_quark_cookie="n"
                if [[ ${choose_quark_cookie} == [YyNn] ]]; then
                    break
                else
                    ERROR "非法输入，请输入 [Y/n]"
                fi
            done
            if [[ ${choose_quark_cookie} == [Yy] ]]; then
                enter_quark_cookie "${1}"
            fi
        fi
    fi

}

function enter_uc_cookie() {

    touch_chmod "${1}/uc_cookie.txt"
    while true; do
        INFO "是否使用扫码自动获取 UC Cookie [Y/n]（默认 Y）"
        read -erp "Cookie:" choose_qrcode_uc_cookie
        [[ -z "${choose_qrcode_uc_cookie}" ]] && choose_qrcode_uc_cookie="y"
        if [[ ${choose_qrcode_uc_cookie} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${choose_qrcode_uc_cookie} == [Yy] ]]; then
        qrocde_common "UC Cookie" "${1}" "/uc_cookie/uc_cookie.py"
    fi
    if ! check_uc_cookie "${1}"; then
        if [[ ${choose_qrcode_uc_cookie} == [Yy] ]]; then
            WARN "扫码获取 UC Cookie 失败，请手动获取！"
        fi
        while true; do
            INFO "输入你的 UC Cookie"
            read -erp "Cookie:" uc_cookie
            echo -e "${uc_cookie}" > ${1}/uc_cookie.txt
            if check_uc_cookie "${1}"; then
                break
            fi
        done
    fi

}

function settings_uc_cookie() {

    if [ "${2}" == "force" ]; then
        enter_uc_cookie "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/uc_cookie.txt" ]; then
            rm -f "${1}/uc_cookie.txt"
        fi
        INFO "删除 uc_cookie.txt 成功！"
        sleep 2
    else
        if [ ! -f "${1}/uc_cookie.txt" ] || ! check_uc_cookie "${1}"; then
            while true; do
                INFO "是否配置 UC Cookie [Y/n]（默认 n 不配置）"
                read -erp "Cookie:" choose_uc_cookie
                [[ -z "${choose_uc_cookie}" ]] && choose_uc_cookie="n"
                if [[ ${choose_uc_cookie} == [YyNn] ]]; then
                    break
                else
                    ERROR "非法输入，请输入 [Y/n]"
                fi
            done
            if [[ ${choose_uc_cookie} == [Yy] ]]; then
                enter_uc_cookie "${1}"
            fi
        fi
    fi

}

function enter_pikpak_account() {

    touch_chmod "${1}/pikpak.txt"
    INFO "输入你的 PikPak 账号（手机号或邮箱）"
    INFO "如果手机号，要\"+区号\"，比如你的手机号\"12345678900\"那么就填\"+8612345678900\""
    read -erp "PikPak_Username:" PikPak_Username
    INFO "输入你的 PikPak 账号密码"
    read -erp "PikPak_Password:" PikPak_Password
    INFO "输入你的 PikPak X-Device-Id"
    read -erp "PikPak_Device_Id:" PikPak_Device_Id
    echo -e "\"${PikPak_Username}\" \"${PikPak_Password}\" \"web\" \"${PikPak_Device_Id}\"" > ${1}/pikpak.txt

}

function settings_pikpak_account() {

    if [ "${2}" == "force" ]; then
        enter_pikpak_account "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/pikpak.txt" ]; then
            rm -f "${1}/pikpak.txt"
        fi
        INFO "删除 pikpak.txt 成功！"
        sleep 2
    else
        if [ ! -f "${1}/pikpak.txt" ]; then
            while true; do
                INFO "是否继续配置 PikPak 账号密码 [Y/n]（默认 n 不配置）"
                read -erp "PikPak_Set:" PikPak_Set
                [[ -z "${PikPak_Set}" ]] && PikPak_Set="n"
                if [[ ${PikPak_Set} == [YyNn] ]]; then
                    break
                else
                    ERROR "非法输入，请输入 [Y/n]"
                fi
            done
            if [[ ${PikPak_Set} == [Yy] ]]; then
                enter_pikpak_account "${1}"
            fi
        fi
    fi

}

function enter_ali2115() {

    touch_chmod "${1}/ali2115.txt"
    if [ -f "${1}/115_cookie.txt" ] && check_115_cookie "${1}"; then
        INFO "自动获取 115 Cookie！"
        set_115_cookie="$(cat ${1}/115_cookie.txt | head -n1)"
    else
        while true; do
            INFO "输入你的 115 Cookie"
            read -erp "Cookie:" set_115_cookie
            if [ -n "${set_115_cookie}" ]; then
                break
            fi
        done
    fi
    while true; do
        INFO "是否自动删除115转存文件 [Y/n]（默认 Y）"
        read -erp "purge_pan115_temp:" purge_pan115_temp
        [[ -z "${purge_pan115_temp}" ]] && purge_pan115_temp="y"
        if [[ ${purge_pan115_temp} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    while true; do
        INFO "是否自动删除阿里云盘转存文件 [Y/n]（默认 Y）"
        read -erp "purge_ali_temp:" purge_ali_temp
        [[ -z "${purge_ali_temp}" ]] && purge_ali_temp="y"
        if [[ ${purge_ali_temp} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    INFO "输入你的 115 转存文件夹 id（默认 0）"
    read -erp "dir_id:" dir_id
    [[ -z "${dir_id}" ]] && dir_id=0
    if [[ ${purge_pan115_temp} == [Yy] ]]; then
        purge_pan115_temp=true
    else
        purge_pan115_temp=false
    fi
    if [[ ${purge_ali_temp} == [Yy] ]]; then
        purge_ali_temp=true
    else
        purge_ali_temp=false
    fi
    echo -e "purge_ali_temp=${purge_ali_temp}\ncookie=\"${set_115_cookie}\"\npurge_pan115_temp=${purge_pan115_temp}\ndir_id=${dir_id}" > ${1}/ali2115.txt

}

function settings_ali2115() {

    if [ "${2}" == "force" ]; then
        enter_ali2115 "${1}"
    elif [ "${2}" == "remove" ]; then
        if [ -f "${1}/ali2115.txt" ]; then
            rm -f "${1}/ali2115.txt"
        fi
        INFO "删除 ali2115.txt 成功！"
        sleep 2
    else
        if [ ! -f "${1}/ali2115.txt" ]; then
            while true; do
                INFO "是否配置 阿里转存115播放（ali2115.txt） [Y/n]（默认 n 不配置）"
                read -erp "ali2115:" ali2115_set
                [[ -z "${ali2115_set}" ]] && ali2115_set="n"
                if [[ ${ali2115_set} == [YyNn] ]]; then
                    break
                else
                    ERROR "非法输入，请输入 [Y/n]"
                fi
            done
            if [[ ${ali2115_set} == [Yy] ]]; then
                enter_ali2115 "${1}"
            fi
        fi
    fi

}

function get_aliyunpan_folder_id() {

    clear_qrcode_container
    if [ "${DOCKER_ARCH}" == "linux/amd64" ] || [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        INFO "阿里云盘 folder id 自动获取"
        pull_glue_python_ddsrem
        # shellcheck disable=SC2046
        docker run -it --rm \
            -v "${1}:/data" \
            -e LANG=C.UTF-8 \
            $(auto_privileged) \
            ddsderek/xiaoya-glue:python \
            /get_folder_id/get_folder_id.py --data_path='/data' --drive_mode=r
    else
        WARN "目前阿里云盘 folder id 自动获取只支持amd64和arm64架构，你的架构是：$CPU_ARCH"
    fi

}

function settings_aliyunpan_folder_id() {

    folderidfilesize=$(cat "${1}"/temp_transfer_folder_id.txt)
    folderidstringsize=${#folderidfilesize}
    if [ ! -f "${1}/temp_transfer_folder_id.txt" ] || [ "$folderidstringsize" -le 39 ]; then
        while true; do
            INFO "是否自动获取 阿里云盘转存目录 folder id [Y/n]（默认 Y）"
            read -erp "Token:" auto_get_folder_id
            [[ -z "${auto_get_folder_id}" ]] && auto_get_folder_id="y"
            if [[ ${auto_get_folder_id} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${auto_get_folder_id} == [Yy] ]]; then
            get_aliyunpan_folder_id "${1}"
        fi

        folderidfilesize=$(cat "${1}"/temp_transfer_folder_id.txt)
        folderidstringsize=${#folderidfilesize}
        if [ "$folderidstringsize" -le 39 ]; then
            while true; do
                INFO "输入你的阿里云盘转存目录 folder id"
                read -erp "FOLDERID:" folderid
                folder_id_len=${#folderid}
                if [ "$folder_id_len" -ne 40 ]; then
                    ERROR "长度不对，阿里云盘 folder id 是40位长"
                    ERROR "请参考指南配置文件: https://xiaoyaliu.notion.site/xiaoya-docker-69404af849504fa5bcf9f2dd5ecaa75f"
                else
                    echo "$folderid" > "${1}"/temp_transfer_folder_id.txt
                    break
                fi
            done
        fi
    fi

}

function get_config_dir() {

    local xiaoya_config_dir DEFAULT_CONFIG_DIR

    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        xiaoya_config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
    fi

    while true; do
        if [ -n "${xiaoya_config_dir}" ]; then
            if [ ! -f "${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt" ] || [ -z "$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)" ]; then
                echo "${xiaoya_config_dir}" > "${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt"
            fi
            if [ "${xiaoya_config_dir}" == "$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)" ]; then
                INFO "小雅容器挂载目录与当前保存的小雅配置目录路径一致"
                INFO "小雅配置目录通过小雅容器获取"
            else
                WARN "小雅容器挂载目录与当前保存的小雅配置目录路径不一致"
                WARN "默认使用当前保存的小雅配置目录路径"
            fi
            xiaoya_config_dir=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
            if [ -z "${xiaoya_config_dir}" ]; then
                WARN "读取小雅Alist配置文件路径错误，请重新输入你的小雅Alist配置文件路径"
            else
                INFO "已读取小雅Alist配置文件路径：${xiaoya_config_dir} (默认不更改回车继续，如果需要更改请输入新路径)"
            fi
            read -erp "CONFIG_DIR:" CONFIG_DIR
            [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${xiaoya_config_dir}
        elif [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
            if [ -z "${OLD_CONFIG_DIR}" ]; then
                WARN "读取小雅Alist配置文件路径错误，请重新输入你的小雅Alist配置文件路径"
            else
                INFO "已读取小雅Alist配置文件路径：${OLD_CONFIG_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
            fi
            read -erp "CONFIG_DIR:" CONFIG_DIR
            [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${OLD_CONFIG_DIR}
        else
            DEFAULT_CONFIG_DIR="$(get_path "xiaoya_alist_config_dir")"
            INFO "请输入配置文件目录（默认 ${DEFAULT_CONFIG_DIR} ）"
            read -erp "CONFIG_DIR:" CONFIG_DIR
            [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR="${DEFAULT_CONFIG_DIR}"
            touch "${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt"
        fi
        if check_path "${CONFIG_DIR}"; then
            echo "${CONFIG_DIR}" > "${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt"
            INFO "目录合法性检测通过！"
            break
        else
            ERROR "非合法目录，请重新输入！"
        fi
    done
    if [ -d "${CONFIG_DIR}" ]; then
        INFO "读取配置目录中..."
        # 将所有小雅配置文件修正成 linux 格式
        if [[ "${OSNAME}" = "macos" ]]; then
            find ${CONFIG_DIR} -maxdepth 1 -type f -name "*.txt" -exec sed -i '' "s/\r$//g" {} \;
        else
            find ${CONFIG_DIR} -maxdepth 1 -type f -name "*.txt" -exec sed -i "s/\r$//g" {} \;
        fi
        # 设置权限
        find ${CONFIG_DIR} -maxdepth 1 -type f -exec chmod 777 {} \;
        if [ -n "${GLOBAL_PUID}" ] && [ -n "${GLOBAL_PGID}" ]; then
            find ${CONFIG_DIR} -maxdepth 1 -type f -exec chown "${GLOBAL_PUID}":"${GLOBAL_PGID}" {} \;
        fi
    fi

}

function get_media_dir() {

    local media_dir DEFAULT_MEDIA_DIR

    if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
        XIAOYA_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
        if [ -s "${XIAOYA_CONFIG_DIR}/emby_config.txt" ]; then
            # shellcheck disable=SC1091
            source "${XIAOYA_CONFIG_DIR}/emby_config.txt"
            # shellcheck disable=SC2154
            echo "${media_dir}" > ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt
            INFO "媒体库目录通过 emby_config.txt 获取"
        fi
    fi

    while true; do
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt ]; then
            OLD_MEDIA_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt)
            INFO "已读取媒体库目录：${OLD_MEDIA_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
            read -erp "MEDIA_DIR:" MEDIA_DIR
            [[ -z "${MEDIA_DIR}" ]] && MEDIA_DIR=${OLD_MEDIA_DIR}
        else
            DEFAULT_MEDIA_DIR="$(get_path "xiaoya_alist_media_dir")"
            INFO "请输入媒体库目录（默认 ${DEFAULT_MEDIA_DIR} ）"
            read -erp "MEDIA_DIR:" MEDIA_DIR
            [[ -z "${MEDIA_DIR}" ]] && MEDIA_DIR="${DEFAULT_MEDIA_DIR}"
            touch "${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt"
        fi
        if check_path "${MEDIA_DIR}"; then
            echo "${MEDIA_DIR}" > "${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt"
            INFO "目录合法性检测通过！"
            break
        else
            ERROR "非合法目录，请重新输入！"
        fi
    done

}

function main_account_management() {

    function main_account_management_level_two() {

        echo -e "——————————————————————————————————————————————————————————————————————————————————"
        echo -e "${Blue}${1}${Font}\n"
        echo -e "1、配置/更新"
        echo -e "2、删除"
        echo -e "0、返回上级"
        echo -e "——————————————————————————————————————————————————————————————————————————————————"
        read -erp "请输入数字 [0-2]:" num
        case "$num" in
        1)
            clear
            "${2}" "${3}" force
            main_account_management
            ;;
        2)
            clear
            "${2}" "${3}" remove
            main_account_management
            ;;
        0)
            clear
            main_account_management
            ;;
        *)
            clear
            ERROR '请输入正确数字 [0-2]'
            main_account_management_level_two "$@"
            ;;
        esac

    }

    clear

    local config_dir
    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
    fi
    if [ -z "${config_dir}" ]; then
        get_config_dir
        config_dir=${CONFIG_DIR}
    fi

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}账号管理${Font}\n"
    echo -e "${Sky_Blue}小雅留言，会员购买指南：
基础版：阿里非会员+115会员+夸克88vip
升级版：阿里svip+115会员+夸克88vip（用TV token破解阿里svip的高速流量限制）
豪华版：阿里svip+第三方权益包+115会员+夸克svip
乞丐版：满足看emby画报但不要播放，播放用tvbox各种免费源${Font}\n"
    echo -ne "${INFO} 界面加载中...${Font}\r"
    echo -e "1、115 Cookie                        （当前：$(if [ -f "${config_dir}/115_cookie.txt" ]; then if CHECK_OUT=$(check_115_cookie "${config_dir}"); then echo -e "${Green}$(echo -e ${CHECK_OUT} | sed 's/\[.*\] //')${Font}"; else echo -e "${Red}错误${Font}"; fi; else echo -e "${Red}未配置${Font}"; fi)）
2、夸克 Cookie                       （当前：$(if [ -f "${config_dir}/quark_cookie.txt" ]; then if CHECK_OUT=$(check_quark_cookie "${config_dir}"); then echo -e "${Green}$(echo -e ${CHECK_OUT} | sed 's/\[.*\] //')${Font}"; else echo -e "${Red}错误${Font}"; fi; else echo -e "${Red}未配置${Font}"; fi)）
3、阿里云盘 Refresh Token（mytoken） （当前：$(if [ -f "${config_dir}/mytoken.txt" ]; then if CHECK_OUT=$(check_aliyunpan_refreshtoken "${config_dir}"); then echo -e "${Green}$(echo -e ${CHECK_OUT} | sed 's/\[.*\] //')${Font}"; else echo -e "${Red}错误${Font}"; fi; else echo -e "${Red}未配置${Font}"; fi)）
4、阿里云盘 Open Token（myopentoken）（当前：$(if [ -f "${config_dir}/myopentoken.txt" ]; then if [ -f "${config_dir}/open_tv_token_url.txt" ]; then if CHECK_OUT=$(check_aliyunpan_tvtoken "${config_dir}"); then echo -e "${Green}$(echo -e ${CHECK_OUT} | sed 's/\[.*\] //')${Font}"; else echo -e "${Red}阿里云盘 TV Token 已失效${Font}"; fi; elif CHECK_OUT=$(check_aliyunpan_opentoken "${config_dir}"); then echo -e "${Green}$(echo -e ${CHECK_OUT} | sed 's/\[.*\] //')${Font}"; else echo -e "${Red}阿里云盘 Open Token 已失效${Font}"; fi; else echo -e "${Red}未配置${Font}"; fi)）
5、UC Cookie                         （当前：$(if [ -f "${config_dir}/uc_cookie.txt" ]; then if CHECK_OUT=$(check_uc_cookie "${config_dir}"); then echo -e "${Green}$(echo -e ${CHECK_OUT} | sed 's/\[.*\] //')${Font}"; else echo -e "${Red}错误${Font}"; fi; else echo -e "${Red}未配置${Font}"; fi)）
6、PikPak                            （当前：$(if [ -f "${config_dir}/pikpak.txt" ]; then echo -e "${Green}已配置${Font}"; else echo -e "${Red}未配置${Font}"; fi)）
7、阿里转存115播放（ali2115.txt）    （当前：$(if [ -f "${config_dir}/ali2115.txt" ]; then echo -e "${Green}已配置${Font}"; else echo -e "${Red}未配置${Font}"; fi)）"
    echo -e "8、应用配置（自动重启小雅，并返回上级菜单）"
    echo -e "0、返回上级（从此处退出不会重启小雅，如果更改了上述配置请手动重启）"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-8]:" num
    case "$num" in
    1)
        clear
        main_account_management_level_two "115 Cookie" settings_115_cookie "${config_dir}"
        ;;
    2)
        clear
        main_account_management_level_two "夸克 Cookie" settings_quark_cookie "${config_dir}"
        ;;
    3)
        clear
        main_account_management_level_two "阿里云盘 Refresh Token（mytoken）" settings_aliyunpan_refreshtoken "${config_dir}"
        ;;
    4)
        clear
        main_account_management_level_two "阿里云盘 Open Token（myopentoken）" settings_aliyunpan_opentoken "${config_dir}"
        ;;
    5)
        clear
        main_account_management_level_two "UC Cookie" settings_uc_cookie "${config_dir}"
        ;;
    6)
        clear
        main_account_management_level_two "PikPak" settings_pikpak_account "${config_dir}"
        ;;
    7)
        clear
        main_account_management_level_two "阿里转存115播放（ali2115.txt）" settings_ali2115 "${config_dir}"
        ;;
    8)
        clear
        if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
            INFO "重启小雅容器中..."
            docker restart "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
            wait_xiaoya_start
        else
            WARN "您未安装小雅，请先安装小雅容器！"
        fi
        if docker container inspect xiaoya-115cleaner > /dev/null 2>&1; then
            docker restart xiaoya-115cleaner
        fi
        INFO "配置保存完成，按任意键返回菜单！"
        read -rs -n 1 -p ""
        clear
        main_xiaoya_alist
        ;;
    0)
        clear
        main_xiaoya_alist
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-8]'
        main_account_management
        ;;
    esac

}

function install_xiaoya_alist() {

    if [ ! -d "${CONFIG_DIR}" ]; then
        mkdir -p "${CONFIG_DIR}"
        auto_chown "${CONFIG_DIR}"
    else
        if [ -d "${CONFIG_DIR}"/mytoken.txt ]; then
            rm -rf "${CONFIG_DIR}"/mytoken.txt
        fi
    fi

    if [ ! -d "${CONFIG_DIR}/data" ]; then
        mkdir -p "${CONFIG_DIR}/data"
        auto_chown "${CONFIG_DIR}/data"
    fi

    files=("mytoken.txt" "myopentoken.txt" "temp_transfer_folder_id.txt")
    for file in "${files[@]}"; do
        if [ ! -f "${CONFIG_DIR}/${file}" ]; then
            touch_chmod "${CONFIG_DIR}/${file}"
        fi
    done

    settings_aliyunpan_refreshtoken "${CONFIG_DIR}"

    if [ -f "${CONFIG_DIR}/open_tv_token_url.txt" ]; then
        check_aliyunpan_tvtoken "${CONFIG_DIR}"
    else
        settings_aliyunpan_opentoken "${CONFIG_DIR}"
    fi

    settings_aliyunpan_folder_id "${CONFIG_DIR}"

    settings_pikpak_account "${CONFIG_DIR}"

    if [ -f "${CONFIG_DIR}/pikpak.txt" ] && [ ! -f "${CONFIG_DIR}/pikpakshare_list.txt" ] && command -v base64 > /dev/null 2>&1; then
        while true; do
            INFO "是否使用小雅官方分享的 pikpakshare_list.txt 文件 [Y/n]（默认 y）"
            read -erp "pikpakshare_list_choose:" pikpakshare_list_choose
            [[ -z "${pikpakshare_list_choose}" ]] && pikpakshare_list_choose="y"
            if [[ ${pikpakshare_list_choose} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${pikpakshare_list_choose} == [Yy] ]]; then
            echo "${pikpakshare_list_base64}" | base64 --decode > "${CONFIG_DIR}/pikpakshare_list.txt"
            auto_chown "${CONFIG_DIR}/pikpakshare_list.txt"
        fi
    fi

    settings_quark_cookie "${CONFIG_DIR}"

    if [ -f "${CONFIG_DIR}/quark_cookie.txt" ] && [ ! -f "${CONFIG_DIR}/quarkshare_list.txt" ] && command -v base64 > /dev/null 2>&1; then
        while true; do
            INFO "是否使用小雅官方分享的 quarkshare_list.txt 文件 [Y/n]（默认 y）"
            read -erp "quarkshare_list_choose:" quarkshare_list_choose
            [[ -z "${quarkshare_list_choose}" ]] && quarkshare_list_choose="y"
            if [[ ${quarkshare_list_choose} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${quarkshare_list_choose} == [Yy] ]]; then
            echo "${quarkshare_list_base64}" | base64 --decode > "${CONFIG_DIR}/quarkshare_list.txt"
            auto_chown "${CONFIG_DIR}/quarkshare_list.txt"
        fi
    fi

    settings_uc_cookie "${CONFIG_DIR}"

    settings_115_cookie "${CONFIG_DIR}"

    if [ -f "${CONFIG_DIR}/115_cookie.txt" ] && [ ! -f "${CONFIG_DIR}/115share_list.txt" ] && command -v base64 > /dev/null 2>&1; then
        while true; do
            INFO "是否使用小雅官方分享的 115share_list.txt 文件 [Y/n]（默认 y）"
            read -erp "pan115share_list_choose:" pan115share_list_choose
            [[ -z "${pan115share_list_choose}" ]] && pan115share_list_choose="y"
            if [[ ${pan115share_list_choose} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${pan115share_list_choose} == [Yy] ]]; then
            echo "${pan115share_list_base64}" | base64 --decode > "${CONFIG_DIR}/115share_list.txt"
            auto_chown "${CONFIG_DIR}/115share_list.txt"
        fi
    fi

    settings_ali2115 "${CONFIG_DIR}"

    if [[ "${OSNAME}" = "macos" ]]; then
        localip=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
    else
        if command -v ifconfig > /dev/null 2>&1; then
            localip=$(ifconfig -a | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1)
        else
            localip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
        fi
    fi
    INFO "本地IP：${localip}"

    ports=(5678 2345 2346 2347)
    for port in "${ports[@]}"; do
        if ! check_port "${port}"; then
            check_ports_result=false
        fi
    done
    if [ "${check_ports_result}" == false ]; then
        exit 1
    fi

    if [ "${SET_NET_MODE}" == true ]; then
        while true; do
            INFO "是否使用host网络模式 [Y/n]（默认 n 不使用）"
            read -erp "NET_MODE:" NET_MODE
            [[ -z "${NET_MODE}" ]] && NET_MODE="n"
            if [[ ${NET_MODE} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
    fi
    if [ ! -s "${CONFIG_DIR}"/docker_address.txt ]; then
        echo "http://$localip:5678" > "${CONFIG_DIR}"/docker_address.txt
        auto_chown "${CONFIG_DIR}/docker_address.txt"
    fi
    docker_command=("docker run" "-itd" "--privileged")
    if [[ ${NET_MODE} == [Yy] ]]; then
        docker_image="xiaoyaliu/alist:hostmode"
        docker_command+=("--network=host")
    else
        docker_image="xiaoyaliu/alist:latest"
        docker_command+=("-p 5678:80" "-p 2345:2345" "-p 2346:2346" "-p 2347:2347")
    fi
    if [[ -f ${CONFIG_DIR}/proxy.txt ]] && [[ -s ${CONFIG_DIR}/proxy.txt ]]; then
        proxy_url=$(head -n1 "${CONFIG_DIR}"/proxy.txt)
        docker_command+=("--env HTTP_PROXY=$proxy_url" "--env HTTPS_PROXY=$proxy_url" "--env no_proxy=*.aliyundrive.com")
    fi
    docker_command+=("-v ${CONFIG_DIR}:/data" "-v ${CONFIG_DIR}/data:/www/data" "--restart=always" "--name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" "$docker_image")
    docker_pull "$docker_image"
    if eval "${docker_command[*]}"; then
        wait_xiaoya_start
        INFO "安装完成！"
        INFO "服务已成功启动，您可以根据使用需求尝试访问以下的地址："
        INFO "alist: ${Sky_Blue}http://ip:5678${Font}"
        INFO "webdav: ${Sky_Blue}http://ip:5678/dav${Font}, 默认用户密码: ${Sky_Blue}guest/guest_Api789${Font}"
        INFO "tvbox: ${Sky_Blue}http://ip:5678/tvbox/my_ext.json${Font}"
    else
        ERROR "安装失败！"
    fi

}

function update_xiaoya_alist() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新小雅Alist${Blue} $i ${Font}\r"
        sleep 1
    done
    cat > "/tmp/container_update_xiaoya_alist_run.sh" <<- EOF
#!/bin/bash
if ! grep -q 'network=host' "/tmp/container_update_$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"; then
    if ! grep -q '2347' "/tmp/container_update_$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"; then
        sed -i '2s/^/-p 2347:2347 /' "/tmp/container_update_$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    fi
fi
if ! grep -q 'privileged' "/tmp/container_update_$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"; then
    sed -i '2s/^/--privileged /' "/tmp/container_update_$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
fi
EOF
    container_update_extra_command="bash /tmp/container_update_xiaoya_alist_run.sh"
    container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    rm -f /tmp/container_update_xiaoya_alist_run.sh

}

function uninstall_xiaoya_alist() {

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
        echo -en "即将开始卸载小雅Alist${Blue} $i ${Font}\r"
        sleep 1
    done
    IMAGE_NAME="$(docker inspect --format='{{.Config.Image}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)")"
    VOLUMES="$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{println .}}{{end}}{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | cut -d' ' -f2 | awk 'NF' | tr '\n' ' ')"
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    docker rmi "${IMAGE_NAME}"
    docker volume rm ${VOLUMES}
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
            for file in "${OLD_CONFIG_DIR}/mycheckintoken.txt" "${OLD_CONFIG_DIR}/mycmd.txt" "${OLD_CONFIG_DIR}/myruntime.txt"; do
                if [ -f "$file" ]; then
                    mv -f "$file" "/tmp/$(basename "$file")"
                fi
            done
            rm -rf \
                ${OLD_CONFIG_DIR}/*.txt* \
                ${OLD_CONFIG_DIR}/*.m3u* \
                ${OLD_CONFIG_DIR}/*.m3u8*
            if [ -d "${OLD_CONFIG_DIR}/xiaoya_backup" ]; then
                rm -rf ${OLD_CONFIG_DIR}/xiaoya_backup
            fi
            for file in /tmp/mycheckintoken.txt /tmp/mycmd.txt /tmp/myruntime.txt; do
                if [ -f "$file" ]; then
                    mv -f "$file" "${OLD_CONFIG_DIR}/$(basename "$file")"
                fi
            done
        fi
    fi
    INFO "小雅Alist卸载成功！"
}

function judgment_xiaoya_alist_sync_data_status() {

    if command -v crontab > /dev/null 2>&1; then
        if crontab -l | grep 'xiaoya_data_downloader' > /dev/null 2>&1; then
            echo -e "${Green}已创建${Font}"
        else
            echo -e "${Red}未创建${Font}"
        fi
    elif [ -f /etc/synoinfo.conf ]; then
        if grep 'xiaoya_data_downloader' /etc/crontab > /dev/null 2>&1; then
            echo -e "${Green}已创建${Font}"
        else
            echo -e "${Red}未创建${Font}"
        fi
    else
        echo -e "${Red}未知${Font}"
    fi

}

function show_xiaoya_non_intranet_ip() {

    local output
    output=
    if ! docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        ERROR "小雅容器未安装，无法查看！"
    else
        if [ "$(docker inspect --format='{{.State.Status}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)")" != "running" ]; then
            ERROR "小雅容器未启动，无法查看！"
        else
            if ! docker exec -it "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" cat /opt/alist/log/alist.log > /dev/null 2>&1; then
                INFO "无非内网IP访问次数记录"
            else
                output="$(docker exec -it "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" bash -c 'cat /opt/alist/log/alist.log | grep -v -i fail | grep -o "([0-9]{1,3}\\.){3}[0-9]{1,3}" | grep -v "172\\.17|127\\.0|192\\.168" | sort | uniq -c | head -n10 | sed "s/^[ \t]*//"')"
                if [ -n "${output}" ]; then
                    INFO "非内网IP访问次数情况："
                    echo -e "${output}"
                else
                    INFO "无非内网IP访问次数记录"
                fi
            fi
        fi
    fi

}

function uninstall_xiaoya_alist_sync_data() {

    if command -v crontab > /dev/null 2>&1; then
        crontab -l > /tmp/cronjob.tmp
        sedsh '/xiaoya_data_downloader/d' /tmp/cronjob.tmp
        crontab /tmp/cronjob.tmp
        rm -f /tmp/cronjob.tmp
    elif [ -f /etc/synoinfo.conf ]; then
        sedsh '/xiaoya_data_downloader/d' /etc/crontab
    fi

}

function main_xiaoya_alist() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Alist${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "4、账号管理"
    echo -e "5、非内网IP访问次数查看"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-5]:" num
    case "$num" in
    1)
        clear
        get_config_dir
        SET_NET_MODE=true
        install_xiaoya_alist
        return_menu "main_xiaoya_alist"
        ;;
    2)
        clear
        update_xiaoya_alist
        return_menu "main_xiaoya_alist"
        ;;
    3)
        clear
        uninstall_xiaoya_alist
        return_menu "main_xiaoya_alist"
        ;;
    4)
        clear
        main_account_management
        ;;
    5)
        clear
        show_xiaoya_non_intranet_ip
        INFO "按任意键返回菜单"
        read -rs -n 1 -p ""
        clear
        main_xiaoya_alist
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-5]'
        main_xiaoya_alist
        ;;
    esac

}

function get_docker0_url() {

    if command -v ifconfig > /dev/null 2>&1; then
        docker0=$(ifconfig docker0 | awk '/inet / {print $2}' | sed 's/addr://')
    else
        docker0=$(ip addr show docker0 | awk '/inet / {print $2}' | cut -d '/' -f 1)
    fi

    if [ -n "$docker0" ]; then
        INFO "docker0 的 IP 地址是：$docker0"
    else
        WARN "无法获取 docker0 的 IP 地址！"
        if [[ "${OSNAME}" = "macos" ]]; then
            docker0=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
        else
            docker0=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
        fi
        INFO "尝试使用本地IP：${docker0}"
    fi

}

function test_xiaoya_status() {

    get_docker0_url

    INFO "测试xiaoya的联通性..."
    if curl -siL -m 10 http://127.0.0.1:5678/d/README.md | grep -e "x-oss-" -e "x-115-request-id"; then
        xiaoya_addr="http://127.0.0.1:5678"
    elif curl -siL -m 10 http://${docker0}:5678/d/README.md | grep -e "x-oss-" -e "x-115-request-id"; then
        xiaoya_addr="http://${docker0}:5678"
    else
        if [ -s ${CONFIG_DIR}/docker_address.txt ]; then
            docker_address=$(head -n1 ${CONFIG_DIR}/docker_address.txt)
            if curl -siL -m 10 ${docker_address}/d/README.md | grep -e "x-oss-" -e "x-115-request-id"; then
                xiaoya_addr=${docker_address}
            else
                __xiaoya_connectivity_detection=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt)
                if [ "${__xiaoya_connectivity_detection}" == "false" ]; then
                    xiaoya_addr=${docker_address}
                    WARN "您已设置跳过小雅连通性检测"
                else
                    ERROR "请检查xiaoya是否正常运行后再试"
                    ERROR "小雅日志如下："
                    docker logs --tail 8 "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
                    exit 1
                fi
            fi
        else
            ERROR "请先配置 ${CONFIG_DIR}/docker_address.txt 后重试"
            exit 1
        fi
    fi

    INFO "连接小雅地址为 ${xiaoya_addr}"

}

function test_disk_capacity() {

    if [ ! -d "${MEDIA_DIR}" ]; then
        mkdir -p "${MEDIA_DIR}"
        auto_chown "${MEDIA_DIR}"
    fi

    free_size=$(df -P "${MEDIA_DIR}" | tail -n1 | awk '{print $4}')
    free_size=$((free_size))
    free_size_G=$((free_size / 1024 / 1024))

    __disk_capacity_detection=$(cat ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt)
    if [ "${__disk_capacity_detection}" == "false" ]; then
        WARN "您已设置跳过磁盘容量检测"
        INFO "磁盘容量：${free_size_G}G"
    else
        if [ "$free_size" -le 193986560 ]; then
            ERROR "空间剩余容量不够：${free_size_G}G 小于最低要求 185G"
            exit 1
        else
            INFO "磁盘容量：${free_size_G}G"
        fi
    fi

}

function show_disk_capacity() {

    free_size=$(df -P "${1}" | tail -n1 | awk '{print $4}')
    free_size=$((free_size))
    free_size_G=$((free_size / 1024 / 1024))
    INFO "磁盘容量：${free_size_G}G"

}

function pull_run_glue() {

    if docker inspect xiaoyaliu/glue:latest > /dev/null 2>&1; then
        local_sha=$(docker inspect --format='{{index .RepoDigests 0}}' xiaoyaliu/glue:latest 2> /dev/null | cut -f2 -d:)
        remote_sha=$(curl -s -m 10 "https://hub.docker.com/v2/repositories/xiaoyaliu/glue/tags/latest" | grep -o '"digest":"[^"]*' | grep -o '[^"]*$' | tail -n1 | cut -f2 -d:)
        if [ "$local_sha" != "$remote_sha" ]; then
            docker rmi xiaoyaliu/glue:latest
            docker_pull "xiaoyaliu/glue:latest"
        fi
    else
        docker_pull "xiaoyaliu/glue:latest"
    fi

    if [ -n "${extra_parameters}" ]; then
        # shellcheck disable=SC2046
        docker run -it \
            --security-opt seccomp=unconfined \
            --rm \
            --net=host \
            -v "${MEDIA_DIR}:/media" \
            -v "${CONFIG_DIR}:/etc/xiaoya" \
            ${extra_parameters} \
            $(auto_privileged) \
            -e LANG=C.UTF-8 \
            -e TZ=Asia/Shanghai \
            xiaoyaliu/glue:latest \
            "${@}"
    else
        # shellcheck disable=SC2046
        docker run -it \
            --security-opt seccomp=unconfined \
            --rm \
            --net=host \
            -v "${MEDIA_DIR}:/media" \
            -v "${CONFIG_DIR}:/etc/xiaoya" \
            $(auto_privileged) \
            -e LANG=C.UTF-8 \
            -e TZ=Asia/Shanghai \
            xiaoyaliu/glue:latest \
            "${@}"
    fi

}

function pull_run_glue_xh() {

    BUILDER_NAME="xiaoya_builder_$(date +%S%N | cut -c 7-11)"

    if docker inspect xiaoyaliu/glue:latest > /dev/null 2>&1; then
        local_sha=$(docker inspect --format='{{index .RepoDigests 0}}' xiaoyaliu/glue:latest 2> /dev/null | cut -f2 -d:)
        remote_sha=$(curl -s -m 10 "https://hub.docker.com/v2/repositories/xiaoyaliu/glue/tags/latest" | grep -o '"digest":"[^"]*' | grep -o '[^"]*$' | tail -n1 | cut -f2 -d:)
        if [ "$local_sha" != "$remote_sha" ]; then
            docker rmi xiaoyaliu/glue:latest
            docker_pull "xiaoyaliu/glue:latest"
        fi
    else
        docker_pull "xiaoyaliu/glue:latest"
    fi

    if [ -n "${extra_parameters}" ]; then
        # shellcheck disable=SC2046
        docker run -itd \
            --security-opt seccomp=unconfined \
            --name=${BUILDER_NAME} \
            --net=host \
            -v "${MEDIA_DIR}:/media" \
            -v "${CONFIG_DIR}:/etc/xiaoya" \
            $(auto_privileged) \
            ${extra_parameters} \
            -e LANG=C.UTF-8 \
            xiaoyaliu/glue:latest \
            "${@}" > /dev/null 2>&1
    else
        # shellcheck disable=SC2046
        docker run -itd \
            --security-opt seccomp=unconfined \
            --name=${BUILDER_NAME} \
            --net=host \
            -v "${MEDIA_DIR}:/media" \
            -v "${CONFIG_DIR}:/etc/xiaoya" \
            $(auto_privileged) \
            -e LANG=C.UTF-8 \
            xiaoyaliu/glue:latest \
            "${@}" > /dev/null 2>&1
    fi

    timeout=20
    start_time=$(date +%s)
    end_time=$((start_time + timeout))
    while [ "$(date +%s)" -lt $end_time ]; do
        status=$(docker inspect -f '{{.State.Status}}' "${BUILDER_NAME}")
        if [ "$status" = "exited" ]; then
            break
        fi
        sleep 1
    done

    status=$(docker inspect -f '{{.State.Status}}' "${BUILDER_NAME}")
    if [ "$status" != "exited" ]; then
        docker kill ${BUILDER_NAME} > /dev/null 2>&1
    fi
    docker rm ${BUILDER_NAME} > /dev/null 2>&1

}

function get_emby_version() {

    local emby_name emby_image_name emby_config_dir CURRENT_ULIMIT
    emby_name=$(cat "${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt")
    if ! docker container inspect "${emby_name}" > /dev/null 2>&1; then
        WARN "未检测到 Emby 容器，请确保您已安装 Emby！"
        return 1
    fi
    emby_image_name="$(docker container inspect -f '{{.Config.Image}}' "${emby_name}")"
    if [ -z "${emby_image_name}" ]; then
        WARN "获取 Emby 镜像标签失败"
        return 1
    fi
    emby_config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "${emby_name}" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/config$" | awk -F: '{print $1}')"
    if [ -z "${emby_config_dir}" ] || ! check_path "${emby_config_dir}"; then
        WARN "Emby 配置目录获取失败，使用 /tmp 目录替代！"
        emby_config_dir=/tmp
    fi
    if [ -f "${emby_config_dir}/EmbyServer.deps.json" ]; then
        rm -f "${emby_config_dir}/EmbyServer.deps.json"
    fi
    CURRENT_ULIMIT=$(ulimit -n)
    ulimit -n 65535
    docker run --rm --ulimit nofile=65535:65535 --entrypoint cp -v "${emby_config_dir}:/data" "${emby_image_name}" /system/EmbyServer.deps.json /data
    ulimit -n "${CURRENT_ULIMIT}"
    if [ ! -f "${emby_config_dir}/EmbyServer.deps.json" ]; then
        WARN "Emby 版本数据文件复制失败！"
        return 1
    fi
    emby_version=$(grep "EmbyServer" "${emby_config_dir}/EmbyServer.deps.json" | head -n 1 | sed -n 's|.*EmbyServer/\(.*\)":.*|\1|p')
    rm -f "${emby_config_dir}/EmbyServer.deps.json"
    if [ -z "${emby_version}" ]; then
        WARN "当前 Emby 版本获取失败！"
        return 1
    fi
    return 0

}

function set_emby_server() {

    get_docker0_url
    if [[ "${OSNAME}" = "macos" ]]; then
        local_ip=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
    else
        local_ip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
    fi

    if docker exec -i "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" curl -I -s "http://127.0.0.1:6908" | grep -m1 "^HTTP/" | grep -q "302"; then
        INFO "使用 127.0.0.1 IP 配置 emby_server.txt"
        echo "http://127.0.0.1:6908" > "${CONFIG_DIR}"/emby_server.txt
    elif docker exec -i "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" curl -I -s "http://$docker0:6908" | grep -m1 "^HTTP/" | grep -q "302"; then
        INFO "使用 $docker0 IP 配置 emby_server.txt"
        echo "http://$docker0:6908" > "${CONFIG_DIR}"/emby_server.txt
    else
        INFO "使用 $local_ip IP 配置 emby_server.txt"
        echo "http://$local_ip:6908" > "${CONFIG_DIR}"/emby_server.txt
    fi

    auto_chown "${CONFIG_DIR}/emby_server.txt"

}

function check_metadata_size() {

    function simple_check_metadata_size() {

        case "${1}" in
        config.mp4)
            if [[ "$2" -le 3200000 ]]; then
                return 1
            fi
            ;;
        all.mp4)
            if [[ "$2" -le 30000000 ]]; then
                return 1
            fi
            ;;
        pikpak.mp4)
            if [[ "$2" -le 14000000 ]]; then
                return 1
            fi
            ;;
        115.mp4)
            if [[ "$2" -le 16000000 ]]; then
                return 1
            fi
            ;;
        蓝光原盘.mp4)
            if [[ "$2" -le 4200000 ]]; then
                return 1
            fi
            ;;
        config.new.mp4)
            if [[ "$2" -le 3200000 ]]; then
                return 1
            fi
            ;;
        esac

    }

    local file_size file_size_b remote_metadata_size check_result

    if [ -z "${xiaoya_addr}" ]; then
        test_xiaoya_status
    fi
    pull_run_glue_xh xh --headers --follow --timeout=10 -o /media/headers.log "${xiaoya_addr}/d/元数据/${1}" "User-Agent: ${GLOBAL_UA}"
    remote_metadata_size=$(grep 'Content-Length' "${MEDIA_DIR}/headers.log" | awk '{print $2}')
    rm -f "${MEDIA_DIR}/headers.log"

    pull_run_glue bash -c "du -k /media/temp/${1} | cut -f1 > /media/size.txt"
    if [ ! -f "${MEDIA_DIR}/size.txt" ]; then
        ERROR "获取元数据文件本地大小失败（单位k）"
        return 1
    fi
    file_size=$(head -n 1 "${MEDIA_DIR}/size.txt")
    rm -f "${MEDIA_DIR}/size.txt"

    if [ -n "${remote_metadata_size}" ] &&
        awk -v remote="${remote_metadata_size}" -v threshold="2147483648" 'BEGIN { if (remote > threshold) print "1"; else print "0"; }' | grep -q "1"; then
        INFO "精准校验文件大小模式"

        pull_run_glue bash -c "du -b /media/temp/${1} | cut -f1 > /media/size.txt"
        if [ ! -f "${MEDIA_DIR}/size.txt" ]; then
            WARN "获取元数据文件本地大小失败（单位b）"
            if ! simple_check_metadata_size "${1}" "${file_size}"; then
                check_result=false
            fi
        else
            file_size_b=$(head -n 1 "${MEDIA_DIR}/size.txt")
            rm -f "${MEDIA_DIR}/size.txt"

            INFO "${1} REMOTE_METADATA_SIZE: ${remote_metadata_size}"
            INFO "${1} LOCAL_METADATA_SIZE: ${file_size_b}"

            if [ "${remote_metadata_size}" != "${file_size_b}" ]; then
                check_result=false
            fi
        fi
    else
        if ! simple_check_metadata_size "${1}" "${file_size}"; then
            check_result=false
        fi
    fi

    if [ "${check_result}" == false ]; then
        ERROR "${1} 下载不完整，文件大小(in KB):$file_size 小于预期"
        return 1
    fi
    INFO "${1} 文件大小验证正常，文件大小(in KB):$file_size"
    return 0

}

function __unzip_metadata() {

    function metadata_unziper() {

        if ! check_metadata_size "${1}"; then
            exit 1
        fi
        if [[ "${OSNAME}" = "macos" ]] || [[ "$(cat "${DDSREM_CONFIG_DIR}/use_host_7z_command.txt")" == "true" ]]; then
            INFO "使用宿主机 7z 命令解压"
            if [ "${1}" == "config.mp4" ] || [ "${1}" == "config.new.mp4" ]; then
                if [ ! -d "${MEDIA_DIR}" ]; then
                    mkdir -p "${MEDIA_DIR}"
                    auto_chown "${MEDIA_DIR}"
                    chmod 777 "${MEDIA_DIR}"
                fi
                cd "${MEDIA_DIR}" || return 1
            else
                if [ ! -d "${MEDIA_DIR}/xiaoya" ]; then
                    mkdir -p "${MEDIA_DIR}/xiaoya"
                    auto_chown "${MEDIA_DIR}/xiaoya"
                    chmod 777 "${MEDIA_DIR}/xiaoya"
                fi
                cd "${MEDIA_DIR}/xiaoya" || return 1
            fi
            INFO "当前解压工作目录：$(pwd)"
            if ! 7z x -aoa -mmt=16 "${MEDIA_DIR}/temp/${1}"; then
                if ! 7z x -aoa -mmt=16 -bb3 "${MEDIA_DIR}/temp/${1}"; then
                    __unzip_metadata_debug "${1}"
                fi
            fi
        else
            if [ "${1}" == "config.mp4" ] || [ "${1}" == "config.new.mp4" ]; then
                extra_parameters="--workdir=/media"
            else
                extra_parameters="--workdir=/media/xiaoya"
            fi
            if ! pull_run_glue 7z x -aoa -mmt=16 "/media/temp/${1}"; then
                if ! pull_run_glue 7z x -aoa -mmt=16 -bb3 "/media/temp/${1}"; then
                    __unzip_metadata_debug "${1}"
                fi
            fi
        fi

        if [ "$(cat "${DDSREM_CONFIG_DIR}/auto_clean_metadata_mp4_file.txt")" == "true" ]; then
            INFO "自动清理 ${1} 文件中..."
            rm -f "${MEDIA_DIR}/temp/${1}"
        fi

    }

    start_time1=$(date +%s)

    if [ "${1}" == "all_metadata" ]; then
        for file in "${ALL_METADATA_FILES[@]}"; do
            metadata_unziper "${file}"
        done
        INFO "设置目录权限..."
        INFO "这可能需要一定时间，请耐心等待！"
        chmod -R 777 "${MEDIA_DIR}"
    elif [ "${1}" == "config.mp4" ] || [ "${1}" == "config.new.mp4" ]; then
        metadata_unziper "${1}"
        emby_fix_strmassistant "${MEDIA_DIR}/config"
        INFO "设置目录权限..."
        INFO "这可能需要一定时间，请耐心等待！"
        chmod -R 777 "${MEDIA_DIR}"/config
    else
        metadata_unziper "${1}"
        INFO "设置目录权限..."
        chmod 777 "${MEDIA_DIR}"/xiaoya
    fi

    end_time1=$(date +%s)
    total_time1=$((end_time1 - start_time1))
    total_time1=$((total_time1 / 60))
    INFO "解压执行时间：$total_time1 分钟"

}

function __download_metadata() {

    function metadata_downloader() {

        local __data_downloader

        INFO "开始下载 ${1} ..."
        INFO "下载路径：${MEDIA_DIR}/temp/${1}"

        __data_downloader=$(cat "${DDSREM_CONFIG_DIR}/data_downloader.txt")

        INFO "使用下载器：${__data_downloader}"

        extra_parameters="--workdir=/media/temp"

        if [ "${__data_downloader}" == "wget" ]; then
            # wget 下载模式下只能单线程下载
            if ! pull_run_glue wget -c --show-progress "${xiaoya_addr}/d/元数据/${1}" -U "${GLOBAL_UA}"; then
                DEBUG "${OSNAME} $(uname -a)"
                ERROR "${1} 下载失败！"
                exit 1
            fi
        else
            local download_threads
            pull_run_glue_xh xh --headers --follow --timeout=10 -o /media/headers.log "${xiaoya_addr}/d/元数据/${1}" "User-Agent: ${GLOBAL_UA}"
            if [ -f "${MEDIA_DIR}/headers.log" ]; then
                # 115网盘下载链接：返回为 X-115-Request-Id，并且存在 ali2115.txt 文件
                if grep "X-115-Request-Id" "${MEDIA_DIR}/headers.log" && [ -f "${CONFIG_DIR}/ali2115.txt" ]; then
                    download_threads="2"
                # 阿里云盘下载链接：非 115 链接情况下，返回为 X-Oss-Request-Id + X-Oss-Storage-Class
                elif grep "X-Oss-Request-Id" "${MEDIA_DIR}/headers.log" && grep "X-Oss-Storage-Class" "${MEDIA_DIR}/headers.log"; then
                    download_threads="6"
                # 其余不确定的情况全部使用四线程下载
                else
                    download_threads="4"
                fi
                rm -f "${MEDIA_DIR}/headers.log"
            else
                if [ -f "${CONFIG_DIR}/ali2115.txt" ]; then
                    download_threads="2"
                else
                    download_threads="6"
                fi
            fi
            if [ "${download_threads}" == "1" ]; then
                INFO "单线程下载"
            else
                INFO "多线程下载，线程数：${download_threads}"
            fi
            if pull_run_glue aria2c -o "${1}" --header="User-Agent: ${GLOBAL_UA}" --allow-overwrite=true --auto-file-renaming=false --enable-color=false --file-allocation=none -c "-x${download_threads}" "${xiaoya_addr}/d/元数据/${1}"; then
                if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
                    ERROR "存在 ${MEDIA_DIR}/temp/${1}.aria2 文件，下载不完整！"
                    exit 1
                else
                    INFO "${1} 下载成功！"
                fi
            else
                DEBUG "${OSNAME} $(uname -a)"
                ERROR "${1} 下载失败！"
                exit 1
            fi
        fi

    }

    if [ "${1}" == "all_metadata" ]; then
        for file in "${ALL_METADATA_FILES[@]}"; do
            metadata_downloader "${file}"
        done

        INFO "设置目录权限..."
        chmod -R 777 "${MEDIA_DIR}"/temp
        auto_chown "${MEDIA_DIR}/temp" "-R"
    else
        metadata_downloader "${1}"

        INFO "设置目录权限..."
        chmod 777 "${MEDIA_DIR}"/temp/"${1}"
        auto_chown "${MEDIA_DIR}/temp/${1}"
    fi

}

function unzip_xiaoya_all_emby() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    mkdir -p "${MEDIA_DIR}"/temp
    rm -rf "${MEDIA_DIR}"/config

    test_disk_capacity

    mkdir -p "${MEDIA_DIR}"/xiaoya
    mkdir -p "${MEDIA_DIR}"/config
    chmod 755 "${MEDIA_DIR}"
    auto_chown "${MEDIA_DIR}"
    auto_chown "${MEDIA_DIR}/xiaoya"
    auto_chown "${MEDIA_DIR}/config"
    auto_chown "${MEDIA_DIR}/temp"

    INFO "开始解压..."

    __unzip_metadata "all_metadata"

    INFO "解压完成！"

}

function unzip_xiaoya_emby() {

    get_config_dir

    get_media_dir

    show_disk_capacity "${MEDIA_DIR}"

    chmod 777 "${MEDIA_DIR}"
    auto_chown "${MEDIA_DIR}"

    INFO "开始解压 ${MEDIA_DIR}/temp/${1} ..."

    if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
        ERROR "存在 ${MEDIA_DIR}/temp/${1}.aria2 文件，文件不完整！"
        exit 1
    fi

    if [ "${1}" == "config.mp4" ]; then
        if [ -d "${MEDIA_DIR}/config" ]; then
            INFO "清理旧配置文件中..."
            INFO "这可能需要一定时间，请耐心等待！"
            rm -rf ${MEDIA_DIR}/config
        fi
        mkdir -p "${MEDIA_DIR}"/config
        auto_chown "${MEDIA_DIR}/config"
        chmod -R 777 "${MEDIA_DIR}"/config
        __unzip_metadata "${1}"
    else
        mkdir -p "${MEDIA_DIR}"/xiaoya
        auto_chown "${MEDIA_DIR}/xiaoya"
        __unzip_metadata "${1}"
    fi

    INFO "解压完成！"

}

function unzip_appoint_xiaoya_emby_jellyfin() {

    function metadata_unziper() {

        if ! check_metadata_size "${1}"; then
            exit 1
        fi

        if [[ "${OSNAME}" = "macos" ]] || [[ "$(cat "${DDSREM_CONFIG_DIR}/use_host_7z_command.txt")" == "true" ]]; then
            INFO "使用宿主机 7z 命令解压"
            if [ ! -d "${MEDIA_DIR}/xiaoya" ]; then
                mkdir -p "${MEDIA_DIR}/xiaoya"
                auto_chown "${MEDIA_DIR}/xiaoya"
                chmod 777 "${MEDIA_DIR}/xiaoya"
            fi
            cd "${MEDIA_DIR}/xiaoya" || return 1
            INFO "当前解压工作目录：$(pwd)"
            if ! 7z x -aoa -mmt=16 "${MEDIA_DIR}/temp/${1}" "${2}/*" -o"${MEDIA_DIR}/xiaoya"; then
                if ! 7z x -aoa -mmt=16 -bb3 "${MEDIA_DIR}/temp/${1}" "${2}/*" -o"${MEDIA_DIR}/xiaoya"; then
                    __unzip_metadata_debug "${1}"
                fi
            fi
        else
            extra_parameters="--workdir=/media/xiaoya"
            if ! pull_run_glue 7z x -aoa -mmt=16 "/media/temp/${1}" "${2}/*" -o/media/xiaoya; then
                if ! pull_run_glue 7z x -aoa -mmt=16 -bb3 "/media/temp/${1}" "${2}/*" -o/media/xiaoya; then
                    __unzip_metadata_debug "${1}"
                fi
            fi
        fi

    }

    get_config_dir

    get_media_dir

    if [ "${1}" == "all.mp4" ] || [ "${1}" == "all_jf.mp4" ]; then
        INFO "请选择要解压的压缩包目录 [ 1:动漫 | 2:每日更新 | 3:电影 | 4:电视剧 | 5:纪录片 | 6:纪录片（已刮削）| 7:综艺 | 8:短剧 ]"
        valid_choice=false
        while [ "$valid_choice" = false ]; do
            read -erp "请输入数字 [1-8]:" choice
            for i in {1..8}; do
                if [ "$choice" = "$i" ]; then
                    valid_choice=true
                    break
                fi
            done
            if [ "$valid_choice" = false ]; then
                ERROR "请输入正确数字 [1-8]"
            fi
        done
        case $choice in
        1)
            UNZIP_FOLD=动漫
            ;;
        2)
            UNZIP_FOLD=每日更新
            ;;
        3)
            UNZIP_FOLD=电影
            ;;
        4)
            UNZIP_FOLD=电视剧
            ;;
        5)
            UNZIP_FOLD=纪录片
            ;;
        6)
            UNZIP_FOLD=纪录片（已刮削）
            ;;
        7)
            UNZIP_FOLD=综艺
            ;;
        8)
            UNZIP_FOLD=短剧
            ;;
        esac
    elif [ "${1}" == "115.mp4" ]; then
        INFO "请选择要解压的压缩包目录 [ 1:电视剧 | 2:电影 | 3:动漫 ]"
        valid_choice=false
        while [ "$valid_choice" = false ]; do
            read -erp "请输入数字 [1-3]:" choice
            for i in {1..3}; do
                if [ "$choice" = "$i" ]; then
                    valid_choice=true
                    break
                fi
            done
            if [ "$valid_choice" = false ]; then
                ERROR "请输入正确数字 [1-3]"
            fi
        done
        case $choice in
        1)
            UNZIP_FOLD=电视剧
            ;;
        2)
            UNZIP_FOLD=电影
            ;;
        3)
            UNZIP_FOLD=动漫
            ;;
        esac
    else
        ERROR "此文件暂时不支持解压指定元数据！"
    fi

    show_disk_capacity "${MEDIA_DIR}"

    chmod 777 "${MEDIA_DIR}"
    auto_chown "${MEDIA_DIR}"

    INFO "开始解压 ${MEDIA_DIR}/temp/${1} ${UNZIP_FOLD} ..."

    if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
        ERROR "存在 ${MEDIA_DIR}/temp/${1}.aria2 文件，文件不完整！"
        exit 1
    fi

    start_time1=$(date +%s)

    if [ "${1}" == "all.mp4" ] || [ "${1}" == "all_jf.mp4" ]; then
        mkdir -p "${MEDIA_DIR}"/xiaoya
        auto_chown "${MEDIA_DIR}/xiaoya"
        metadata_unziper "${1}" "${UNZIP_FOLD}"
    elif [ "${1}" == "115.mp4" ]; then
        mkdir -p "${MEDIA_DIR}"/xiaoya/115
        auto_chown "${MEDIA_DIR}/xiaoya/115"
        metadata_unziper "${1}" "115/${UNZIP_FOLD}"
    else
        ERROR "此文件暂时不支持解压指定元数据！"
        exit 1
    fi

    INFO "设置目录权限..."
    chmod 777 "${MEDIA_DIR}"/xiaoya

    end_time1=$(date +%s)
    total_time1=$((end_time1 - start_time1))
    total_time1=$((total_time1 / 60))
    INFO "解压执行时间：$total_time1 分钟"

    INFO "解压完成！"

}

function download_xiaoya_emby() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    mkdir -p "${MEDIA_DIR}"/temp
    auto_chown "${MEDIA_DIR}/temp"
    chmod 777 "${MEDIA_DIR}"/temp

    show_disk_capacity "${MEDIA_DIR}"

    if [ -f "${MEDIA_DIR}/temp/${1}" ]; then
        INFO "清理旧 ${1} 中..."
        rm -f "${MEDIA_DIR}/temp/${1}"
        if [ -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
            rm -rf "${MEDIA_DIR}/temp/${1}.aria2"
        fi
    fi

    __download_metadata "${1}"

    INFO "下载完成！"

}

function download_unzip_xiaoya_all_emby() {

    get_config_dir

    get_media_dir

    test_xiaoya_status

    rm -rf "${MEDIA_DIR}/config"

    test_disk_capacity

    mkdir -p "${MEDIA_DIR}/xiaoya"
    mkdir -p "${MEDIA_DIR}/config"
    mkdir -p "${MEDIA_DIR}/temp"
    auto_chown "${MEDIA_DIR}"
    auto_chown "${MEDIA_DIR}/xiaoya"
    auto_chown "${MEDIA_DIR}/config"
    auto_chown "${MEDIA_DIR}/temp"
    chmod 777 "${MEDIA_DIR}"

    for file in "${ALL_METADATA_FILES[@]}"; do
        if [ -f "${MEDIA_DIR}/temp/${file}.aria2" ]; then
            rm -rf "${MEDIA_DIR}/temp/${file}.aria2"
        fi
    done

    INFO "开始下载解压..."

    __download_metadata "all_metadata"

    __unzip_metadata "all_metadata"

    INFO "刮削数据已经下载解压完成！"

}

function download_unzip_xiaoya_emby_new_config() {

    function compare_metadata_size() {

        local REMOTE_METADATA_SIZE LOCAL_METADATA_SIZE

        pull_run_glue_xh xh --headers --follow --timeout=10 -o /media/headers.log "${xiaoya_addr}/d/元数据/${1}" "User-Agent: ${GLOBAL_UA}"
        REMOTE_METADATA_SIZE=$(cat ${MEDIA_DIR}/headers.log | grep 'Content-Length' | awk '{print $2}')
        rm -f ${MEDIA_DIR}/headers.log

        if [ -f "${MEDIA_DIR}/temp/${1}" ] && [ ! -f "${MEDIA_DIR}/temp/${1}.aria2" ]; then
            pull_run_glue bash -c "du -b /media/temp/${1} | cut -f1 > /media/size.txt"
            if [ ! -f "${MEDIA_DIR}/size.txt" ]; then
                WARN "获取元数据文件本地大小失败（单位b）"
                LOCAL_METADATA_SIZE=0
            else
                LOCAL_METADATA_SIZE=$(head -n 1 "${MEDIA_DIR}/size.txt")
                rm -f "${MEDIA_DIR}/size.txt"
            fi
        else
            LOCAL_METADATA_SIZE=0
        fi

        INFO "${1} REMOTE_METADATA_SIZE: ${REMOTE_METADATA_SIZE}"
        INFO "${1} LOCAL_METADATA_SIZE: ${LOCAL_METADATA_SIZE}"

        if
            [ "${REMOTE_METADATA_SIZE}" != "${LOCAL_METADATA_SIZE}" ] &&
                [ -n "${REMOTE_METADATA_SIZE}" ] &&
                awk -v remote="${REMOTE_METADATA_SIZE}" -v threshold="2147483648" 'BEGIN { if (remote > threshold) print "1"; else print "0"; }' | grep -q "1"
        then
            return 1
        else
            return 0
        fi

    }

    get_config_dir

    get_media_dir

    if [ -f "${MEDIA_DIR}/config/config/system.xml" ]; then
        INFO "检测到非第一次安装全家桶..."
        WARN "警告：本次元数据升级会丢失当前 Emby 所有用户配置信息！"
        local OPERATE
        while true; do
            INFO "是否继续操作 [Y/n]（默认 Y）"
            read -erp "OPERATE:" OPERATE
            [[ -z "${OPERATE}" ]] && OPERATE="y"
            if [[ ${OPERATE} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ "${OPERATE}" == [Nn] ]]; then
            exit 0
        fi
        if get_emby_version; then
            INFO "当前 Emby 版本：${emby_version}"
        else
            ERROR "当前 Emby 版本获取失败！"
            exit 1
        fi
        if version_lt "${emby_version}" "4.9.0.42"; then
            INFO "您的 Emby 版本过低，开始进入升级流程，请升级到 4.9.0.42 或更高版本！"
            oneclick_upgrade_emby
        fi

        INFO "关闭 Emby 容器中..."
        if ! docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"; then
            if ! docker kill "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"; then
                ERROR "关闭 Emby 容器失败！"
                exit 1
            fi
        fi
    fi

    test_xiaoya_status

    INFO "清理旧配置文件中..."
    INFO "这可能需要一定时间，请耐心等待！"
    rm -rf "${MEDIA_DIR}/config"

    mkdir -p "${MEDIA_DIR}/config"
    auto_chown "${MEDIA_DIR}/config"
    chmod -R 777 "${MEDIA_DIR}/config"

    if [ -f "${MEDIA_DIR}/temp/config.new.mp4.aria2" ]; then
        rm -rf "${MEDIA_DIR}/temp/config.new.mp4.aria2"
        if [ -f "${MEDIA_DIR}/temp/config.new.mp4" ]; then
            INFO "清理不完整 config.new.mp4 中..."
            rm -rf "${MEDIA_DIR}/temp/config.new.mp4"
        fi
    fi
    if [ -f "${MEDIA_DIR}/temp/config.new.mp4" ]; then
        if compare_metadata_size "config.new.mp4"; then
            INFO "当前 config.new.mp4 已是最新，无需重新下载！"
        else
            INFO "清理旧 config.new.mp4 中..."
            rm -rf "${MEDIA_DIR}/temp/config.new.mp4"
        fi
    fi

    show_disk_capacity "${MEDIA_DIR}"

    INFO "开始下载解压..."

    if [ ! -f "${MEDIA_DIR}/temp/config.new.mp4" ]; then
        __download_metadata "config.new.mp4"
    fi

    __unzip_metadata "config.new.mp4"

    docker start "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"
    wait_emby_start

    INFO "操作完成！"

}

function main_download_unzip_xiaoya_emby() {

    __data_downloader=$(cat ${DDSREM_CONFIG_DIR}/data_downloader.txt)

    function main_download_unzip_xiaoya_emby_page1() {

        echo -e "——————————————————————————————————————————————————————————————————————————————————"
        echo -e "${Blue}下载/解压 元数据${Font}\n"
        echo -e "1、下载并解压 全部元数据"
        echo -e "2、解压 全部元数据"
        echo -e "3、下载 all.mp4"
        echo -e "4、解压 all.mp4"
        echo -e "5、解压 all.mp4 的指定元数据目录【非全部解压】"
        echo -e "6、下载 config.mp4（4.9.0.42）"
        echo -e "7、解压 config.mp4（4.9.0.42）"
        echo -e "8、下载 pikpak.mp4"
        echo -e "9、解压 pikpak.mp4"
        echo -e "10、下载 115.mp4"
        echo -e "11、解压 115.mp4"
        echo -e "n、下一页"
        echo -e "0、返回上级"
        echo -e "——————————————————————————————————————————————————————————————————————————————————"

    }

    function main_download_unzip_xiaoya_emby_page2() {

        echo -e "——————————————————————————————————————————————————————————————————————————————————"
        echo -e "${Blue}下载/解压 元数据${Font}\n"
        echo -e "12、解压 115.mp4 的指定元数据目录【非全部解压】"
        echo -e "13、下载 蓝光原盘.mp4"
        echo -e "14、解压 蓝光原盘.mp4"
        echo -e "15、下载 json.mp4"
        echo -e "16、解压 json.mp4"
        echo -e "17、下载 music.mp4"
        echo -e "18、解压 music.mp4"
        echo -e "19、当前下载器【aria2/wget】                  当前状态：${Green}${__data_downloader}${Font}"
        # echo -e "101、下载并解压 config.new.mp4（4.9.0.42）"
        echo -e "p、上一页"
        echo -e "——————————————————————————————————————————————————————————————————————————————————"

    }

    __next_operate=
    local page next_page next_page_choose
    if [ -z "${1}" ]; then
        page=1
    else
        page="${1}"
    fi
    "main_download_unzip_xiaoya_emby_page${page}"
    read -erp "请输入数字（支持输入多个数字，空格分离，按输入顺序执行）[0-19]:" -a nums
    for num in "${nums[@]}"; do
        if [ $num -ge 1 ] && [ $num -le 18 ]; then
            case "$num" in
            1)
                clear
                download_unzip_xiaoya_all_emby
                ;;
            2)
                clear
                unzip_xiaoya_all_emby
                ;;
            3)
                clear
                download_xiaoya_emby "all.mp4"
                ;;
            4)
                clear
                unzip_xiaoya_emby "all.mp4"
                ;;
            5)
                clear
                unzip_appoint_xiaoya_emby_jellyfin "all.mp4"
                ;;
            6)
                clear
                download_xiaoya_emby "config.mp4"
                ;;
            7)
                clear
                unzip_xiaoya_emby "config.mp4"
                ;;
            8)
                clear
                download_xiaoya_emby "pikpak.mp4"
                ;;
            9)
                clear
                unzip_xiaoya_emby "pikpak.mp4"
                ;;
            10)
                clear
                download_xiaoya_emby "115.mp4"
                ;;
            11)
                clear
                unzip_xiaoya_emby "115.mp4"
                ;;
            12)
                clear
                unzip_appoint_xiaoya_emby_jellyfin "115.mp4"
                ;;
            13)
                clear
                download_xiaoya_emby "蓝光原盘.mp4"
                ;;
            14)
                clear
                unzip_xiaoya_emby "蓝光原盘.mp4"
                ;;
            15)
                clear
                download_xiaoya_emby "json.mp4"
                ;;
            16)
                clear
                unzip_xiaoya_emby "json.mp4"
                ;;
            17)
                clear
                download_xiaoya_emby "music.mp4"
                ;;
            18)
                clear
                unzip_xiaoya_emby "music.mp4"
                ;;
            esac
            __next_operate=return_menu
        elif [ $num == 101 ]; then
            clear
            download_unzip_xiaoya_emby_new_config
            __next_operate=return_menu
        elif [ $num == 19 ]; then
            if [ "${__data_downloader}" == "wget" ]; then
                echo 'aria2' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
            elif [ "${__data_downloader}" == "aria2" ]; then
                echo 'wget' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
            else
                echo 'aria2' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
            fi
            clear
            __next_operate=main_download_unzip_xiaoya_emby
            break
        elif [ $num == 0 ]; then
            clear
            __next_operate=main_xiaoya_all_emby
            break
        elif [ $num == "n" ]; then
            clear
            next_page=$((page + 1))
            next_page_choose=n
            __next_operate=next_page
            break
        elif [ $num == "p" ]; then
            clear
            next_page=$((page - 1))
            next_page_choose=p
            __next_operate=next_page
            break
        else
            clear
            ERROR '请输入正确数字 [0-19]'
            __next_operate=main_download_unzip_xiaoya_emby
            break
        fi
    done
    if [ -z ${__next_operate} ]; then
        clear
        ERROR '请输入正确数字 [0-19]'
        __next_operate=main_download_unzip_xiaoya_emby
    fi
    if [ "${__next_operate}" == "return_menu" ]; then
        return_menu "main_download_unzip_xiaoya_emby"
    elif [ "${__next_operate}" == "main_download_unzip_xiaoya_emby" ]; then
        main_download_unzip_xiaoya_emby "${page}"
    elif [ "${__next_operate}" == "main_xiaoya_all_emby" ]; then
        main_xiaoya_all_emby
    elif [ "${__next_operate}" == "next_page" ]; then
        if [ $next_page -ge 1 ] && [ $next_page -le 2 ]; then
            main_download_unzip_xiaoya_emby "${next_page}"
        else
            clear
            if [ "${next_page_choose}" == "n" ]; then
                ERROR '当前页面为最后一页，无法前往下一页'
            else
                ERROR '当前页面为第一页，无法前往前一页'
            fi
            main_download_unzip_xiaoya_emby "${page}"
        fi
    fi

}

function install_emby_embyserver() {

    INFO "开始安装Emby容器....."
    if [ "${DOCKER_ARCH}" == "linux/amd64" ]; then
        image_name="emby/embyserver"
    elif [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        image_name="emby/embyserver_arm64v8"
    else
        ERROR "目前只支持amd64和arm64架构，你的架构是：$CPU_ARCH"
        exit 1
    fi
    docker_pull "${image_name}:${IMAGE_VERSION}"
    if [ -n "${extra_parameters}" ]; then
        # shellcheck disable=SC2046
        docker run -itd \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            ${NET_MODE} \
            $(auto_privileged) \
            ${extra_parameters} \
            -e UID=0 \
            -e GID=0 \
            -e TZ=Asia/Shanghai \
            --restart=always \
            "${image_name}:${IMAGE_VERSION}"
    else
        # shellcheck disable=SC2046
        docker run -itd \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            ${NET_MODE} \
            $(auto_privileged) \
            -e UID=0 \
            -e GID=0 \
            -e TZ=Asia/Shanghai \
            --restart=always \
            "${image_name}:${IMAGE_VERSION}"
    fi

}

function install_amilys_embyserver() {

    INFO "开始安装Emby容器....."
    if [ "${DOCKER_ARCH}" == "linux/amd64" ]; then
        image_name="amilys/embyserver"
    elif [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        image_name="amilys/embyserver_arm64v8"
    else
        ERROR "目前只支持amd64和arm64架构，你的架构是：$CPU_ARCH"
        exit 1
    fi
    docker_pull "${image_name}:${IMAGE_VERSION}"
    if [ -n "${extra_parameters}" ]; then
        # shellcheck disable=SC2046
        docker run -itd \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            ${NET_MODE} \
            ${extra_parameters} \
            $(auto_privileged) \
            -e UID=0 \
            -e GID=0 \
            -e TZ=Asia/Shanghai \
            --restart=always \
            "${image_name}:${IMAGE_VERSION}"
    else
        # shellcheck disable=SC2046
        docker run -itd \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            ${NET_MODE} \
            $(auto_privileged) \
            -e UID=0 \
            -e GID=0 \
            -e TZ=Asia/Shanghai \
            --restart=always \
            "${image_name}:${IMAGE_VERSION}"
    fi

}

function install_lovechen_embyserver() {

    INFO "开始安装Emby容器....."

    INFO "开始转换数据库..."

    mv ${MEDIA_DIR}/config/data/library.db ${MEDIA_DIR}/config/data/library.org.db
    if [ -f "${MEDIA_DIR}/config/data/library.db-wal" ]; then
        rm -rf ${MEDIA_DIR}/config/data/library.db-wal
    fi
    if [ -f "${MEDIA_DIR}/config/data/library.db-shm" ]; then
        rm -rf ${MEDIA_DIR}/config/data/library.db-shm
    fi
    chmod 777 ${MEDIA_DIR}/config/data/library.org.db
    curl -o ${MEDIA_DIR}/config/data/library.db https://cdn.jsdelivr.net/gh/xiaoyaDev/xiaoya-alist@latest/emby_lovechen/library.db
    curl -o ${MEDIA_DIR}/temp.sql https://cdn.jsdelivr.net/gh/xiaoyaDev/xiaoya-alist@latest/emby_lovechen/temp.sql
    pull_run_glue sqlite3 /media/config/data/library.db ".read /media/temp.sql"

    INFO "数据库转换成功！"
    rm -rf ${MEDIA_DIR}/temp.sql

    docker_pull "lovechen/embyserver:${IMAGE_VERSION}"
    if [ -n "${extra_parameters}" ]; then
        # shellcheck disable=SC2046
        docker run -itd \
            --name "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            ${NET_MODE} \
            ${extra_parameters} \
            $(auto_privileged) \
            -e UID=0 \
            -e GID=0 \
            -e TZ=Asia/Shanghai \
            --restart=always \
            lovechen/embyserver:${IMAGE_VERSION}
    else
        # shellcheck disable=SC2046
        docker run -itd \
            --name "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" \
            -v "${MEDIA_DIR}/config:/config" \
            -v "${MEDIA_DIR}/xiaoya:/media" \
            -v ${NSSWITCH}:/etc/nsswitch.conf \
            --add-host="xiaoya.host:$xiaoya_host" \
            ${NET_MODE} \
            $(auto_privileged) \
            -e UID=0 \
            -e GID=0 \
            -e TZ=Asia/Shanghai \
            --restart=always \
            lovechen/embyserver:${IMAGE_VERSION}
    fi

}

function choose_network_mode() {

    INFO "请选择使用的网络模式 [ 1:host | 2:bridge ]（默认 1）"
    read -erp "Net:" MODE
    [[ -z "${MODE}" ]] && MODE="1"
    if [[ ${MODE} == [1] ]]; then
        MODE=host
    elif [[ ${MODE} == [2] ]]; then
        MODE=bridge
    else
        ERROR "输入无效，请重新选择"
        choose_network_mode
    fi

    if [ "$MODE" == "host" ]; then
        NET_MODE="--net=host"
    elif [ "$MODE" == "bridge" ]; then
        NET_MODE="-p 6908:6908"
    fi

}

function choose_emby_image() {

    INFO "您的架构是：$CPU_ARCH"
    if [ "${DOCKER_ARCH}" == "linux/amd64" ]; then
        INFO "请选择使用的Emby镜像 [ 1:amilys/embyserver | 2:emby/embyserver ]（默认 2）"
        read -erp "IMAGE:" IMAGE
        [[ -z "${IMAGE}" ]] && IMAGE="2"
        if [[ ${IMAGE} == [1] ]]; then
            CHOOSE_EMBY=amilys_embyserver
        elif [[ ${IMAGE} == [2] ]]; then
            CHOOSE_EMBY=emby_embyserver
        elif [[ ${IMAGE} == [3] ]]; then
            CHOOSE_EMBY=lovechen_embyserver
        else
            ERROR "输入无效，请重新选择"
            choose_emby_image
        fi
    elif [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        WARN "${DOCKER_ARCH} 只支持官方镜像！"
        INFO "请选择使用的Emby镜像 [ 1:emby/embyserver ]（默认 1）"
        read -erp "IMAGE:" IMAGE
        [[ -z "${IMAGE}" ]] && IMAGE="1"
        if [[ ${IMAGE} == [1] ]]; then
            CHOOSE_EMBY=amilys_embyserver
        else
            ERROR "输入无效，请重新选择"
            choose_emby_image
        fi
    else
        ERROR "全家桶 Emby 目前只支持 amd64 和 arm64 架构，你的架构是：$CPU_ARCH"
        exit 1
    fi

}

function get_nsswitch_conf_path() {

    if [ -f /etc/nsswitch.conf ]; then
        NSSWITCH="/etc/nsswitch.conf"
    else
        CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
        if [ -d "${CONFIG_DIR}/nsswitch.conf" ]; then
            rm -rf ${CONFIG_DIR}/nsswitch.conf
        fi
        echo -e "hosts:\tfiles dns" > ${CONFIG_DIR}/nsswitch.conf
        echo -e "networks:\tfiles" >> ${CONFIG_DIR}/nsswitch.conf
        NSSWITCH="${CONFIG_DIR}/nsswitch.conf"
    fi
    INFO "nsswitch.conf 配置文件路径：${NSSWITCH}"

}

function get_xiaoya_hosts() { # 调用这个函数必须设置 $MODE 此变量

    if ! grep -q xiaoya.host ${HOSTS_FILE_PATH}; then
        if [ "$MODE" == "host" ]; then
            echo -e "127.0.0.1\txiaoya.host\n" >> ${HOSTS_FILE_PATH}
            xiaoya_host="127.0.0.1"
        elif [ "$MODE" == "bridge" ]; then
            echo -e "$docker0\txiaoya.host\n" >> ${HOSTS_FILE_PATH}
            xiaoya_host="$docker0"
        fi
    else
        if [ "$MODE" == "host" ]; then
            if grep -q "^${docker0}.*xiaoya\.host" ${HOSTS_FILE_PATH}; then
                sedsh '/xiaoya.host/d' ${HOSTS_FILE_PATH}
                echo -e "127.0.0.1\txiaoya.host\n" >> ${HOSTS_FILE_PATH}
            fi
        elif [ "$MODE" == "bridge" ]; then
            if grep -q "^127\.0\.0\.1.*xiaoya\.host" ${HOSTS_FILE_PATH}; then
                sedsh '/xiaoya.host/d' ${HOSTS_FILE_PATH}
                echo -e "$docker0\txiaoya.host\n" >> ${HOSTS_FILE_PATH}
            fi
        fi
        xiaoya_host=$(grep xiaoya.host ${HOSTS_FILE_PATH} | awk '{print $1}' | head -n1)
    fi

    XIAOYA_HOSTS_SHOW=$(grep xiaoya.host ${HOSTS_FILE_PATH})
    # if echo "${XIAOYA_HOSTS_SHOW}" | awk '
    # {
    #     split($1, ip, ".");
    #     if(length(ip) == 4 && ip[1] >= 0 && ip[1] <= 255 && ip[2] >= 0 && ip[2] <= 255 && ip[3] >= 0 && ip[3] <= 255 && ip[4] >= 0 && ip[4] <= 255 && index($2, "\t") == 0)
    #         exit 0;
    #     else
    #         exit 1;
    # }'; then
    #     INFO "hosts 文件设置正确！"
    # else
    #     WARN "hosts 文件设置错误！"
    #     INFO "是否使用脚本自动纠错（只支持单机部署自动纠错，如果小雅和全家桶不在同一台机器上，请手动修改）[Y/n]（默认 Y）"
    #     read -erp "自动纠错:" FIX_HOST_ERROR
    #     [[ -z "${FIX_HOST_ERROR}" ]] && FIX_HOST_ERROR="y"
    #     if [[ ${FIX_HOST_ERROR} == [Yy] ]]; then
    #         INFO "开始自动纠错..."
    #         sedsh '/xiaoya\.host/d' /etc/hosts
    #         get_xiaoya_hosts
    #     else
    #         exit 1
    #     fi
    # fi
    if echo "${XIAOYA_HOSTS_SHOW}" | awk '{ if($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $2 ~ /^[^\t]+$/) exit 0; else exit 1 }'; then
        INFO "hosts 文件格式设置正确！"
    else
        WARN "hosts 文件格式设置错误！"
        while true; do
            INFO "是否使用脚本自动纠错（只支持单机部署自动纠错，如果小雅和全家桶不在同一台机器上，请手动修改）[Y/n]（默认 Y）"
            read -erp "自动纠错:" FIX_HOST_ERROR
            [[ -z "${FIX_HOST_ERROR}" ]] && FIX_HOST_ERROR="y"
            if [[ ${FIX_HOST_ERROR} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${FIX_HOST_ERROR} == [Yy] ]]; then
            INFO "开始自动纠错..."
            sedsh '/xiaoya\.host/d' /etc/hosts
            get_xiaoya_hosts
        else
            exit 1
        fi
    fi

    INFO "${XIAOYA_HOSTS_SHOW}"

    response="$(curl -s -o /dev/null -w '%{http_code}' http://${xiaoya_host}:5678)"
    if [[ "$response" == "302" || "$response" == "200" ]]; then
        INFO "hosts 文件设置正确，本机可以正常访问小雅容器！"
    else
        response="$(curl -s -o /dev/null -w '%{http_code}' http://${xiaoya_host}:5678)"
        if [[ "$response" == "302" || "$response" == "200" ]]; then
            INFO "hosts 文件设置正确，本机可以正常访问小雅容器！"
        else
            if [[ "${OSNAME}" = "macos" ]]; then
                localip=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
            else
                if command -v ifconfig > /dev/null 2>&1; then
                    localip=$(ifconfig -a | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1)
                else
                    localip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
                fi
            fi
            INFO "尝试使用本机IP：${localip}"
            response="$(curl -s -o /dev/null -w '%{http_code}' http://${localip}:5678)"
            if [[ "$response" == "302" || "$response" == "200" ]]; then
                sedsh '/xiaoya.host/d' ${HOSTS_FILE_PATH}
                echo -e "$localip\txiaoya.host\n" >> ${HOSTS_FILE_PATH}
                INFO "hosts 文件设置成功，本机可以正常访问小雅容器！"
            else
                ERROR "hosts 文件设置错误，本机无法正常访问小雅容器！"
                exit 1
            fi
        fi
    fi

}

function emby_fix_strmassistant() {

    function emby_test_exist_strmassistant() {
        if [ -f "${1}/plugins/StrmAssistant.dll" ]; then
            DEBUG "Emby神医助手 已安装：${1}/plugins/StrmAssistant.dll"
            return 0
        fi
        return 1
    }

    if [ "${DOCKER_ARCH}" == "linux/amd64" ]; then
        INFO "当前系统架构支持 Emby神医助手"
        if emby_test_exist_strmassistant "${1}"; then
            clear_qrcode_container
            pull_glue_python_ddsrem
            # shellcheck disable=SC2046
            docker run -it --rm \
                -v "${1}:/media/config" \
                -e LANG=C.UTF-8 \
                $(auto_privileged) \
                ddsderek/xiaoya-glue:python \
                /strmassistanthelper/strmassistanthelper.py
        fi
    elif [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        WARN "检测当前为 arm64 机器，自动卸载 Emby神医助手 中..."
        if emby_test_exist_strmassistant "${1}"; then
            rm -f "${1}/plugins/StrmAssistant.dll"
            DEBUG "删除 ${1}/plugins/StrmAssistant.dll 文件成功！"
        fi
        INFO "卸载 Emby神医助手 完成！"
    else
        WARN "未知的系统架构，无法确认是否支持 Emby神医助手"
        emby_test_exist_strmassistant "${1}"
    fi

}

function install_emby_xiaoya_all_emby() {

    get_docker0_url

    if [ -f "${MEDIA_DIR}/config/config/system.xml" ]; then
        if ! grep -q 6908 ${MEDIA_DIR}/config/config/system.xml; then
            ERROR "Emby config 出错，请重新下载解压！"
            exit 1
        fi
    else
        if [ ! -f "${MEDIA_DIR}/temp/config.mp4" ]; then
            ERROR "config.mp4 不存在，请下载此文件并解压！"
        else
            ERROR "Emby config 出错，请重新下载解压！"
        fi
        exit 1
    fi

    if [ -f "${MEDIA_DIR}/config/data/device.txt" ]; then
        INFO "检测到存在 device.txt 文件！"
        if grep -q "1999bfd1661041cd85ff5e260bc04c06" ${MEDIA_DIR}/config/data/device.txt; then
            INFO "删除 device.txt 文件中..."
            rm -f ${MEDIA_DIR}/config/data/device.txt
        fi
    fi

    XIAOYA_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
    if [ -s "${XIAOYA_CONFIG_DIR}/emby_config.txt" ]; then
        # shellcheck disable=SC1091
        source "${XIAOYA_CONFIG_DIR}/emby_config.txt"

        if ! check_port "6908"; then
            ERROR "6908 端口被占用，请关闭占用此端口的程序！"
            exit 1
        fi

        # shellcheck disable=SC2154
        if [ "${mode}" == "bridge" ]; then
            MODE=bridge
            NET_MODE="-p 6908:6908"
        elif [ "${mode}" == "host" ]; then
            MODE=host
            NET_MODE="--net=host"
        else
            choose_network_mode
        fi

        get_xiaoya_hosts

        # shellcheck disable=SC2154
        if [ "${dev_dri}" == "yes" ]; then
            extra_parameters="--device /dev/dri:/dev/dri --privileged -e GIDLIST=0,0 -e NVIDIA_VISIBLE_DEVICES=all -e NVIDIA_DRIVER_CAPABILITIES=all"
        fi

        get_nsswitch_conf_path

        if [ -n "${version}" ]; then
            IMAGE_VERSION="${version}"
        else
            IMAGE_VERSION=4.9.0.42
        fi

        emby_fix_strmassistant "${MEDIA_DIR}/config"

        # shellcheck disable=SC2154
        if [ "${image}" == "emby" ]; then
            install_emby_embyserver
        else
            if [ "${DOCKER_ARCH}" == "linux/amd64" ] || [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
                if [ "${IMAGE_VERSION}" == "${amilys_embyserver_beta_version}" ]; then
                    IMAGE_VERSION=beta
                fi
                if [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
                    WARN "amilys/embyserver_arm64v8 镜像无法指定版本号，默认拉取 latest 镜像！"
                    IMAGE_VERSION=latest
                fi
                install_amilys_embyserver
            else
                ERROR "全家桶 Emby 目前只支持 amd64 和 arm64 架构，你的架构是：$CPU_ARCH"
                exit 1
            fi
        fi

    else
        choose_emby_image

        if ! check_port "6908"; then
            ERROR "6908 端口被占用，请关闭占用此端口的程序！"
            exit 1
        fi

        choose_network_mode

        get_xiaoya_hosts

        INFO "如果需要开启Emby硬件转码请先返回主菜单开启容器运行额外参数添加 -> 72"
        container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
        if [ "${container_run_extra_parameters}" == "true" ]; then
            local RETURN_DATA
            RETURN_DATA="$(data_crep "r" "install_xiaoya_emby")"
            if [ "${RETURN_DATA}" == "None" ]; then
                INFO "请输入其他参数（默认 --device /dev/dri:/dev/dri --privileged -e GIDLIST=0,0 -e NVIDIA_VISIBLE_DEVICES=all -e NVIDIA_DRIVER_CAPABILITIES=all ）"
                read -erp "Extra parameters:" extra_parameters
                [[ -z "${extra_parameters}" ]] && extra_parameters="--device /dev/dri:/dev/dri --privileged -e GIDLIST=0,0 -e NVIDIA_VISIBLE_DEVICES=all -e NVIDIA_DRIVER_CAPABILITIES=all"
            else
                INFO "已读取您上次设置的参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
                read -erp "Extra parameters:" extra_parameters
                [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
                if [ "${extra_parameters}" == "None" ]; then
                    extra_parameters="--device /dev/dri:/dev/dri --privileged -e GIDLIST=0,0 -e NVIDIA_VISIBLE_DEVICES=all -e NVIDIA_DRIVER_CAPABILITIES=all"
                fi
            fi
            extra_parameters=$(data_crep "write" "install_xiaoya_emby")
        fi

        get_nsswitch_conf_path

        while true; do
            case ${CHOOSE_EMBY} in
            "amilys_embyserver")
                if [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
                    WARN "amilys/embyserver_arm64v8 镜像无法指定版本号，默认拉取 latest 镜像！"
                    IMAGE_VERSION=latest
                    break
                else
                    INFO "请选择 Emby 镜像版本 [ 1；4.8.9.0 | 2: 4.9.0.42 | 3；latest（${amilys_embyserver_latest_version}） ]（默认 2）"
                    read -erp "CHOOSE_IMAGE_VERSION:" CHOOSE_IMAGE_VERSION
                    [[ -z "${CHOOSE_IMAGE_VERSION}" ]] && CHOOSE_IMAGE_VERSION="2"
                    case ${CHOOSE_IMAGE_VERSION} in
                    1)
                        IMAGE_VERSION=4.8.9.0
                        break
                        ;;
                    2)
                        IMAGE_VERSION=4.9.0.42
                        if [ "${IMAGE_VERSION}" == "${amilys_embyserver_beta_version}" ]; then
                            IMAGE_VERSION=beta
                        fi
                        break
                        ;;
                    3)
                        IMAGE_VERSION=latest
                        break
                        ;;
                    *)
                        ERROR "输入无效，请重新选择"
                        ;;
                    esac
                fi
                ;;
            "install_lovechen_embyserver")
                WARN "lovechen/embyserver 镜像无法指定版本号，默认拉取 4.7.14.0 镜像！"
                IMAGE_VERSION=4.7.14.0
                break
                ;;
            "emby_embyserver")
                INFO "请选择 Emby 镜像版本 [ 1；4.8.9.0 | 2；4.9.0.42 | 3；latest（${emby_embyserver_latest_version}） ]（默认 2）"
                read -erp "CHOOSE_IMAGE_VERSION:" CHOOSE_IMAGE_VERSION
                [[ -z "${CHOOSE_IMAGE_VERSION}" ]] && CHOOSE_IMAGE_VERSION="2"
                case ${CHOOSE_IMAGE_VERSION} in
                1)
                    IMAGE_VERSION=4.8.9.0
                    break
                    ;;
                2)
                    IMAGE_VERSION=4.9.0.42
                    break
                    ;;
                3)
                    IMAGE_VERSION=latest
                    break
                    ;;
                *)
                    ERROR "输入无效，请重新选择"
                    ;;
                esac
                ;;
            esac
        done

        emby_fix_strmassistant "${MEDIA_DIR}/config"

        case ${CHOOSE_EMBY} in
        emby_embyserver)
            install_emby_embyserver
            ;;
        lovechen_embyserver)
            install_lovechen_embyserver
            ;;
        amilys_embyserver)
            install_amilys_embyserver
            ;;
        esac

    fi

    if [ ! -f "${CONFIG_DIR}"/infuse_api_key.txt ]; then
        echo "e825ed6f7f8f44ffa0563cddaddce14d" > "${CONFIG_DIR}"/infuse_api_key.txt
        auto_chown "${CONFIG_DIR}/infuse_api_key.txt"
    fi

    wait_emby_start

    sleep 2

    set_emby_server

    if ! docker exec -i "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" curl -I -s http://127.0.0.1:2345/ | grep -q "302"; then
        INFO "重启小雅容器中..."
        docker restart "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
        wait_xiaoya_start
    fi

    INFO "Emby安装完成！"

}

function oneclick_upgrade_emby() {

    local emby_name emby_config_dir
    emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)
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
    INFO "获取 ${emby_name} 容器信息中..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp ddsderek/runlike "${emby_name}" > "/tmp/container_update_${emby_name}"
    old_image=$(docker container inspect -f '{{.Config.Image}}' "${emby_name}")
    old_image_name="$(echo "${old_image}" | cut -d':' -f1)"
    emby_config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "${emby_name}" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/config$" | awk -F: '{print $1}')"
    INFO "获取 Emby 版本中..."
    if get_emby_version; then
        INFO "当前 Emby 版本：${emby_version}"
        check_emby_version_status=true
    else
        check_emby_version_status=false
    fi
    while true; do
        if [ "${old_image_name}" == "amilys/embyserver" ] || [ "${old_image_name}" == "amilys/embyserver_arm64v8" ]; then
            if [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
                WARN "amilys/embyserver_arm64v8 镜像无法指定版本号，默认重新拉取 latest 镜像更新容器！"
                IMAGE_VERSION=latest
                break
            else
                INFO "请选择 Emby 镜像版本 [ 1；4.8.9.0 | 2；4.9.0.42 | 3；latest（${amilys_embyserver_latest_version}）| 4；beta（${amilys_embyserver_beta_version}）]（默认 2）"
                read -erp "CHOOSE_IMAGE_VERSION:" CHOOSE_IMAGE_VERSION
                [[ -z "${CHOOSE_IMAGE_VERSION}" ]] && CHOOSE_IMAGE_VERSION="2"
                case ${CHOOSE_IMAGE_VERSION} in
                1)
                    IMAGE_VERSION=4.8.9.0
                    choose_emby_version="${IMAGE_VERSION}"
                    ;;
                2)
                    IMAGE_VERSION=4.9.0.42
                    if [ "${IMAGE_VERSION}" == "${amilys_embyserver_beta_version}" ]; then
                        IMAGE_VERSION=beta
                        choose_emby_version="${amilys_embyserver_beta_version}"
                    else
                        choose_emby_version="${IMAGE_VERSION}"
                    fi
                    ;;
                3)
                    IMAGE_VERSION=latest
                    choose_emby_version="${amilys_embyserver_latest_version}"
                    ;;
                4)
                    IMAGE_VERSION=beta
                    choose_emby_version="${amilys_embyserver_beta_version}"
                    ;;
                *)
                    ERROR "输入无效，请重新选择"
                    ;;
                esac
                if [ "${check_emby_version_status}" == true ] && [ -n "${choose_emby_version}" ]; then
                    if version_lt "${choose_emby_version}" "${emby_version}"; then
                        ERROR "您选择升级的 Emby 版本低于当前安装 Emby 版本，Emby 版本无法降级，请重新选择"
                    else
                        break
                    fi
                elif [ "${check_emby_version_status}" == false ] && [ -n "${choose_emby_version}" ]; then
                    break
                fi
            fi
        elif [ "${old_image_name}" == "lovechen/embyserver" ]; then
            WARN "lovechen/embyserver 镜像无法更新！"
            exit 0
        elif [ "${old_image_name}" == "emby/embyserver" ] || [ "${old_image_name}" == "emby/embyserver_arm64v8" ]; then
            INFO "请选择 Emby 镜像版本 [ 1；4.8.9.0 | 2；4.9.0.42 | 3；latest（${emby_embyserver_latest_version}） | 4；beta（${emby_embyserver_beta_version}）]（默认 2）"
            read -erp "CHOOSE_IMAGE_VERSION:" CHOOSE_IMAGE_VERSION
            [[ -z "${CHOOSE_IMAGE_VERSION}" ]] && CHOOSE_IMAGE_VERSION="2"
            case ${CHOOSE_IMAGE_VERSION} in
            1)
                IMAGE_VERSION=4.8.9.0
                choose_emby_version="${IMAGE_VERSION}"
                ;;
            2)
                IMAGE_VERSION=4.9.0.42
                choose_emby_version="${IMAGE_VERSION}"
                ;;
            3)
                IMAGE_VERSION=latest
                choose_emby_version="${emby_embyserver_latest_version}"
                ;;
            4)
                IMAGE_VERSION=beta
                choose_emby_version="${emby_embyserver_beta_version}"
                ;;
            *)
                ERROR "输入无效，请重新选择"
                ;;
            esac
            if [ "${check_emby_version_status}" == true ] && [ -n "${choose_emby_version}" ]; then
                if version_lt "${choose_emby_version}" "${emby_version}"; then
                    ERROR "您选择升级的 Emby 版本低于当前安装 Emby 版本，Emby 版本无法降级，请重新选择"
                else
                    break
                fi
            elif [ "${check_emby_version_status}" == false ] && [ -n "${choose_emby_version}" ]; then
                break
            fi
        fi
    done
    local config_dir
    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
    fi
    if [ -n "${config_dir}" ]; then
        if [ -f "${config_dir}/emby_config.txt" ]; then
            INFO "检测到配置 emby_config.txt，自动更新 emby_config.txt 版本信息"
            sedsh "s/version=.*/version=${IMAGE_VERSION}/" "${config_dir}/emby_config.txt"
        fi
    fi
    if [ -n "${emby_config_dir}" ]; then
        emby_fix_strmassistant "${emby_config_dir}"
    fi
    run_image="$(echo "${old_image}" | cut -d':' -f1):${IMAGE_VERSION}"
    remove_image=$(docker images -q ${old_image})
    sedsh "s|${old_image}|${run_image}|g" "/tmp/container_update_${emby_name}"
    INFO "${old_image} ${old_image_name} ${run_image} ${remove_image}"
    local retries=0
    local max_retries=3
    IMAGE_MIRROR=$(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")
    while [ $retries -lt $max_retries ]; do
        if docker pull "${IMAGE_MIRROR}/${run_image}"; then
            INFO "${emby_name} 镜像拉取成功！"
            break
        else
            WARN "${emby_name} 镜像拉取失败，正在进行第 $((retries + 1)) 次重试..."
            retries=$((retries + 1))
        fi
    done
    if [ $retries -eq $max_retries ]; then
        ERROR "镜像拉取失败，已达到最大重试次数！"
        exit 1
    else
        if [ "${IMAGE_MIRROR}" != "docker.io" ]; then
            pull_image=$(docker images -q "${IMAGE_MIRROR}/${run_image}")
        else
            pull_image=$(docker images -q "${run_image}")
        fi
        if ! docker stop "${emby_name}" > /dev/null 2>&1; then
            if ! docker kill "${emby_name}" > /dev/null 2>&1; then
                docker rmi "${IMAGE_MIRROR}/${run_image}"
                ERROR "更新失败，停止 ${emby_name} 容器失败！"
                exit 1
            fi
        fi
        INFO "停止 ${emby_name} 容器成功！"
        if ! docker rm --force "${emby_name}" > /dev/null 2>&1; then
            ERROR "更新失败，删除 ${emby_name} 容器失败！"
            exit 1
        fi
        INFO "删除 ${emby_name} 容器成功！"
        if [ "${pull_image}" != "${remove_image}" ]; then
            INFO "删除 ${remove_image} 镜像中..."
            docker rmi "${remove_image}" > /dev/null 2>&1
        fi
        if [ "${IMAGE_MIRROR}" != "docker.io" ]; then
            docker tag "${IMAGE_MIRROR}/${run_image}" "${run_image}" > /dev/null 2>&1
            docker rmi "${IMAGE_MIRROR}/${run_image}" > /dev/null 2>&1
        fi
        if bash "/tmp/container_update_${emby_name}"; then
            rm -f "/tmp/container_update_${emby_name}"
            wait_emby_start
            INFO "${emby_name} 更新成功"
            return 0
        else
            ERROR "更新失败，创建 ${emby_name} 容器失败！"
            exit 1
        fi
    fi

}

function emby_close_6908_port() {

    echo -e "${Yellow}此功能关闭 6908 访问是通过将 Emby 设置为桥接模式并取消端口映射，非防火墙屏蔽！！！${Font}"
    echo -e "${Yellow}如果您使用此功能关闭 6908 访问，那您无法再使用浏览器访问 6908 端口使用 Emby！！！${Font}"
    echo -e "${Yellow}如果您需要访问 Emby 并且走服务端流量，可以访问 2347 端口，此端口与 6908 逻辑一致！！！${Font}"
    echo -e "${Yellow}正常使用依旧是访问 2345 端口即可愉快观影！！！${Font}"
    local OPERATE
    while true; do
        INFO "是否继续操作 [Y/n]（默认 Y）"
        read -erp "OPERATE:" OPERATE
        [[ -z "${OPERATE}" ]] && OPERATE="y"
        if [[ ${OPERATE} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ "${OPERATE}" == [Nn] ]]; then
        exit 0
    fi

    local emby_name emby_ip config_dir xiaoya_name
    xiaoya_name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    emby_name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"
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
    INFO "获取 ${emby_name} 容器信息中..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp ddsderek/runlike -p "${emby_name}" > "/tmp/container_update_${emby_name}"
    INFO "更改 Emby 为桥接模式并取消端口映射中..."
    if grep -q 'network=host' "/tmp/container_update_${emby_name}"; then
        INFO "更改网络模式为桥接模式"
        sedsh 's/network=host/network=bridge/' "/tmp/container_update_${emby_name}"
    fi
    if grep -q '6908:6908' "/tmp/container_update_${emby_name}"; then
        INFO "关闭 6908 端口映射"
        sedsh '/-p 6908:6908/d' "/tmp/container_update_${emby_name}"
    fi
    MODE=bridge
    get_docker0_url
    get_xiaoya_hosts
    INFO "更改容器 host 配置"
    sedsh "s/--add-host xiaoya.host.*/--add-host xiaoya.host:${xiaoya_host} \\\/" "/tmp/container_update_${emby_name}"
    if ! docker stop "${emby_name}" > /dev/null 2>&1; then
        if ! docker kill "${emby_name}" > /dev/null 2>&1; then
            docker rmi "${IMAGE_MIRROR}/${run_image}"
            ERROR "停止 ${emby_name} 容器失败！"
            exit 1
        fi
    fi
    INFO "停止 ${emby_name} 容器成功！"
    if ! docker rm --force "${emby_name}" > /dev/null 2>&1; then
        ERROR "删除 ${emby_name} 容器失败！"
        exit 1
    fi
    if bash "/tmp/container_update_${emby_name}"; then
        rm -f "/tmp/container_update_${emby_name}"
        wait_emby_start
        INFO "${emby_name} 容器启动成功！"
    else
        ERROR "创建 ${emby_name} 容器失败！"
        exit 1
    fi
    INFO "获取 ${emby_name} 容器 IP"
    emby_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${emby_name}")"
    if [ -n "${emby_ip}" ]; then
        INFO "${emby_name} 容器 IP：${emby_ip}"
    else
        ERROR "获取 ${emby_name} 容器 IP 错误！"
    fi
    INFO "配置 emby_server.txt 文件中"
    config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "${xiaoya_name}" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
    if [ -z "${config_dir}" ]; then
        WARN "小雅容器配置目录获取失败，请手动输入！"
        get_config_dir
        config_dir=${CONFIG_DIR}
    fi
    echo "http://$emby_ip:6908" > "${config_dir}"/emby_server.txt
    auto_chown "${config_dir}/emby_server.txt"
    INFO "重启小雅容器"
    docker restart "${xiaoya_name}"
    wait_xiaoya_start
    INFO "关闭 Emby 6908 端口完成！"

}

function xiaoya_emd_updated_tips() {

    if ! docker exec -i xiaoya-emd grep -q 'main_solid' /entrypoint.sh > /dev/null 2>&1; then
        ERROR "当前版本小雅元数据定时爬虫不支持执行此操作，请手动卸载重新安装！"
        exit 1
    fi

    if [ "${1}" != "None" ]; then
        if version_lt "$(docker exec -i xiaoya-emd awk -F '=' '/IMAGE_VERSION/ {print $2}' /entrypoint.sh | head -n 1)" "${1}"; then
            ERROR "当前版本小雅元数据定时爬虫不支持执行此操作，请手动卸载重新安装！"
            exit 1
        fi
    fi

}

function xiaoya_emd_pathlib() {

    if [ "${1}" == "install" ]; then
        PATHLIB_DIR="${2}/pathlib.txt"
        if [ ! -f "${PATHLIB_DIR}" ]; then
            echo -e "每日更新/\n纪录片（已刮削）/\n" > "${PATHLIB_DIR}"
        fi
    elif [ "${1}" == "once" ]; then
        PATHLIB_DIR="${2}/once_pathlib.txt"
        touch_chmod "${2}/once_pathlib.txt"
    fi
    sedsh '/^[[:space:]]*$/d' "${PATHLIB_DIR}"
    while true; do
        clear
        emd_all_paths=('动漫/' '每日更新/' '电影/' '电视剧/' '纪录片/' '纪录片（已刮削）/' '综艺/' '音乐/' '测试/' '📺画质演示测试（4K，8K，HDR，Dolby）/')
        interface=
        file_array=()
        while IFS= read -r line; do
            file_array+=("$line")
        done < "${PATHLIB_DIR}"
        for i in "${file_array[@]}"; do
            skip=false
            for j in "${emd_all_paths[@]}"; do
                if [ "$i" == "$j" ]; then
                    skip=true
                    break
                fi
            done
            if [[ "$skip" = false ]]; then
                emd_all_paths+=("$i")
            fi
        done
        for i in "${!emd_all_paths[@]}"; do
            local CONTENT
            if grep -q "^${emd_all_paths[$i]}$" "${PATHLIB_DIR}"; then
                CONTENT="${Green}已选中${Font}"
            else
                CONTENT="${Red}未选中${Font}"
            fi
            if ((i + 1 <= 10)); then
                interface+="$((i + 1))、${emd_all_paths[$i]}（${CONTENT}）\n"
            else
                interface+="$((i + 1))、${emd_all_paths[$i]}（${Sky_Blue}用户自定义${Font}）（${CONTENT}）\n"
            fi
        done
        echo -e "——————————————————————————————————————————————————————————————————————————————————"
        echo -e "${Blue}爬取目录选择${Font}\n"
        echo -e "${Sky_Blue}红色代表未选中，绿色代表已选中，输入对应选项数字可勾选或取消勾选"
        echo -e "支持输入多个数字，支持自定义爬取路径和现有选项一起输入，自定义爬取路径需要用''包裹"
        echo -e "示例：1 5 8 9 10 '电影/豆瓣 top 1000部/' '每日更新/动漫/'${Font}\n"
        echo -e "${interface}\c"
        if [ "${1}" == "install" ]; then
            echo -e "101、重置配置"
        fi
        echo -e "0、保存退出"
        echo -e "——————————————————————————————————————————————————————————————————————————————————"
        read -erp "请输入数字或路径:" user_paths
        if [ -n "${user_paths}" ]; then
            if [ "${user_paths}" == 0 ]; then
                clear
                break
            fi
            if [ "${user_paths}" == 101 ] && [ "${1}" == "install" ]; then
                echo -e "每日更新/\n纪录片（已刮削）/\n" > "${PATHLIB_DIR}"
                clear
            fi
            eval "user_path_array=($user_paths)"
            # shellcheck disable=SC2154
            for j in "${!user_path_array[@]}"; do
                if [[ "${user_path_array[$j]}" -eq "${user_path_array[$j]}" ]] 2> /dev/null; then
                    for i in "${!emd_all_paths[@]}"; do
                        if [[ "$((i + 1))" == "${user_path_array[$j]}" ]]; then
                            if grep -q "^${emd_all_paths[$i]}$" "${PATHLIB_DIR}"; then
                                sedsh "\#${emd_all_paths[$i]}#d" "${PATHLIB_DIR}"
                            else
                                echo "${emd_all_paths[$i]}" >> "${PATHLIB_DIR}"
                            fi
                            break
                        fi
                    done
                else
                    if grep -q "^${user_path_array[$j]}$" "${PATHLIB_DIR}"; then
                        sedsh "\#${user_path_array[$j]}#d" "${PATHLIB_DIR}"
                    else
                        echo "${user_path_array[$j]}" >> "${PATHLIB_DIR}"
                    fi
                fi
            done
            sedsh '/^[[:space:]]*$/d' "${PATHLIB_DIR}"
        fi
    done

}

function install_xiaoya_emd() {

    get_media_dir

    while true; do
        INFO "请输入您希望的爬虫同步间隔"
        WARN "循环时间必须大于12h，为了减轻服务器压力，请用户理解！"
        read -erp "请输入以小时为单位的正整数同步间隔时间（默认：12）：" sync_interval
        [[ -z "${sync_interval}" ]] && sync_interval="12"
        if [[ "$sync_interval" -ge 12 ]]; then
            break
        else
            ERROR "输入错误，请重新输入。同步间隔时间必须为12以上的正整数。"
        fi
    done
    cycle=$((sync_interval * 60 * 60))

    xiaoya_emd_pathlib "install" "${MEDIA_DIR}/xiaoya"

    while true; do
        INFO "是否开启重启容器自动更新到最新程序 [Y/n]（默认 n 不开启）"
        WARN "需要拥有良好的上网环境才可以更新成功，要能访问 Github 和 Python PIP 库！"
        read -erp "RESTART_AUTO_UPDATE:" RESTART_AUTO_UPDATE
        [[ -z "${RESTART_AUTO_UPDATE}" ]] && RESTART_AUTO_UPDATE="n"
        if [[ ${RESTART_AUTO_UPDATE} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${RESTART_AUTO_UPDATE} == [Yy] ]]; then
        RESTART_AUTO_UPDATE=true
    else
        RESTART_AUTO_UPDATE=false
    fi

    while true; do
        INFO "请选择镜像版本 [ 1；latest | 2；beta ]（默认 1）"
        read -erp "CHOOSE_IMAGE_VERSION:" CHOOSE_IMAGE_VERSION
        [[ -z "${CHOOSE_IMAGE_VERSION}" ]] && CHOOSE_IMAGE_VERSION="1"
        case ${CHOOSE_IMAGE_VERSION} in
        1)
            IMAGE_VERSION=latest
            break
            ;;
        2)
            IMAGE_VERSION=beta
            break
            ;;
        *)
            ERROR "输入无效，请重新选择"
            ;;
        esac
    done

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
        if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)" > /dev/null 2>&1; then
            case "$(docker inspect --format='{{.State.Status}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)")" in
            "running")
                INFO "重启 Emby 容器中..."
                docker restart "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"
                ;;
            esac
        fi
        INFO "系统 inotify watches & instances 数值配置成功！"
    fi

    extra_parameters=
    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA
        RETURN_DATA="$(data_crep "r" "install_xiaoya_emd")"
        # 兼容新版本参数
        if [ "${RETURN_DATA}" == "--media /media" ]; then
            RETURN_DATA="--media /media --paths /media/pathlib.txt"
        fi
        if [ "${RETURN_DATA}" == "None" ]; then
            INFO "请输入运行参数（默认 --media /media --paths /media/pathlib.txt ）"
            WARN "如果需要更改此设置请注意容器目录映射，默认媒体库路径映射到容器内的 /media 文件夹下！"
            WARN "警告！！！ 默认请勿修改 /media 路径！！！"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters="--media /media --paths /media/pathlib.txt"
        else
            INFO "已读取您上次设置的运行参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
            WARN "如果需要更改此设置请注意容器目录映射，默认媒体库路径映射到容器内的 /media 文件夹下！"
            WARN "警告！！！ 默认请勿修改 /media 路径！！！"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
            if [ "${extra_parameters}" == "None" ]; then
                extra_parameters="--media /media --paths /media/pathlib.txt"
            fi
        fi
    else
        extra_parameters="--media /media --paths /media/pathlib.txt"
    fi
    script_extra_parameters="$(data_crep "write" "install_xiaoya_emd")"

    extra_parameters=
    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA_2
        RETURN_DATA_2="$(data_crep "r" "install_xiaoya_emd_2")"
        if [ "${RETURN_DATA_2}" == "None" ]; then
            INFO "请输入运行容器额外参数（默认 无 ）"
            read -erp "Extra parameters:" extra_parameters
        else
            INFO "已读取您上次设置的运行容器额外参数：${RETURN_DATA_2} (默认不更改回车继续，如果需要更改请输入新参数)"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA_2}
        fi
        run_extra_parameters=$(data_crep "w" "install_xiaoya_emd_2")
    fi

    docker_pull "ddsderek/xiaoya-emd:${IMAGE_VERSION}"

    # shellcheck disable=SC2046
    docker run -d \
        --name=xiaoya-emd \
        --restart=always \
        --net=host \
        -v "${MEDIA_DIR}/xiaoya:/media" \
        -e "CYCLE=${cycle}" \
        -e "RESTART_AUTO_UPDATE=${RESTART_AUTO_UPDATE}" \
        -e TZ=Asia/Shanghai \
        ${run_extra_parameters} \
        $(auto_privileged) \
        ddsderek/xiaoya-emd:${IMAGE_VERSION} \
        ${script_extra_parameters}

    INFO "安装完成！"

}

function update_xiaoya_emd() {

    xiaoya_emd_updated_tips "None"
    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新小雅元数据定时爬虫${Blue} $i ${Font}\r"
        sleep 1
    done
    xiaoya_emd_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' xiaoya-emd | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/media$" | awk -F: '{print $1}')"
    if [ -n "${xiaoya_emd_dir}" ]; then
        if [ -f "${xiaoya_emd_dir}/solid.lock" ]; then
            INFO "检测到存在进程锁，清理中..."
            rm -f "${xiaoya_emd_dir}/solid.lock"
        fi
    fi
    container_update xiaoya-emd

}

function unisntall_xiaoya_emd() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始卸载小雅元数据定时爬虫${Blue} $i ${Font}\r"
        sleep 1
    done

    xiaoya_emd_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' xiaoya-emd | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/media$" | awk -F: '{print $1}')"

    docker stop xiaoya-emd
    docker rm xiaoya-emd
    docker rmi ddsderek/xiaoya-emd:latest

    if [ -n "${xiaoya_emd_dir}" ]; then
        for file in "solid.lock" "once_pathlib.txt" "pathlib.txt" ".tempfiles.db" ".localfiles.db"; do
            if [ -f "${xiaoya_emd_dir}/${file}" ]; then
                INFO "清理 ${file} 文件"
                rm -f "${xiaoya_emd_dir}/${file}"
            fi
        done
    fi

    INFO "小雅元数据定时爬虫卸载成功！"

}

function once_xiaoya_emd() {

    xiaoya_emd_updated_tips "v1.0.0"
    xiaoya_emd_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' xiaoya-emd | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/media$" | awk -F: '{print $1}')"
    if [ -z "${xiaoya_emd_dir}" ]; then
        get_media_dir
        xiaoya_emd_dir="${MEDIA_DIR}/xiaoya"
    fi
    INFO "小雅媒体库路径：${xiaoya_emd_dir}"
    sleep 2
    xiaoya_emd_pathlib "once" "${xiaoya_emd_dir}"
    cat << EOF > "${xiaoya_emd_dir}/once_run.sh"
cd /app || exit 1
if [ -d /tmp/db ]; then
    rm -rf /tmp/db
fi
mkdir -p /tmp/db
if [ -f /media/solid.lock ] && grep -q 'python3 solid.py'; then
    echo -e "${ERROR} 当前已有爬虫进程在运行，请稍后再试！"
    exit 1
else
    touch /media/solid.lock
    echo -e "${INFO} 开始下载同步！"
    echo -e "${INFO} python3 solid.py --media /media --paths /media/once_pathlib.txt --location /tmp/db"
    python3 solid.py --media /media --paths /media/once_pathlib.txt --location /tmp/db
    echo -e "${INFO} 运行完成！"
    rm -f /media/solid.lock
    exit 0
fi
EOF
    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始爬取指定元数据${Blue} $i ${Font}\r"
        sleep 1
    done
    docker exec -it xiaoya-emd bash /media/once_run.sh
    docker exec -it xiaoya-emd rm -f /media/once_run.sh
    docker exec -it xiaoya-emd rm -f /media/once_pathlib.txt

}

function main_xiaoya_emd() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅元数据定时爬虫${Font}\n"
    echo -e "${Sky_Blue}小雅元数据定时爬虫由 https://github.com/Rik-F5 更新维护，在此表示感谢！"
    echo -e "具体详细配置参数请看项目README：https://github.com/xiaoyaDev/xiaoya_db${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "4、立刻爬取指定目录"
    echo -e "5、容器定时爬取目录单独配置"
    echo -e "6、清理爬虫进程锁"
    echo -e "7、重置爬虫数据库"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-7]:" num
    case "$num" in
    1)
        clear
        install_xiaoya_emd
        return_menu "main_xiaoya_emd"
        ;;
    2)
        clear
        update_xiaoya_emd
        return_menu "main_xiaoya_emd"
        ;;
    3)
        clear
        unisntall_xiaoya_emd
        return_menu "main_xiaoya_emd"
        ;;
    4)
        clear
        once_xiaoya_emd
        return_menu "main_xiaoya_emd"
        ;;
    5)
        clear
        xiaoya_emd_updated_tips "v1.0.0"
        xiaoya_emd_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' xiaoya-emd | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/media$" | awk -F: '{print $1}')"
        if [ -z "${xiaoya_emd_dir}" ]; then
            get_media_dir
            xiaoya_emd_dir="${MEDIA_DIR}/xiaoya"
        fi
        INFO "小雅媒体库路径：${xiaoya_emd_dir}"
        sleep 2
        xiaoya_emd_pathlib "install" "${xiaoya_emd_dir}"
        return_menu "main_xiaoya_emd"
        ;;
    6)
        clear
        xiaoya_emd_updated_tips "v1.0.0"
        if [ "$(docker inspect --format='{{.State.Status}}' xiaoya-emd)" == "running" ]; then
            if docker exec -it xiaoya-emd ps -ef | grep -q 'python3 solid.py'; then
                ERROR "当前有爬虫进程正在运行，无法清理进程锁！"
                exit 1
            else
                if docker exec -it xiaoya-emd ls -al /media/solid.lock > /dev/null 2>&1; then
                    INFO "检测到存在进程锁，清理中..."
                    docker exec -it xiaoya-emd rm -f /media/solid.lock
                fi
            fi
        else
            xiaoya_emd_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' xiaoya-emd | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/media$" | awk -F: '{print $1}')"
            if [ -n "${xiaoya_emd_dir}" ]; then
                if [ -f "${xiaoya_emd_dir}/solid.lock" ]; then
                    INFO "检测到存在进程锁，清理中..."
                    rm -f "${xiaoya_emd_dir}/solid.lock"
                fi
            fi
        fi
        INFO "进程锁清理完成！"
        return_menu "main_xiaoya_emd"
        ;;
    7)
        clear
        xiaoya_emd_updated_tips "v1.0.0"
        if [ "$(docker inspect --format='{{.State.Status}}' xiaoya-emd)" == "running" ]; then
            if docker exec -it xiaoya-emd ps -ef | grep -q 'python3 solid.py'; then
                ERROR "当前有爬虫进程正在运行，无法重置数据库！"
                exit 1
            fi
        fi
        xiaoya_emd_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' xiaoya-emd | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/media$" | awk -F: '{print $1}')"
        if [ -n "${xiaoya_emd_dir}" ]; then
            for file in ".tempfiles.db" ".localfiles.db"; do
                if [ -f "${xiaoya_emd_dir}/${file}" ]; then
                    INFO "清理 ${file} 文件"
                    rm -f "${xiaoya_emd_dir}/${file}"
                fi
            done
            INFO "数据库重置完成！"
        else
            ERROR "数据库重置失败，无法读取媒体库路径，请手动删除媒体库路径下面的 db 后缀文件！"
            exit 1
        fi
        return_menu "main_xiaoya_emd"
        ;;
    0)
        clear
        main_xiaoya_all_emby
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-7]'
        main_xiaoya_emd
        ;;
    esac

}

function uninstall_xiaoya_all_emby() {

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
        echo -en "即将开始卸载小雅Emby全家桶${Blue} $i ${Font}\r"
        sleep 1
    done
    IMAGE_NAME="$(docker inspect --format='{{.Config.Image}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)")"
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)"
    docker rmi "${IMAGE_NAME}"
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt ]; then
            OLD_MEDIA_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_media_dir.txt)
            rm -rf "${OLD_MEDIA_DIR}"
        fi
    fi

    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)" > /dev/null 2>&1; then
        unisntall_resilio
    fi
    if docker container inspect xiaoya-emd > /dev/null 2>&1; then
        unisntall_xiaoya_emd
    fi

    INFO "全家桶卸载成功！"

}

function auto_clean_metadata_mp4_files() {

    __auto_clean_metadata_mp4_file=$(cat "${DDSREM_CONFIG_DIR}/auto_clean_metadata_mp4_file.txt")
    if [ "${__auto_clean_metadata_mp4_file}" == "true" ]; then
        _auto_clean_metadata_mp4_file="${Green}开启${Font}"
    elif [ "${__auto_clean_metadata_mp4_file}" == "false" ]; then
        _auto_clean_metadata_mp4_file="${Red}关闭${Font}"
    else
        _auto_clean_metadata_mp4_file="${Red}错误${Font}"
    fi

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}元数据压缩文件清理${Font}\n"
    echo -e "1、开启/关闭 解压成功后自动清理 mp4 元数据文件    当前状态：${_auto_clean_metadata_mp4_file}"
    echo -e "2、一键清理当前所有 mp4 元数据文件"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-2]:" num
    case "$num" in
    1)
        if [ "${__auto_clean_metadata_mp4_file}" == "false" ]; then
            echo 'true' > ${DDSREM_CONFIG_DIR}/auto_clean_metadata_mp4_file.txt
        else
            echo 'false' > ${DDSREM_CONFIG_DIR}/auto_clean_metadata_mp4_file.txt
        fi
        clear
        auto_clean_metadata_mp4_files
        ;;
    2)
        clear
        get_media_dir
        WARN "将清理以下所有文件："
        find "${MEDIA_DIR}/temp" -type f -name "*.mp4"
        local OPERATE
        while true; do
            INFO "是否继续操作 [Y/n]（默认 Y）"
            read -erp "OPERATE:" OPERATE
            [[ -z "${OPERATE}" ]] && OPERATE="y"
            if [[ ${OPERATE} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ "${OPERATE}" == [Nn] ]]; then
            exit 0
        fi
        for i in $(seq -w 3 -1 0); do
            echo -en "即将开始清理${Blue} $i ${Font}\r"
            sleep 1
        done
        find "${MEDIA_DIR}/temp" -type f -name "*.mp4" -delete
        INFO "清理完成！"
        return_menu "auto_clean_metadata_mp4_files"
        ;;
    0)
        clear
        main_xiaoya_all_emby_other_features
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-2]'
        auto_clean_metadata_mp4_files
        ;;
    esac

}

function main_xiaoya_all_emby_other_features() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Emby全家桶其他功能${Font}\n"
    echo -e "1、自动清理 mp4 元数据文件"
    echo -e "2、关闭 Emby 6908 端口访问"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-2]:" num
    case "$num" in
    1)
        clear
        auto_clean_metadata_mp4_files
        ;;
    2)
        clear
        emby_close_6908_port
        return_menu "main_xiaoya_all_emby_other_features"
        ;;
    0)
        clear
        main_xiaoya_all_emby
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-2]'
        main_xiaoya_all_emby_other_features
        ;;
    esac

}

function main_xiaoya_all_emby() {

    local show_main_xiaoya_all_emby
    show_main_xiaoya_all_emby=false
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Emby全家桶${Font}\n"
    echo -e "${Yellow}注意：当前 Emby 全家桶要求 Emby 容器版本不低于 4.9.0.42${Font}"
    echo -e "${Yellow}如果您的版本低于 4.9.0.42 请使用 菜单2-6 一键升级版本${Font}"
    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        local container_status
        container_status=$(docker inspect --format='{{.State.Status}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)")
        case "${container_status}" in
        "running")
            echo
            show_main_xiaoya_all_emby=true
            ;;
        *)
            echo -e "\n${Red}警告：您的小雅容器未正常启动，请先检查小雅容器后再安装全家桶${Font}\n"
            ;;
        esac
    else
        echo -e "${Red}\n警告：您未安装小雅容器，请先安装小雅容器后再安装全家桶${Font}\n"
    fi
    echo -ne "${INFO} 界面加载中...${Font}\r"
    if [ "${show_main_xiaoya_all_emby}" == "true" ]; then
        echo -e "1、一键安装Emby全家桶
2、下载/解压 元数据
3、安装 Emby（可选择版本）
4、图形化编辑 emby_config.txt
5、安装/更新/卸载 小雅元数据定时爬虫          当前状态：$(judgment_container xiaoya-emd)
6、一键升级 Emby 容器（可选择镜像版本）
7、卸载 Emby 全家桶
8、其他功能"
    fi
    echo -e "0、返回上级          "
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    if [ "${show_main_xiaoya_all_emby}" == "true" ]; then
        read -erp "请输入数字 [0-8]:" num
    else
        read -erp "请输入数字 [0]:" num
    fi
    case "$num" in
    1)
        clear
        download_unzip_xiaoya_all_emby
        install_emby_xiaoya_all_emby
        XIAOYA_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
        if [ -s "${XIAOYA_CONFIG_DIR}/emby_config.txt" ]; then
            # shellcheck disable=SC1091
            source "${XIAOYA_CONFIG_DIR}/emby_config.txt"
            if [ -n "${resilio}" ]; then
                WARN "Resilio-Sync 已弃用，默认使用 小雅元数据定时爬虫"
            fi
        fi
        while true; do
            INFO "是否安装 小雅元数据定时爬虫 [Y/n]（默认 Y）"
            read -erp "INSTALL:" xiaoya_emd_install
            [[ -z "${xiaoya_emd_install}" ]] && xiaoya_emd_install="y"
            if [[ ${xiaoya_emd_install} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${xiaoya_emd_install} == [Yy] ]]; then
            install_xiaoya_emd
        fi
        INFO "Emby 全家桶安装完成！ "
        INFO "浏览器访问 Emby 服务：${Sky_Blue}http://ip:2345${Font}, 默认用户密码: ${Sky_Blue}xiaoya/1234${Font}"
        return_menu "main_xiaoya_all_emby"
        ;;
    2)
        clear
        main_download_unzip_xiaoya_emby "1"
        ;;
    3)
        clear
        get_config_dir
        get_media_dir
        install_emby_xiaoya_all_emby
        return_menu "main_xiaoya_all_emby"
        ;;
    4)
        clear
        get_config_dir
        bash -c "$(curl -sLk https://ddsrem.com/xiaoya/emby_config_editor.sh)" -s ${CONFIG_DIR}
        main_xiaoya_all_emby
        ;;
    5)
        clear
        main_xiaoya_emd
        ;;
    6)
        clear
        oneclick_upgrade_emby
        return_menu "main_xiaoya_all_emby"
        ;;
    7)
        clear
        uninstall_xiaoya_all_emby
        ;;
    8)
        clear
        main_xiaoya_all_emby_other_features
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-8]'
        main_xiaoya_all_emby
        ;;
    esac

}

function xiaoyahelper_install_check() {
    local URL="$1"
    if bash -c "$(curl --insecure -fsSL -k ${URL} | tail -n +2)" -s "${MODE}" ${TG_CHOOSE}; then
        if docker container inspect xiaoyakeeper > /dev/null 2>&1; then
            INFO "安装完成！"
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

function install_xiaoyahelper() {

    INFO "选择模式：[3/5]（默认 3）"
    INFO "模式3: 定时运行小雅转存清理并升级小雅镜像"
    INFO "模式5: 只要产生了播放缓存一分钟内立即清理。签到和定时升级同模式3"
    read -erp "MODE:" MODE
    [[ -z "${MODE}" ]] && MODE="3"

    while true; do
        INFO "是否使用Telegram通知 [Y/n]（默认 n 不使用）"
        read -erp "TG:" TG
        [[ -z "${TG}" ]] && TG="n"
        if [[ ${TG} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${TG} == [Yy] ]]; then
        TG_CHOOSE="-tg"
    fi

    docker_pull "ddsderek/xiaoyakeeper:latest"

    XIAOYAHELPER_URL="https://xiaoyahelper.ddsrem.com/aliyun_clear.sh"
    if xiaoyahelper_install_check "${XIAOYAHELPER_URL}"; then
        return 0
    fi
    XIAOYAHELPER_URL="https://xiaoyahelper.zengge99.eu.org/aliyun_clear.sh"
    if xiaoyahelper_install_check "${XIAOYAHELPER_URL}"; then
        return 0
    fi
    ERROR "安装失败！"
    return 1

}

function once_xiaoyahelper() {

    while true; do
        INFO "是否使用Telegram通知 [Y/n]（默认 n 不使用）"
        read -erp "TG:" TG
        [[ -z "${TG}" ]] && TG="n"
        if [[ ${TG} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done
    if [[ ${TG} == [Yy] ]]; then
        TG_CHOOSE="-tg"
    fi

    XIAOYAHELPER_URL="https://xiaoyahelper.ddsrem.com/aliyun_clear.sh"
    if bash -c "$(curl --insecure -fsSL -k ${XIAOYAHELPER_URL} | tail -n +2)" -s 1 ${TG_CHOOSE}; then
        INFO "运行完成！"
    else
        XIAOYAHELPER_URL="https://xiaoyahelper.zengge99.eu.org/aliyun_clear.sh"
        if bash -c "$(curl --insecure -fsSL -k ${XIAOYAHELPER_URL} | tail -n +2)" -s 1 ${TG_CHOOSE}; then
            INFO "运行完成！"
        else
            ERROR "运行失败！"
            exit 1
        fi
    fi
}

function uninstall_xiaoyahelper() {

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
        echo -en "即将开始卸载小雅助手（xiaoyahelper）${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop xiaoyakeeper
    docker rm xiaoyakeeper
    docker rmi dockerproxy.com/library/alpine:3.18.2 > /dev/null 2>&1
    docker rmi alpine:3.18.2 > /dev/null 2>&1
    docker rmi ddsderek/xiaoyakeeper:latest

    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
            for file in "${OLD_CONFIG_DIR}/mycheckintoken.txt" "${OLD_CONFIG_DIR}/mycmd.txt" "${OLD_CONFIG_DIR}/myruntime.txt"; do
                if [ -f "$file" ]; then
                    rm -f "$file"
                fi
            done
        fi
        rm -f ${OLD_CONFIG_DIR}/*json
    fi

    INFO "小雅助手（xiaoyahelper）卸载成功！"

}

function main_xiaoyahelper() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅助手（xiaoyahelper）${Font}\n"
    echo -e "1、安装/更新"
    echo -e "2、一次性运行"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_xiaoyahelper
        return_menu "main_xiaoyahelper"
        ;;
    2)
        clear
        once_xiaoyahelper
        ;;
    3)
        clear
        uninstall_xiaoyahelper
        return_menu "main_xiaoyahelper"
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_xiaoyahelper
        ;;
    esac

}

function install_xiaoya_alist_tvbox() {

    local DEFAULT_CONFIG_DIR
    while true; do
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_tvbox_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_tvbox_config_dir.txt)
            INFO "已读取小雅Alist-TVBox配置文件路径：${OLD_CONFIG_DIR} (默认不更改回车继续，如果需要更改请输入新路径)"
            read -erp "CONFIG_DIR:" CONFIG_DIR
            [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR=${OLD_CONFIG_DIR}
        else
            DEFAULT_CONFIG_DIR="$(get_path "xiaoya_alist_config_dir")"
            INFO "请输入配置文件目录（默认 ${DEFAULT_CONFIG_DIR} ）"
            read -erp "CONFIG_DIR:" CONFIG_DIR
            [[ -z "${CONFIG_DIR}" ]] && CONFIG_DIR="${DEFAULT_CONFIG_DIR}"
            touch ${DDSREM_CONFIG_DIR}/xiaoya_alist_tvbox_config_dir.txt
        fi
        if check_path "${CONFIG_DIR}"; then
            echo "${CONFIG_DIR}" > "${DDSREM_CONFIG_DIR}/xiaoya_alist_tvbox_config_dir.txt"
            INFO "目录合法性检测通过！"
            break
        else
            ERROR "非合法目录，请重新输入！"
        fi
    done

    while true; do
        INFO "请输入Alist端口（默认 5344 ）"
        read -erp "ALIST_PORT:" ALIST_PORT
        [[ -z "${ALIST_PORT}" ]] && ALIST_PORT="5344"
        if check_port "${ALIST_PORT}"; then
            break
        else
            ERROR "${ALIST_PORT} 此端口被占用，请输入其他端口！"
        fi
    done

    while true; do
        INFO "请输入后台管理端口（默认 4567 ）"
        read -erp "HT_PORT:" HT_PORT
        [[ -z "${HT_PORT}" ]] && HT_PORT="4567"
        if check_port "${HT_PORT}"; then
            break
        else
            ERROR "${HT_PORT} 此端口被占用，请输入其他端口！"
        fi
    done

    INFO "请输入内存限制（默认 -Xmx512M ）"
    read -erp "MEM_OPT:" MEM_OPT
    [[ -z "${MEM_OPT}" ]] && MEM_OPT="-Xmx512M"

    INFO "您的CPU架构：${CPU_ARCH}"
    if [ "${DOCKER_ARCH}" == "linux/amd64" ]; then
        while true; do
            INFO "是否使用内存优化版镜像 [Y/n]（默认 n 不使用）"
            read -erp "Native:" choose_native
            [[ -z "${choose_native}" ]] && choose_native="n"
            if [[ ${choose_native} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${choose_native} == [Yy] ]]; then
            __choose_native="native"
        else
            __choose_native="latest"
        fi
    elif [ "${DOCKER_ARCH}" == "linux/arm64/v8" ]; then
        __choose_native="latest"
    else
        ERROR "Xiaoya-TVBox 目前只支持 amd64 和 arm64 架构，你的架构是：$CPU_ARCH"
        exit 1
    fi

    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA
        RETURN_DATA="$(data_crep "r" "install_xiaoya_alist_tvbox")"
        if [ "${RETURN_DATA}" == "None" ]; then
            INFO "请输入其他参数（默认 无 ）"
            read -erp "Extra parameters:" extra_parameters
        else
            INFO "已读取您上次设置的参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
        fi
        extra_parameters=$(data_crep "w" "install_xiaoya_alist_tvbox")
    fi

    if ls ${CONFIG_DIR}/*.txt 1> /dev/null 2>&1; then
        INFO "备份小雅配置数据中..."
        mkdir -p ${CONFIG_DIR}/xiaoya_backup
        cp -rf ${CONFIG_DIR}/*.txt ${CONFIG_DIR}/xiaoya_backup
        INFO "完成备份小雅配置数据！"
        INFO "备份数据路径：${CONFIG_DIR}/xiaoya_backup"
    fi

    if ! grep "access.mypikpak.com" ${HOSTS_FILE_PATH}; then
        echo -e "127.0.0.1\taccess.mypikpak.com" >> ${HOSTS_FILE_PATH}
    fi

    docker_pull "haroldli/xiaoya-tvbox:${__choose_native}"

    if [ -n "${extra_parameters}" ]; then
        docker run -itd \
            -p "${HT_PORT}":4567 \
            -p "${ALIST_PORT}":80 \
            -e ALIST_PORT="${ALIST_PORT}" \
            -e MEM_OPT="${MEM_OPT}" \
            -e TZ=Asia/Shanghai \
            -v "${CONFIG_DIR}:/data" \
            ${extra_parameters} \
            --restart=always \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)" \
            haroldli/xiaoya-tvbox:${__choose_native}
    else
        docker run -itd \
            -p "${HT_PORT}":4567 \
            -p "${ALIST_PORT}":80 \
            -e ALIST_PORT="${ALIST_PORT}" \
            -e MEM_OPT="${MEM_OPT}" \
            -e TZ=Asia/Shanghai \
            -v "${CONFIG_DIR}:/data" \
            --restart=always \
            --name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)" \
            haroldli/xiaoya-tvbox:${__choose_native}
    fi

    INFO "安装完成！"
    INFO "浏览器访问 小雅Alist-TVBox 服务：${Sky_Blue}http://ip:${HT_PORT}${Font}, 默认用户密码: ${Sky_Blue}admin/admin${Font}"

}

function update_xiaoya_alist_tvbox() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新小雅Alist-TVBox${Blue} $i ${Font}\r"
        sleep 1
    done
    VOLUMES="$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{println .}}{{end}}{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)" | cut -d' ' -f2 | awk 'NF' | tr '\n' ' ')"
    # shellcheck disable=SC2034
    container_update_extra_command="sedsh '/\/opt\/atv\/data/d; \/opt\/alist\/data/d' "/tmp/container_update_$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)""
    container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)"
    docker volume rm ${VOLUMES}

}

function uninstall_xiaoya_alist_tvbox() {

    local CLEAN_CONFIG IMAGE_NAME VOLUMES
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
        echo -en "即将开始卸载小雅Alist-TVBox${Blue} $i ${Font}\r"
        sleep 1
    done
    IMAGE_NAME="$(docker inspect --format='{{.Config.Image}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)")"
    VOLUMES="$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{println .}}{{end}}{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)" | cut -d' ' -f2 | awk 'NF' | tr '\n' ' ')"
    docker stop "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)"
    docker rm "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)"
    docker rmi "${IMAGE_NAME}"
    docker volume rm ${VOLUMES}
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_tvbox_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_tvbox_config_dir.txt)
            for dir in "${OLD_CONFIG_DIR}"/*/; do
                rm -rf "$dir"
            done
            rm -rf ${OLD_CONFIG_DIR}/*.db
        fi
    fi
    INFO "小雅Alist-TVBox卸载成功！"

}

function main_xiaoya_alist_tvbox() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}小雅Alist-TVBox${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_xiaoya_alist_tvbox
        return_menu "main_xiaoya_alist_tvbox"
        ;;
    2)
        clear
        update_xiaoya_alist_tvbox
        return_menu "main_xiaoya_alist_tvbox"
        ;;
    3)
        clear
        uninstall_xiaoya_alist_tvbox
        return_menu "main_xiaoya_alist_tvbox"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_xiaoya_alist_tvbox
        ;;
    esac

}

function install_xiaoya_115_cleaner() {

    local config_dir
    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
    fi
    if [ -z "${config_dir}" ]; then
        get_config_dir
        config_dir=${CONFIG_DIR}
    fi

    settings_115_cookie "${config_dir}"

    if [ ! -f "${config_dir}/115_key.txt" ]; then
        touch ${config_dir}/115_key.txt
        INFO "输入你的 115 回收站密码"
        INFO "注意：此选项为必填项，如果您关闭了回收站密码请手动开启并输入！"
        read -erp "Key:" password_key
        echo -e "${password_key}" > ${config_dir}/115_key.txt
    fi

    while true; do
        INFO "请选择 115 Cleaner 清理模式（默认 1）"
        INFO "1：标准模式，清空 /我的接收 下面的文件并同时清理回收站的对应文件"
        INFO "2：只清空 115云盘 回收站文件，不会清理其他地方的文件"
        INFO "3：清空 /我的接收 下面的文件并同时清空回收站"
        read -erp "CHOOSE_RUN_MODE:" CHOOSE_RUN_MODE
        [[ -z "${CHOOSE_RUN_MODE}" ]] && CHOOSE_RUN_MODE="1"
        if [ -f "${config_dir}/115_cleaner_all_recyclebin.txt" ]; then
            rm -rf "${config_dir}/115_cleaner_all_recyclebin.txt"
        fi
        if [ -f "${config_dir}/115_cleaner_only_recyclebin.txt" ]; then
            rm -rf "${config_dir}/115_cleaner_only_recyclebin.txt"
        fi
        case ${CHOOSE_RUN_MODE} in
        1)
            break
            ;;
        2)
            touch "${config_dir}/115_cleaner_only_recyclebin.txt"
            break
            ;;
        3)
            touch "${config_dir}/115_cleaner_all_recyclebin.txt"
            break
            ;;
        *)
            ERROR "输入无效，请重新选择"
            ;;
        esac
    done

    if [ -f "${config_dir}/ali2115.txt" ]; then
        while true; do
            INFO "是否将 ali2115 转存文件交由 115 Cleaner 清理 [Y/n]（默认 y）"
            read -erp "ali2115:" choose_ali2115
            [[ -z "${choose_ali2115}" ]] && choose_ali2115="y"
            if [[ ${choose_ali2115} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
    fi
    if [[ ${choose_ali2115} == [Yy] ]]; then
        touch "${config_dir}/115_cleaner_auto_set_ali2115.txt"
    fi

    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA
        RETURN_DATA="$(data_crep "r" "install_xiaoya_115_cleaner")"
        if [ "${RETURN_DATA}" == "None" ]; then
            INFO "请输入其他参数（默认 无 ）"
            read -erp "Extra parameters:" extra_parameters
        else
            INFO "已读取您上次设置的参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
        fi
        extra_parameters=$(data_crep "w" "install_xiaoya_115_cleaner")
    fi

    docker_pull "ddsderek/xiaoya-115cleaner:latest"

    docker run -d \
        --name=xiaoya-115cleaner \
        -v "${config_dir}:/data" \
        --net=host \
        -e TZ=Asia/Shanghai \
        ${extra_parameters} \
        --restart=always \
        ddsderek/xiaoya-115cleaner:latest

    INFO "安装完成！"

}

function update_xiaoya_115_cleaner() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新115清理助手${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update xiaoya-115cleaner

}

function uninstall_xiaoya_115_cleaner() {

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
        echo -en "即将开始卸载115清理助手${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop xiaoya-115cleaner
    docker rm xiaoya-115cleaner
    docker rmi ddsderek/xiaoya-115cleaner:latest
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
            for file in "${OLD_CONFIG_DIR}/115_cleaner_only_recyclebin.txt" "${OLD_CONFIG_DIR}/115_cleaner_all_recyclebin.txt" "${OLD_CONFIG_DIR}/115_key.txt"; do
                if [ -f "$file" ]; then
                    rm -f "$file"
                fi
            done
        fi
    fi
    INFO "115清理助手卸载成功！"

}

function main_xiaoya_115_cleaner() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}115 清理助手${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_xiaoya_115_cleaner
        return_menu "main_xiaoya_115_cleaner"
        ;;
    2)
        clear
        update_xiaoya_115_cleaner
        return_menu "main_xiaoya_115_cleaner"
        ;;
    3)
        clear
        uninstall_xiaoya_115_cleaner
        return_menu "main_xiaoya_115_cleaner"
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_xiaoya_115_cleaner
        ;;
    esac

}

function install_xiaoya_proxy() {

    local config_dir
    if docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
        config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
    else
        ERROR "请先安装小雅容器后再使用 Xiaoya Proxy！"
        exit 1
    fi
    if [ -z "${config_dir}" ]; then
        get_config_dir
        config_dir=${CONFIG_DIR}
    fi
    INFO "小雅配置文件目录：${config_dir}"
    container_run_extra_parameters=$(cat ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt)
    if [ "${container_run_extra_parameters}" == "true" ]; then
        local RETURN_DATA
        RETURN_DATA="$(data_crep "r" "install_xiaoya_proxy")"
        if [ "${RETURN_DATA}" == "None" ]; then
            INFO "请输入其他参数（默认 无 ）"
            read -erp "Extra parameters:" extra_parameters
        else
            INFO "已读取您上次设置的参数：${RETURN_DATA} (默认不更改回车继续，如果需要更改请输入新参数)"
            read -erp "Extra parameters:" extra_parameters
            [[ -z "${extra_parameters}" ]] && extra_parameters=${RETURN_DATA}
        fi
        extra_parameters=$(data_crep "w" "install_xiaoya_proxy")
    fi
    if ! check_port "9988"; then
        ERROR "9988 端口被占用，请关闭占用此端口的程序！"
        exit 1
    fi
    docker_pull "ddsderek/xiaoya-proxy:latest"
    # shellcheck disable=SC2046
    docker run -d \
        --name=xiaoya-proxy \
        --restart=always \
        $(get_default_network "xiaoya-proxy") \
        ${extra_parameters} \
        -e TZ=Asia/Shanghai \
        ddsderek/xiaoya-proxy:latest
    if [[ "${OSNAME}" = "macos" ]]; then
        local_ip=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
    else
        local_ip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
    fi
    if [ -z "${local_ip}" ]; then
        WARN "请手动配置 ${config_dir}/xiaoya_proxy.txt 文件，内容为 http://小雅服务器IP:9988"
    else
        INFO "本机IP：${local_ip}"
        echo "http://${local_ip}:9988" > ${config_dir}/xiaoya_proxy.txt
        INFO "xiaoya_proxy.txt 配置完成！"
    fi
    docker restart "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    wait_xiaoya_start
    INFO "安装完成！"

}

function update_xiaoya_proxy() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新 Xiaoya Proxy${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update xiaoya-proxy

}

function uninstall_xiaoya_proxy() {

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
        echo -en "即将开始卸载 Xiaoya Proxy${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop xiaoya-proxy
    docker rm xiaoya-proxy
    docker rmi ddsderek/xiaoya-proxy:latest
    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        INFO "清理配置文件..."
        if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt ]; then
            OLD_CONFIG_DIR=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)
            if [ -f "${OLD_CONFIG_DIR}/xiaoya_proxy.txt" ]; then
                rm -f "${OLD_CONFIG_DIR}/xiaoya_proxy.txt"
            fi
        fi
    fi
    INFO "Xiaoya Proxy 卸载成功！"

}

function main_xiaoya_proxy() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}Xiaoya Proxy${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_xiaoya_proxy
        return_menu "main_xiaoya_proxy"
        ;;
    2)
        clear
        update_xiaoya_proxy
        return_menu "main_xiaoya_proxy"
        ;;
    3)
        clear
        uninstall_xiaoya_proxy
        return_menu "main_xiaoya_proxy"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_xiaoya_proxy
        ;;
    esac

}

function install_xiaoya_aliyuntvtoken_connector() {

    CONFIG_DIR=$1

    if [ ! -f "${CONFIG_DIR}/open_tv_token_url.txt" ]; then
        INFO "当前未配置 阿里云盘 TV Token，开始进入 TV Token 配置流程..."
        qrocde_common "阿里云盘 TV Token" "${CONFIG_DIR}" "/aliyuntvtoken/alitoken2.py"
    else
        INFO "阿里云盘 TV Token 当前已配置！"
    fi

    if ! check_port "34278"; then
        ERROR "34278 端口被占用，请关闭占用此端口的程序！"
        exit 1
    fi

    docker_pull "ddsderek/xiaoya-glue:aliyuntvtoken_connector"

    # shellcheck disable=SC2046
    docker run -d \
        $(get_default_network "xiaoya-aliyuntvtoken_connector") \
        --name=xiaoya-aliyuntvtoken_connector \
        --restart=always \
        ddsderek/xiaoya-glue:aliyuntvtoken_connector

    sleep 2

    get_docker0_url
    local xiaoya_name aliyuntvtoken_connector_addr local_ip xiaoya_running
    xiaoya_name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    xiaoya_running=false
    if docker container inspect "${xiaoya_name}" > /dev/null 2>&1; then
        case "$(docker inspect --format='{{.State.Status}}' "${xiaoya_name}")" in
        "running")
            xiaoya_running=true
            ;;
        esac
    fi
    function set_local_ip() {
        if [[ "${OSNAME}" = "macos" ]]; then
            local_ip=$(ifconfig "$(route -n get default | grep interface | awk -F ':' '{print$2}' | awk '{$1=$1};1')" | grep 'inet ' | awk '{print$2}')
        else
            local_ip=$(ip address | grep inet | grep -v 172.17 | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's/addr://' | head -n1 | cut -f1 -d"/")
        fi
        if [ -z "${local_ip}" ]; then
            WARN "请手动配置 ${CONFIG_DIR}/open_tv_token_url.txt 文件，内容为 http://小雅服务器IP:34278/oauth/alipan/token"
        else
            INFO "本机IP：${local_ip}"
            aliyuntvtoken_connector_addr="http://${local_ip}:34278/oauth/alipan/token"
        fi
    }
    if [ "${xiaoya_running}" == "true" ]; then
        if docker exec -it "${xiaoya_name}" curl -siL -m 10 http://127.0.0.1:34278/oauth/alipan/token | grep 405; then
            aliyuntvtoken_connector_addr="http://127.0.0.1:34278/oauth/alipan/token"
        elif docker exec -it "${xiaoya_name}" curl -siL -m 10 http://${docker0}:34278/oauth/alipan/token | grep 405; then
            aliyuntvtoken_connector_addr="http://${docker0}:34278/oauth/alipan/token"
        else
            set_local_ip
        fi
    else
        set_local_ip
    fi
    if [ -n "${aliyuntvtoken_connector_addr}" ]; then
        INFO "本地阿里云盘 TV Token 鉴权接口地址：${aliyuntvtoken_connector_addr}"
        echo "${aliyuntvtoken_connector_addr}" > "${CONFIG_DIR}/open_tv_token_url.txt"
    fi

    if docker container inspect "${xiaoya_name}" > /dev/null 2>&1; then
        docker restart "${xiaoya_name}"
        sleep 5
        wait_xiaoya_start
    fi

    INFO "安装完成！"

}

function update_xiaoya_aliyuntvtoken_connector() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新 xiaoya-aliyuntvtoken_connector${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update xiaoya-aliyuntvtoken_connector

}

function uninstall_xiaoya_aliyuntvtoken_connector() {

    while true; do
        INFO "是否停止使用 阿里云盘 TV Token 配置 [Y/n]（默认 n）"
        read -erp "Use_TV_Token:" USE_TV_TOKEN
        [[ -z "${USE_TV_TOKEN}" ]] && USE_TV_TOKEN="n"
        if [[ ${USE_TV_TOKEN} == [YyNn] ]]; then
            break
        else
            ERROR "非法输入，请输入 [Y/n]"
        fi
    done

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始卸载 xiaoya-aliyuntvtoken_connector${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop xiaoya-aliyuntvtoken_connector
    docker rm xiaoya-aliyuntvtoken_connector
    docker rmi ddsderek/xiaoya-glue:aliyuntvtoken_connector

    local xiaoya_name config_dir
    xiaoya_name="$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
    if docker container inspect "${xiaoya_name}" > /dev/null 2>&1; then
        config_dir="$(docker inspect -f '{{ range .Mounts }}{{ if eq .Destination "/data" }}{{ .Source }}{{ end }}{{ end }}' "${xiaoya_name}")"
    elif [ -f "${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt" ]; then
        config_dir="$(cat ${DDSREM_CONFIG_DIR}/xiaoya_alist_config_dir.txt)"
    else
        get_config_dir
        config_dir="${CONFIG_DIR}"
    fi
    INFO "小雅容器配置目录：${config_dir}"

    if [[ ${USE_TV_TOKEN} == [Yy] ]]; then
        rm -f "${config_dir}/open_tv_token_url.txt"
        rm -f "${config_dir}/myopentoken.txt"
        while true; do
            INFO "是否配置阿里云盘 Open Token（myopentoken文件） [Y/n]（默认 y）"
            read -erp "Set_Open_Token:" SET_OPEN_TOKEN
            [[ -z "${SET_OPEN_TOKEN}" ]] && SET_OPEN_TOKEN="y"
            if [[ ${SET_OPEN_TOKEN} == [YyNn] ]]; then
                break
            else
                ERROR "非法输入，请输入 [Y/n]"
            fi
        done
        if [[ ${SET_OPEN_TOKEN} == [Yy] ]]; then
            settings_aliyunpan_opentoken "${config_dir}" force
        fi
    else
        INFO "切换使用公共鉴权接口：https://www.voicehub.top/api/v1/oauth/alipan/token"
        echo "https://www.voicehub.top/api/v1/oauth/alipan/token" > "${config_dir}/open_tv_token_url.txt"
    fi

    if docker container inspect "${xiaoya_name}" > /dev/null 2>&1; then
        docker restart "${xiaoya_name}"
        sleep 5
        wait_xiaoya_start
    fi

    INFO "xiaoya-aliyuntvtoken_connector 卸载成功！"

}

function main_xiaoya_aliyuntvtoken_connector() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}阿里云盘 TV Token 令牌刷新接口（xiaoya-aliyuntvtoken_connector）${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        get_config_dir
        install_xiaoya_aliyuntvtoken_connector "${CONFIG_DIR}"
        return_menu "main_xiaoya_aliyuntvtoken_connector"
        ;;
    2)
        clear
        update_xiaoya_aliyuntvtoken_connector
        return_menu "main_xiaoya_aliyuntvtoken_connector"
        ;;
    3)
        clear
        uninstall_xiaoya_aliyuntvtoken_connector
        return_menu "main_xiaoya_aliyuntvtoken_connector"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_xiaoya_aliyuntvtoken_connector
        ;;
    esac

}

function install_lrcapi() {

    INFO "开始安装 LrcAPI"
    if ! check_port "28883"; then
        ERROR "28883 端口被占用，请关闭占用此端口的程序！"
        exit 1
    fi
    docker_pull "hisatri/lrcapi:latest"
    docker run -d \
        -p 28883:28883 \
        --name=lrcapi \
        -e "API_AUTH=1234" \
        hisatri/lrcapi:latest
    INFO "安装完成！"
    INFO "LrcAPI API地址：${Sky_Blue}http://ip:28883${Font}"
    INFO "LrcAPI API密码：${Sky_Blue}1234${Font}"

}

function update_lrcapi() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始更新 LrcAPI${Blue} $i ${Font}\r"
        sleep 1
    done
    container_update lrcapi

}

function uninstall_lrcapi() {

    for i in $(seq -w 3 -1 0); do
        echo -en "即将开始卸载 LrcAPI${Blue} $i ${Font}\r"
        sleep 1
    done
    docker stop lrcapi
    docker rm lrcapi
    docker rmi hisatri/lrcapi:latest
    INFO "LrcAPI 卸载成功！"

}

function main_lrcapi() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}LrcAPI${Font}\n"
    echo -e "1、安装"
    echo -e "2、更新"
    echo -e "3、卸载"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-3]:" num
    case "$num" in
    1)
        clear
        install_lrcapi
        return_menu "main_lrcapi"
        ;;
    2)
        clear
        update_lrcapi
        return_menu "main_lrcapi"
        ;;
    3)
        clear
        uninstall_lrcapi
        return_menu "main_lrcapi"
        ;;
    0)
        clear
        main_other_tools
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-3]'
        main_lrcapi
        ;;
    esac

}

function init_container_name() {

    if [ ! -d ${DDSREM_CONFIG_DIR}/container_name ]; then
        mkdir -p ${DDSREM_CONFIG_DIR}/container_name
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt ]; then
        xiaoya_alist_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)
    else
        echo 'xiaoya' > ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt
        xiaoya_alist_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt ]; then
        xiaoya_emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)
    else
        echo 'emby' > ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt
        xiaoya_emby_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_emby_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt ]; then
        xiaoya_jellyfin_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)
    else
        echo 'jellyfin' > ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt
        xiaoya_jellyfin_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_jellyfin_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt ]; then
        xiaoya_resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)
    else
        echo 'resilio' > ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt
        xiaoya_resilio_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_resilio_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt ]; then
        xiaoya_tvbox_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)
    else
        echo 'xiaoya-tvbox' > ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt
        xiaoya_tvbox_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_tvbox_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt ]; then
        xiaoya_onelist_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt)
    else
        echo 'onelist' > ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt
        xiaoya_onelist_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_onelist_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt ]; then
        portainer_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt)
    else
        echo 'portainer' > ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt
        portainer_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/portainer_name.txt)
    fi

    if [ -f ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt ]; then
        auto_symlink_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)
    else
        echo 'auto_symlink' > ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt
        auto_symlink_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/auto_symlink_name.txt)
    fi

}

function change_container_name() {

    INFO "请输入新的容器名称"
    read -erp "Container name:" container_name
    [[ -z "${container_name}" ]] && container_name=$(cat ${DDSREM_CONFIG_DIR}/container_name/"${1}".txt)
    echo "${container_name}" > ${DDSREM_CONFIG_DIR}/container_name/"${1}".txt
    clear
    container_name_settings

}

function container_name_settings() {

    init_container_name

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}容器名称设置${Font}\n"
    echo -e "1、更改 小雅 容器名                 （当前：${Green}${xiaoya_alist_name}${Font}）"
    echo -e "2、更改 小雅Emby 容器名             （当前：${Green}${xiaoya_emby_name}${Font}）"
    echo -e "3、更改 Resilio 容器名              （当前：${Green}${xiaoya_resilio_name}${Font}）"
    echo -e "4、更改 小雅Alist-TVBox 容器名      （当前：${Green}${xiaoya_tvbox_name}${Font}）"
    echo -e "5、更改 Onelist 容器名              （当前：${Green}${xiaoya_onelist_name}${Font}）"
    echo -e "6、更改 Portainer 容器名            （当前：${Green}${portainer_name}${Font}）"
    echo -e "7、更改 Auto_Symlink 容器名         （当前：${Green}${auto_symlink_name}${Font}）"
    echo -e "8、更改 Jellyfin 容器名             （当前：${Green}${xiaoya_jellyfin_name}${Font}）"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-8]:" num
    case "$num" in
    1)
        change_container_name "xiaoya_alist_name"
        ;;
    2)
        change_container_name "xiaoya_emby_name"
        ;;
    3)
        change_container_name "xiaoya_resilio_name"
        ;;
    4)
        change_container_name "xiaoya_tvbox_name"
        ;;
    5)
        change_container_name "xiaoya_onelist_name"
        ;;
    6)
        change_container_name "portainer_name"
        ;;
    7)
        change_container_name "auto_symlink_name"
        ;;
    8)
        change_container_name "xiaoya_jellyfin_name"
        ;;
    0)
        clear
        main_advanced_configuration
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-8]'
        container_name_settings
        ;;
    esac

}

function reset_script_configuration() {

    INFO "是否${Red}删除所有脚本配置文件${Font} [Y/n]（默认 Y 删除）"
    read -erp "Clean config:" CLEAN_CONFIG
    [[ -z "${CLEAN_CONFIG}" ]] && CLEAN_CONFIG="y"

    if [[ ${CLEAN_CONFIG} == [Yy] ]]; then
        for i in $(seq -w 3 -1 0); do
            echo -en "即将开始清理配置文件${Blue} $i ${Font}\r"
            sleep 1
        done
        FILES_TO_REMOVE=(
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
        for file in "${FILES_TO_REMOVE[@]}"; do
            rm -f ${DDSREM_CONFIG_DIR}/$file
        done
        rm -rf \
            ${DDSREM_CONFIG_DIR}/container_name \
            ${DDSREM_CONFIG_DIR}/data_crep
        INFO "清理完成！"

        for i in $(seq -w 3 -1 0); do
            echo -en "即将返回主界面并重新生成默认配置${Blue} $i ${Font}\r"
            sleep 1
        done

        first_init
        clear
        main_return
    else
        return 0
    fi

}

function main_advanced_configuration() {

    __container_run_extra_parameters=$(cat "${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt")
    if [ "${__container_run_extra_parameters}" == "true" ]; then
        _container_run_extra_parameters="${Green}开启${Font}"
    elif [ "${__container_run_extra_parameters}" == "false" ]; then
        _container_run_extra_parameters="${Red}关闭${Font}"
    else
        _container_run_extra_parameters="${Red}错误${Font}"
    fi

    __use_host_7z_command=$(cat "${DDSREM_CONFIG_DIR}/use_host_7z_command.txt")
    if [ "${__use_host_7z_command}" == "true" ]; then
        _use_host_7z_command="${Green}开启${Font}"
    elif [ "${__use_host_7z_command}" == "false" ]; then
        _use_host_7z_command="${Red}关闭${Font}"
    else
        _use_host_7z_command="${Red}错误${Font}"
    fi

    __disk_capacity_detection=$(cat ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt)
    if [ "${__disk_capacity_detection}" == "true" ]; then
        _disk_capacity_detection="${Green}开启${Font}"
    elif [ "${__disk_capacity_detection}" == "false" ]; then
        _disk_capacity_detection="${Red}关闭${Font}"
    else
        _disk_capacity_detection="${Red}错误${Font}"
    fi

    __xiaoya_connectivity_detection=$(cat ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt)
    if [ "${__xiaoya_connectivity_detection}" == "true" ]; then
        _xiaoya_connectivity_detection="${Green}开启${Font}"
    elif [ "${__xiaoya_connectivity_detection}" == "false" ]; then
        _xiaoya_connectivity_detection="${Red}关闭${Font}"
    else
        _xiaoya_connectivity_detection="${Red}错误${Font}"
    fi

    _default_network=$(cat "${DDSREM_CONFIG_DIR}/default_network.txt")

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}高级配置${Font}\n"
    echo -e "1、容器名称设置"
    echo -e "2、开启/关闭 容器运行额外参数添加             当前状态：${_container_run_extra_parameters}"
    echo -e "3、重置脚本配置"
    echo -e "4、开启/关闭 磁盘容量检测                     当前状态：${_disk_capacity_detection}"
    echo -e "5、开启/关闭 小雅连通性检测                   当前状态：${_xiaoya_connectivity_detection}"
    echo -e "6、Docker镜像源选择"
    echo -e "7、非可选网络模式容器默认网络模式             当前状态：${Blue}${_default_network}${Font}"
    echo -e "8、弃用菜单"
    echo -e "9、开启/关闭 使用宿主机7z命令解压             当前状态：${_use_host_7z_command}"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-9]:" num
    case "$num" in
    1)
        clear
        container_name_settings
        ;;
    2)
        if [ "${__container_run_extra_parameters}" == "false" ]; then
            echo 'true' > ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt
        else
            echo 'false' > ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt
        fi
        clear
        main_advanced_configuration
        ;;
    3)
        clear
        reset_script_configuration
        return_menu "main_advanced_configuration"
        ;;
    4)
        if [ "${__disk_capacity_detection}" == "true" ]; then
            echo 'false' > ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt
        elif [ "${__disk_capacity_detection}" == "false" ]; then
            echo 'true' > ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt
        else
            echo 'true' > ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt
        fi
        clear
        main_advanced_configuration
        ;;
    5)
        if [ "${__xiaoya_connectivity_detection}" == "true" ]; then
            echo 'false' > ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt
        elif [ "${__xiaoya_connectivity_detection}" == "false" ]; then
            echo 'true' > ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt
        else
            echo 'true' > ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt
        fi
        clear
        main_advanced_configuration
        ;;
    6)
        clear
        choose_image_mirror "main_advanced_configuration"
        ;;
    7)
        if [ "${_default_network}" == "host" ]; then
            echo 'bridge' > ${DDSREM_CONFIG_DIR}/default_network.txt
        elif [ "${_default_network}" == "bridge" ]; then
            echo 'host' > ${DDSREM_CONFIG_DIR}/default_network.txt
        else
            echo 'host' > ${DDSREM_CONFIG_DIR}/default_network.txt
        fi
        clear
        main_advanced_configuration
        ;;
    8)
        clear
        main_deprecation
        ;;
    9)
        if [ "${__use_host_7z_command}" == "false" ]; then
            echo 'true' > ${DDSREM_CONFIG_DIR}/use_host_7z_command.txt
        else
            echo 'false' > ${DDSREM_CONFIG_DIR}/use_host_7z_command.txt
        fi
        clear
        main_advanced_configuration
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-9]'
        main_advanced_configuration
        ;;
    esac

}

function main_other_tools() {

    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    echo -e "${Blue}其他工具${Font}\n"
    echo -ne "${INFO} 界面加载中...${Font}\r"
    echo -e "1、安装/更新/卸载 Portainer                       当前状态：$(judgment_container "${portainer_name}")
2、安装/更新/卸载 Auto_Symlink                    当前状态：$(judgment_container "${auto_symlink_name}")
3、安装/更新/卸载 Onelist                         当前状态：$(judgment_container "${xiaoya_onelist_name}")
4、安装/更新/卸载 Xiaoya Proxy                    当前状态：$(judgment_container xiaoya-proxy)
5、安装/更新/卸载 Xiaoya aliyuntvtoken_connector  当前状态：$(judgment_container xiaoya-aliyuntvtoken_connector)
6、安装/更新/卸载 小雅Alist-TVBox（非原版）       当前状态：$(judgment_container "${xiaoya_tvbox_name}")
7、安装/更新/卸载 LrcAPI                          当前状态：$(judgment_container "${xiaoya_tvbox_name}")"
    echo -e "8、查看系统磁盘挂载"
    echo -e "9、安装/卸载 CasaOS"
    echo -e "0、返回上级"
    echo -e "——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-9]:" num
    case "$num" in
    1)
        clear
        main_portainer
        ;;
    2)
        clear
        main_auto_symlink
        ;;
    3)
        clear
        main_onelist
        ;;
    4)
        clear
        main_xiaoya_proxy
        ;;
    5)
        clear
        main_xiaoya_aliyuntvtoken_connector
        ;;
    6)
        clear
        main_xiaoya_alist_tvbox
        ;;
    7)
        clear
        main_lrcapi
        ;;
    8)
        clear
        INFO "系统磁盘挂载情况:"
        show_disk_mount
        INFO "按任意键返回菜单"
        read -rs -n 1 -p ""
        clear
        main_other_tools
        ;;
    9)
        clear
        main_casaos
        ;;
    0)
        clear
        main_return
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-9]'
        main_other_tools
        ;;
    esac

}

function main_return() {

    local out_tips
    cat /tmp/xiaoya_alist
    echo -ne "${INFO} 主界面加载中...${Font}\r"
    if ! curl -s -o /dev/null -m 4 -w '%{time_total}' --head --request GET "$(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")" &> /dev/null; then
        if auto_choose_image_mirror; then
            out_tips="${Green}提示：已为您自动配置Docker镜像源地址为: $(cat "${DDSREM_CONFIG_DIR}/image_mirror.txt")${Font}\n"
        else
            out_tips="${Red}警告：当前环境无法访问Docker镜像仓库，请输入66进入Docker镜像源设置更改镜像源${Font}\n"
        fi
    fi
    # shellcheck disable=SC2154
    echo -e "${out_tips}1、安装/更新/卸载 小雅Alist & 账号管理        当前状态：$(judgment_container "${xiaoya_alist_name}")
2、安装/更新/卸载 小雅Emby全家桶              当前状态：$(judgment_container "${xiaoya_emby_name}")
3、安装/更新/卸载 小雅助手（xiaoyahelper）    当前状态：$(judgment_container xiaoyakeeper)
4、安装/更新/卸载 115清理助手                 当前状态：$(judgment_container xiaoya-115cleaner)
5、其他工具 | Script info: ${DATE_VERSION} OS: ${_os},${OSNAME},${is64bit}
6、高级配置 | Docker version: ${Blue}${DOCKER_VERSION}${Font} ${IP_CITY}
0、退出脚本 | Thanks: ${Sky_Blue}heiheigui,xiaoyaLiu,Harold,AI老G,monlor,Rik${Font}
——————————————————————————————————————————————————————————————————————————————————"
    read -erp "请输入数字 [0-6]:" num
    case "$num" in
    1)
        clear
        main_xiaoya_alist
        ;;
    2)
        clear
        main_xiaoya_all_emby
        ;;
    3)
        clear
        main_xiaoyahelper
        ;;
    4)
        clear
        main_xiaoya_115_cleaner
        ;;
    5)
        clear
        main_other_tools
        ;;
    6)
        clear
        main_advanced_configuration
        ;;
    66)
        clear
        choose_image_mirror "main_return"
        ;;
    fuckaliyun)
        clear
        if ! docker container inspect "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" > /dev/null 2>&1; then
            ERROR "当前未安装小雅容器，请先安装小雅容器后重试！"
            exit 1
        fi
        INFO "AliyunPan ありがとう、あなたのせいで世界は爆発する"
        config_dir="$(docker inspect --format='{{range $v,$conf := .Mounts}}{{$conf.Source}}:{{$conf.Destination}}{{$conf.Type}}~{{end}}' "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)" | tr '~' '\n' | grep bind | sed 's/bind//g' | grep ":/data$" | awk -F: '{print $1}')"
        if [ -n "${config_dir}" ]; then
            qrocde_common "阿里云盘 TV Token" "${config_dir}" "/aliyuntvtoken/alitoken2.py"
            if [ ! -f "${config_dir}/open_tv_token_url.txt" ] || [ ! -f "${config_dir}/myopentoken.txt" ]; then
                ERROR "阿里云盘 TV Token 配置失败！"
                exit 1
            fi
            if ! docker container inspect xiaoya-aliyuntvtoken_connector > /dev/null 2>&1; then
                while true; do
                    INFO "是否自建阿里云盘 TV Token 令牌刷新接口 [Y/n]（默认 Y）"
                    read -erp "INSTALL_TVTOKEN:" INSTALL_TVTOKEN
                    [[ -z "${INSTALL_TVTOKEN}" ]] && INSTALL_TVTOKEN="Y"
                    if [[ ${INSTALL_TVTOKEN} == [YyNn] ]]; then
                        break
                    else
                        ERROR "非法输入，请输入 [Y/n]"
                    fi
                done
                if [[ ${INSTALL_TVTOKEN} == [Yy] ]]; then
                    install_xiaoya_aliyuntvtoken_connector "${config_dir}"
                else
                    WARN "请手动配置 ${config_dir}/open_tv_token_url.txt 文件，内容为 TV Token 令牌刷新接口地址"
                    WARN "配置完成请手动重启小雅容器！"
                fi
            else
                INFO "开始更新小雅容器..."
                container_update "$(cat ${DDSREM_CONFIG_DIR}/container_name/xiaoya_alist_name.txt)"
            fi
        else
            ERROR "小雅配置文件目录获取失败咯！请检查小雅容器是否已创建！"
            exit 1
        fi
        return_menu "main_return"
        ;;
    0)
        clear
        exit 0
        ;;
    *)
        clear
        ERROR '请输入正确数字 [0-6]'
        main_return
        ;;
    esac
}

function first_init() {

    INFO "获取系统信息中..."
    get_os

    CPU_ARCH=$(uname -m)
    case $CPU_ARCH in
    "x86_64" | *"amd64"*)
        DOCKER_ARCH="linux/amd64"
        ;;
    "aarch64" | *"arm64"* | *"armv8"* | *"arm/v8"*)
        DOCKER_ARCH="linux/arm64/v8"
        ;;
    *)
        DOCKER_ARCH="others"
        ;;
    esac
    INFO "CPU_ARCH：${CPU_ARCH}  DOCKER_ARCH：${DOCKER_ARCH}"

    if [ -f /tmp/run_xiaoya_install_user.txt ]; then
        INFO "运行脚本的用户：$(head -n 1 /tmp/run_xiaoya_install_user.txt)"
        RUN_USER="$(head -n 1 /tmp/run_xiaoya_install_user.txt)"
        GLOBAL_PUID="$(id -u "${RUN_USER}")"
        GLOBAL_PGID="$(id -g "${RUN_USER}")"
    fi

    INFO "获取 IP 地址中..."
    CITY="$(curl -fsSL -m 10 -s http://ipinfo.io/json | sed -n 's/.*"city": *"\([^"]*\)".*/\1/p')"
    if [ -n "${CITY}" ]; then
        IP_CITY="IP City: ${Yellow}${CITY}${Font}"
        INFO "获取 IP 地址成功！"
    fi

    INFO "检查 Docker 版本"
    DOCKER_VERSION="$(docker -v | sed "s/Docker version //g" | cut -d',' -f1)"

    if [ ! -d ${DDSREM_CONFIG_DIR} ]; then
        mkdir -p ${DDSREM_CONFIG_DIR}
    fi
    # Fix https://github.com/xiaoyaDev/xiaoya-alist/commit/a246bc582393b618b564e3beca2b9e1d40800a5d 中media目录保存错误
    if [ -f /xiaoya_alist_media_dir.txt ]; then
        mv /xiaoya_alist_media_dir.txt ${DDSREM_CONFIG_DIR}
    fi
    INFO "初始化容器名称中..."
    init_container_name

    if [ ! -f ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt ]; then
        echo 'false' > ${DDSREM_CONFIG_DIR}/container_run_extra_parameters.txt
    fi

    if [ ! -f "${DDSREM_CONFIG_DIR}/use_host_7z_command.txt" ]; then
        echo 'false' > "${DDSREM_CONFIG_DIR}/use_host_7z_command.txt"
    fi

    if [ ! -f "${DDSREM_CONFIG_DIR}/auto_clean_metadata_mp4_file.txt" ]; then
        echo 'false' > "${DDSREM_CONFIG_DIR}/auto_clean_metadata_mp4_file.txt"
    fi

    if [ ! -d "${DDSREM_CONFIG_DIR}/data_crep" ]; then
        mkdir -p "${DDSREM_CONFIG_DIR}/data_crep"
    fi

    if [ ! -d "${DDSREM_CONFIG_DIR}/cache_data" ]; then
        mkdir -p "${DDSREM_CONFIG_DIR}/cache_data"
    fi

    if [ ! -f ${DDSREM_CONFIG_DIR}/data_downloader.txt ]; then
        if [ "$OSNAME" = "ugos" ] || [ "$OSNAME" = "ugos pro" ]; then
            echo 'wget' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
        else
            echo 'wget' > ${DDSREM_CONFIG_DIR}/data_downloader.txt
        fi
    fi

    if [ ! -f ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt ]; then
        echo 'true' > ${DDSREM_CONFIG_DIR}/disk_capacity_detection.txt
    fi

    if [ ! -f ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt ]; then
        echo 'true' > ${DDSREM_CONFIG_DIR}/xiaoya_connectivity_detection.txt
    fi

    if [ ! -f "${DDSREM_CONFIG_DIR}/default_network.txt" ]; then
        if [[ "${OSNAME}" = "macos" ]]; then
            echo 'bridge' > "${DDSREM_CONFIG_DIR}/default_network.txt"
        else
            echo 'host' > "${DDSREM_CONFIG_DIR}/default_network.txt"
        fi
    fi

    INFO "设置 Docker 镜像源中..."
    if [ ! -f "${DDSREM_CONFIG_DIR}/image_mirror.txt" ]; then
        if ! auto_choose_image_mirror; then
            echo 'docker.io' > ${DDSREM_CONFIG_DIR}/image_mirror.txt
        fi
    fi
    if [ ! -f "${DDSREM_CONFIG_DIR}/image_mirror_user.txt" ]; then
        touch ${DDSREM_CONFIG_DIR}/image_mirror_user.txt
    fi

    INFO "清理旧配置文件中..."
    if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_emby_url.txt ]; then
        rm -rf ${DDSREM_CONFIG_DIR}/xiaoya_emby_url.txt
    fi
    if [ -f ${DDSREM_CONFIG_DIR}/xiaoya_emby_api.txt ]; then
        rm -rf ${DDSREM_CONFIG_DIR}/xiaoya_emby_api.txt
    fi

    if [ ! -f "${DDSREM_CONFIG_DIR}/勿删_小雅周边脚本配置目录" ]; then
        touch "${DDSREM_CONFIG_DIR}/勿删_小雅周边脚本配置目录"
    fi

    if [ -f /tmp/xiaoya_alist ]; then
        rm -rf /tmp/xiaoya_alist
    fi
    if ! curl -sL https://ddsrem.com/xiaoya/xiaoya_alist -o /tmp/xiaoya_alist; then
        if ! curl -sL https://fastly.jsdelivr.net/gh/xiaoyaDev/xiaoya-alist@latest/xiaoya_alist -o /tmp/xiaoya_alist; then
            curl -sL https://raw.githubusercontent.com/xiaoyaDev/xiaoya-alist/master/xiaoya_alist -o /tmp/xiaoya_alist
            if ! grep -q 'alias xiaoya' /etc/profile; then
                echo -e "alias xiaoya='bash -c \"\$(curl -sLk https://raw.githubusercontent.com/xiaoyaDev/xiaoya-alist/master/xiaoya_alist)\"'" >> /etc/profile
            fi
        else
            if ! grep -q 'alias xiaoya' /etc/profile; then
                echo -e "alias xiaoya='bash -c \"\$(curl -sLk https://fastly.jsdelivr.net/gh/xiaoyaDev/xiaoya-alist@latest/xiaoya_alist)\"'" >> /etc/profile
            fi
        fi
    else
        if ! grep -q 'alias xiaoya' /etc/profile; then
            echo -e "alias xiaoya='bash -c \"\$(curl -sLk https://ddsrem.com/xiaoya_install.sh)\"'" >> /etc/profile
        fi
    fi
    # 兼容仓库迁移
    if grep -q 'DDS-Derek/xiaoya-alist' /etc/profile; then
        sedsh 's/DDS-Derek\/xiaoya-alist/xiaoyaDev\/xiaoya-alist/g' /etc/profile
    fi
    INFO "初始化完成！"
    sleep 1

}

function root_need() {
    if [[ $EUID -ne 0 ]] && [ "$(uname -s)" != "Darwin" ]; then
        ERROR '此脚本必须以 root 身份运行！'
        exit 1
    fi
    if [ $EUID == 0 ] && [ "$(uname -s)" == "Darwin" ]; then
        ERROR 'MacOS 运行脚本必须使用非 root 身份运行，脚本会自动提权！'
        exit 1
    fi
}

clear
INFO "初始化中，请稍等...."
root_need
if [ "$(uname -s)" == "Darwin" ]; then
    if ! command -v brew; then
        WARN "brew 未安装，脚本尝试自动安装..."
        if /bin/zsh -c "$(curl -fsSL https://gitee.com/cunkai/HomebrewCN/raw/master/Homebrew.sh)"; then
            INFO "brew 安装成功！"
        else
            ERROR "brew 安装失败，请手动安装！"
            exit 1
        fi
    fi
    if ! command -v 7z; then
        WARN "p7zip 未安装，脚本尝试自动安装..."
        if brew install p7zip; then
            INFO "p7zip 安装成功！"
        else
            ERROR "p7zip 安装失败，请手动安装！"
            exit 1
        fi
    fi
    if ! command -v docker; then
        ERROR "docker 未安装，请手动安装！"
        exit 1
    fi
    if [[ $EUID -ne 0 ]]; then
        if [ -f /tmp/xiaoya_install.sh ]; then
            rm -rf /tmp/xiaoya_install.sh
        fi
        if [ -f /tmp/run_xiaoya_install_user.txt ]; then
            rm -rf /tmp/run_xiaoya_install_user.txt
        fi
        if ! curl -sL https://ddsrem.com/xiaoya/all_in_one.sh -o /tmp/xiaoya_install.sh; then
            if ! curl -sL https://fastly.jsdelivr.net/gh/xiaoyaDev/xiaoya-alist@latest/all_in_one.sh -o /tmp/xiaoya_install.sh; then
                if ! curl -sL https://raw.githubusercontent.com/xiaoyaDev/xiaoya-alist/master/all_in_one.sh -o /tmp/xiaoya_install.sh; then
                    ERROR "脚本获取失败！"
                    exit 1
                fi
            fi
        fi
        INFO "脚本获取成功！"
        sed -i '' '/^root_need$/d' /tmp/xiaoya_install.sh
        who | sed -n "2,1p" | awk '{print $1}' > /tmp/run_xiaoya_install_user.txt
        # shellcheck disable=SC2068
        if ! sudo bash /tmp/xiaoya_install.sh $@; then
            exit 1
        fi
        exit 0
    fi
fi
if [ ! -d "/tmp/xiaoya_alist_tmp" ]; then
    mkdir -p /tmp/xiaoya_alist_tmp
fi
for file in "base" "image_mirror" "auto_symlink" "jellyfin" "portainer" "onelist" "casaos" "deprecation"; do
    if ! curl -sSLf "https://gitee.com/ddsrem/xiaoya-alist-base/raw/master/${file}.sh" -o "/tmp/xiaoya_alist_tmp/${file}.sh"; then
        ERROR "${file} 基础库获取失败！"
        ERROR "请检查是否能访问 gitee.com！"
        exit 1
    else
        source "/tmp/xiaoya_alist_tmp/${file}.sh"
        rm -f "/tmp/xiaoya_alist_tmp/${file}.sh"
        INFO "${file} 基础库加载成功！"
    fi
done
rm -rf /tmp/xiaoya_alist_tmp
first_init
clear
if [ ! "$*" ]; then
    main_return
else
    "$@"
fi
