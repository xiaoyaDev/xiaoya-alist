#!/usr/local/bin/python3
# pylint: disable=C0114

import time
import logging
import os
import threading
import sys
import argparse
import json

import qrcode
import requests
from flask import Flask, send_file, render_template, jsonify


app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
LAST_STATUS = 0
if sys.platform.startswith("win32"):
    QRCODE_DIR = "qrcode.png"
else:
    QRCODE_DIR = "/aliyunopentoken/qrcode.png"


# pylint: disable=W0603
def poll_qrcode_status(data, log_print, _api_url):
    """
    循环等待扫码
    """
    global LAST_STATUS
    retry_times = 0
    while True:
        try:
            if retry_times == 3:
                LAST_STATUS = 2
                break
            url = f"https://openapi.aliyundrive.com/oauth/qrcode/{data}/status"
            _re = requests.get(url, timeout=10)
            if _re.status_code == 200:
                _re_data = json.loads(_re.text)
                if _re_data["status"] == "LoginSuccess":
                    auth_code = _re_data["authCode"]
                    data_2 = {
                        "code": auth_code,
                        "grant_type": "authorization_code",
                        "client_id": "",
                        "client_secret": "",
                    }
                    if _api_url == "auth.xiaoya.pro":
                        _re = requests.post("http://auth.xiaoya.pro/api/ali_open/refresh", json=data_2, timeout=10)
                        opentoken_url = "http://auth.xiaoya.pro/api/ali_open/refresh"
                    else:
                        _re = requests.post(
                            "https://aliyundrive-oauth.messense.me/oauth/access_token",
                            json={
                                "grant_type": "authorization_code",
                                "code": auth_code,
                            },
                            timeout=10,
                        )
                        opentoken_url = "https://aliyundrive-oauth.messense.me/oauth/access_token"
                    if _re.status_code == 200:
                        _re_data = json.loads(_re.text)
                        refresh_token = _re_data["refresh_token"]
                        if sys.platform.startswith("win32"):
                            with open("myopentoken.txt", "w", encoding="utf-8") as f:
                                f.write(refresh_token)
                            with open("opentoken_url.txt", "w", encoding="utf-8") as f:
                                f.write(opentoken_url)
                        else:
                            with open("/data/myopentoken.txt", "w", encoding="utf-8") as f:
                                f.write(refresh_token)
                            with open("/data/opentoken_url.txt", "w", encoding="utf-8") as f:
                                f.write(opentoken_url)
                        logging.info("扫码成功, opentoken 已写入文件！")
                        LAST_STATUS = 1
                        break
                else:
                    if log_print:
                        logging.info("等待用户扫码...")
                    time.sleep(2)
            else:
                if log_print:
                    logging.info("等待用户扫码...")
                time.sleep(2)
        except Exception as e:  # pylint: disable=W0718
            logging.error("错误：%s", e)
            retry_times += 1


@app.route("/")
def index():
    """
    网页扫码首页
    """
    return render_template("index.html")


@app.route("/image")
def serve_image():
    """
    获取二维码图片
    """
    return send_file(QRCODE_DIR, mimetype="image/png")


@app.route("/status")
def status():
    """
    扫码状态获取
    """
    if LAST_STATUS == 1:
        return jsonify({"status": "success"})
    elif LAST_STATUS == 2:
        return jsonify({"status": "failure"})
    else:
        return jsonify({"status": "unknown"})


@app.route("/shutdown_server", methods=["GET"])
def shutdown():
    """
    退出进程
    """
    if os.path.isfile(QRCODE_DIR):
        os.remove(QRCODE_DIR)
    os._exit(0)


if __name__ == "__main__":
    if os.path.isfile(QRCODE_DIR):
        os.remove(QRCODE_DIR)
    parser = argparse.ArgumentParser(description="AliyunPan Open Token")
    parser.add_argument("--qrcode_mode", type=str, required=True, help="扫码模式")
    parser.add_argument("--api_url", type=str, required=True, help="API 地址")
    args = parser.parse_args()
    logging.info("二维码生成中...")
    RE_COUNT = 0
    while True:
        try:
            if RE_COUNT == 3:
                logging.error("二维码生成失败，退出进程")
                os._exit(1)
            if args.api_url == "auth.xiaoya.pro":
                re = requests.get("http://auth.xiaoya.pro/api/ali_open/qr", timeout=10)
            else:
                re = requests.post(
                    "https://aliyundrive-oauth.messense.me/oauth/authorize/qrcode",
                    json={
                        "scopes": ["user:base", "file:all:read", "file:all:write"],
                        "width": 300,
                        "height": 300,
                    },
                    timeout=10,
                )
            if re.status_code == 200:
                re_data = json.loads(re.content)
                sid = re_data["sid"]
                # pylint: disable=C0103
                qr_code_url = f"https://www.aliyundrive.com/o/oauth/authorize?sid={sid}"
                qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=5, border=4)
                qr.add_data(qr_code_url)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img.save(QRCODE_DIR)
                if os.path.isfile(QRCODE_DIR):
                    logging.info("二维码生成完成！")
                    break
            time.sleep(1)
            RE_COUNT += 1
        except Exception as e:  # pylint: disable=W0718
            logging.error("错误：%s", e)
            RE_COUNT += 1
    if args.qrcode_mode == "web":
        threading.Thread(target=poll_qrcode_status, args=(sid, True, args.api_url)).start()
        app.run(host="0.0.0.0", port=34256)
    elif args.qrcode_mode == "shell":
        threading.Thread(target=poll_qrcode_status, args=(sid, False, args.api_url)).start()
        logging.info("请打开阿里云盘扫描此二维码！")
        qr.print_ascii(invert=True, tty=sys.stdout.isatty())
        while LAST_STATUS not in [1, 2]:
            time.sleep(1)
        if os.path.isfile(QRCODE_DIR):
            os.remove(QRCODE_DIR)
        os._exit(0)
    else:
        logging.error("未知的扫码模式")
        if os.path.isfile(QRCODE_DIR):
            os.remove(QRCODE_DIR)
        os._exit(1)
