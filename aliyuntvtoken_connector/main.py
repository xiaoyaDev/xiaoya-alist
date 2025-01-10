# pylint: disable=C0114
# pylint: disable=C0116
import json
import base64
import uuid
import hashlib
import random

import requests
from flask import Flask, request, Response
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


app = Flask(__name__)


class AliyunPanTvToken:
    """
    阿里云盘 TV Token 解密刷新模块
    """

    def __init__(self):
        self.timestamp = str(requests.get("http://api.extscreen.com/timestamp", timeout=10).json()["data"]["timestamp"])
        self.unique_id = uuid.uuid4().hex
        self.wifimac = str(random.randint(10**11, 10**12 - 1))
        self.headers = {
            "token": "6733b42e28cdba32",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 9; zh-cn; SM-S908E Build/TP1A.220624.014) AppleWebKit/533.1 (KHTML, like Gecko) Mobile Safari/533.1",  # noqa: E501
            "Host": "api.extscreen.com",
        }

    def h(self, char_array, modifier):
        unique_chars = list(dict.fromkeys(char_array))
        numeric_modifier = int(modifier[7:])
        transformed_string = "".join(
            [
                chr(
                    abs(ord(c) - (numeric_modifier % 127) - 1) + 33
                    if abs(ord(c) - (numeric_modifier % 127) - 1) < 33
                    # noqa: E501
                    else abs(ord(c) - (numeric_modifier % 127) - 1)
                )
                for c in unique_chars
            ]
        )
        return transformed_string

    def get_params(self):
        params = {
            "akv": "2.8.1496",
            "apv": "1.3.8",
            "b": "samsung",
            "d": self.unique_id,
            "m": "SM-S908E",
            "mac": "",
            "n": "SM-S908E",
            "t": self.timestamp,
            "wifiMac": self.wifimac,
        }
        return params

    def generate_key(self):
        params = self.get_params()
        sorted_keys = sorted(params.keys())
        concatenated_params = "".join([params[key] for key in sorted_keys if key != "t"])
        hashed_key = self.h(list(concatenated_params), self.timestamp)
        return hashlib.md5(hashed_key.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext, iv):
        try:
            key = self.generate_key()
            cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv=bytes.fromhex(iv))
            decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
            dec = decrypted.decode("utf-8")
            return dec
        except Exception as error:
            print("Decryption failed %s", error)
            raise error

    def get_headers(self):
        return {**self.get_params(), **self.headers}

    def get_token(self, data):
        token_data = requests.post(
            "http://api.extscreen.com/aliyundrive/v3/token", data=data, headers=self.get_headers(), timeout=10
        ).json()["data"]
        return self.decrypt(token_data["ciphertext"], token_data["iv"])


@app.route('/oauth/alipan/token', methods=['POST'])
def oauth_token():
    data = request.get_json()
    refresh_token = data.get('refresh_token', None)
    if not refresh_token:
        return Response(json.dumps({"error": "No refresh_token provided"}), status=400, mimetype='application/json')
    req_body = {
        "refresh_token": refresh_token
    }
    client = AliyunPanTvToken()
    return Response(json.dumps(json.loads(client.get_token(req_body))), status=200, mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=34278)
