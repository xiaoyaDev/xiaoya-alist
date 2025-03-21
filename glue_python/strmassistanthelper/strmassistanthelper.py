#!/usr/local/bin/python3
# pylint: disable=C0103
# pylint: disable=C0114

import json
import logging
import sys
import shutil
from pathlib import Path

import pefile


def get_file_version(file_path):
    """
    获取文件版本
    """
    pe = pefile.PE(file_path)
    for file_info in pe.FileInfo[0]:
        if file_info.Key == b"StringFileInfo":
            for st in file_info.StringTable:
                for entry in st.entries.items():
                    if entry[0] == b"FileVersion":
                        return entry[1].decode("utf-8")


def move_and_replace_file(src_file: Path, dst_path: Path):
    """
    替换文件
    """
    try:
        if not dst_path.parent.exists():
            dst_path.parent.mkdir(parents=True)
        if dst_path.exists():
            dst_path.unlink()
        shutil.copy2(src_file, dst_path)
        logging.info("复制 %s 文件成功！", src_file.name)
    except Exception as e:  # pylint: disable=W0718
        logging.error("复制 %s 文件失败：%s", src_file.name, e)


def set_and_info_config():
    """
    更新配置文件并输出信息
    """
    if Path(f"{BASE_CONFIG_PATH}/plugins/configurations/Strm Assistant.json").exists():
        with open(f"{BASE_CONFIG_PATH}/plugins/configurations/Strm Assistant.json", encoding="utf-8") as file:
            data = json.load(file)
        if data["ModOptions"]["EnhanceChineseSearch"]:
            logging.info("中文搜索增强已开启")
        else:
            logging.info("中文搜索增强未开启")
            try:
                logging.info("自动开启中文搜索增强中...")
                data["ModOptions"]["EnhanceChineseSearch"] = True
                with open(
                    f"{BASE_CONFIG_PATH}/plugins/configurations/Strm Assistant.json", "w", encoding="utf-8"
                ) as file:
                    json.dump(data, file, ensure_ascii=False, indent=4)
                logging.info("开启中文搜索增强成功！")
            except Exception as e:  # pylint: disable=W0718
                logging.info("开启中文搜索增强失败：%s", e)
    else:
        logging.warning("Strm Assistant.json 配置文件不存在，跳过自动配置！")


logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)

BASE_CONFIG_PATH = "/media/config"
BASE_DATA_PATH = "/strmassistanthelper"

if __name__ == "__main__":
    new_version = get_file_version(f"{BASE_DATA_PATH}/StrmAssistant.dll")
    version = get_file_version(f"{BASE_CONFIG_PATH}/plugins/StrmAssistant.dll")
    if version and new_version:
        if version >= new_version:
            set_and_info_config()
        else:
            source_file = Path(f"{BASE_DATA_PATH}/StrmAssistant.dll")
            dst_file_path = Path(f"{BASE_CONFIG_PATH}/plugins/StrmAssistant.dll")
            logging.info("更新 神医助手 插件：%s --> %s", version, new_version)
            move_and_replace_file(source_file, dst_file_path)
            set_and_info_config()
    else:
        logging.info("获取 StrmAssistant 版本失败！")
