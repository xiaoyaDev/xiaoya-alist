#!/usr/local/bin/python3
# pylint: disable=C0103
# pylint: disable=C0114

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


version = get_file_version("/config/StrmAssistant.dll")
if version:
    print(f"{version}")
