#!/bin/sh

BASE_CONFIG_PATH="/media/config"
BASE_DATA_PATH="/coverart"

if [ ! -f "${BASE_CONFIG_PATH}/plugins/configurations/CoverArt.xml" ]; then
    cp -f "${BASE_DATA_PATH}/CoverArt.xml" "${BASE_CONFIG_PATH}/plugins/configurations/CoverArt.xml"
    echo "CoverArt.xml 配置完成！"
fi

if [ ! -f "${BASE_CONFIG_PATH}/plugins/CoverArt.dll" ]; then
    cp -f "${BASE_DATA_PATH}/CoverArt.dll" "${BASE_CONFIG_PATH}/plugins/CoverArt.dll"
    echo "CoverArt.dll 配置完成！"
fi

if [ ! -d "${BASE_CONFIG_PATH}/cache/coverart/4.1.28.0/MetroCase" ]; then
    mkdir -p "${BASE_CONFIG_PATH}/cache/coverart/4.1.28.0/MetroCase"
fi

if [ ! -f "${BASE_CONFIG_PATH}/cache/coverart/4.1.28.0/MetroCase/UHD.png" ]; then
    cp -f "${BASE_DATA_PATH}/UHD.png" "${BASE_CONFIG_PATH}/cache/coverart/4.1.28.0/MetroCase/UHD.png"
    echo "UHD.png 配置完成！"
fi
