FROM python:3.12-alpine3.21

COPY --chmod=755 . /

RUN apk add --no-cache curl bash jq && \
    pip install --no-cache --upgrade pip && \
    pip install --no-cache -r /requirements.txt && \
    StrmAssistantVersion=$(curl -s "https://api.github.com/repos/sjtuross/StrmAssistant/releases/latest" | jq -r .tag_name) && \
    curl -sL https://github.com/sjtuross/StrmAssistant/releases/download/${StrmAssistantVersion}/StrmAssistant.dll -o /strmassistanthelper/StrmAssistant.dll && \
    if [ -f "/strmassistanthelper/StrmAssistant.dll" ]; then echo "${StrmAssistantVersion}"; else exit 1; fi
