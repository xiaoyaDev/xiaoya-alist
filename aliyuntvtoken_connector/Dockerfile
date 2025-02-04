FROM python:3.12-alpine3.21

ENV TZ=Asia/Shanghai

WORKDIR /app

COPY . .

RUN set -ex && \
    apk add --no-cache \
        bash \
        tzdata && \
    apk add --no-cache --virtual=build-dependencies \
        build-base \
        gcc \
        g++ && \
    python3 -m pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    apk del --purge build-dependencies && \
    rm -rf \
        /root/.cache \
        /tmp/*

EXPOSE 34278

ENTRYPOINT [ "python3", "/app/main.py" ]
