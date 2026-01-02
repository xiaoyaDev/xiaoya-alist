FROM alpine:3.23

ENV TZ=Asia/Shanghai

RUN set -ex && \
    apk add --no-cache \
        bash \
        curl \
        s6-overlay \
        tzdata && \
    apk add --no-cache \
        --repository https://dl-cdn.alpinelinux.org/v3.21/community/ \
        docker==27.3.1-r5 && \
    rm -rf \
        /var/cache/apk/* \
        /tmp/*

COPY --chmod=755 ./rootfs /

ENTRYPOINT [ "/init" ]
