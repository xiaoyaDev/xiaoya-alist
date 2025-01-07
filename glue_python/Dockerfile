FROM python:3.12-alpine3.21

COPY --chmod=755 . /

RUN pip install --no-cache --upgrade pip && \
    pip install --no-cache -r /requirements.txt
