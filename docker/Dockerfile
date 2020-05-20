FROM python:3.7-slim-buster

ARG BUILD_SERIES=dev
ARG BUILD_ID=0

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    make \
    && apt-get clean

COPY Makefile /opt/snikket-web-portal/Makefile

COPY requirements.txt /opt/snikket-web-portal/requirements.txt

COPY build-requirements.txt /opt/snikket-web-portal/build-requirements.txt

COPY snikket_web/ /opt/snikket-web-portal/snikket_web

COPY babel.cfg /opt/snikket-web-portal/babel.cfg

COPY web_config.production.py /opt/snikket-web-portal/.local/web_config.py

WORKDIR /opt/snikket-web-portal

RUN pip install -r requirements.txt \
    && pip install -r build-requirements.txt

RUN make

ENV SNIKKET_WEB_CONFIG "/opt/snikket-web-portal/.local/web_config.py"

RUN pip install hypercorn

ADD docker/entrypoint.sh /bin/entrypoint.sh

ENTRYPOINT ["/bin/sh", "/bin/entrypoint.sh"]
