FROM debian:bullseye-slim AS build

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update ; \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-setuptools python3-wheel \
        libpython3-dev \
        make build-essential;

COPY requirements.txt /opt/snikket-web-portal/requirements.txt
COPY build-requirements.txt /opt/snikket-web-portal/build-requirements.txt
COPY Makefile /opt/snikket-web-portal/Makefile
COPY snikket_web/ /opt/snikket-web-portal/snikket_web
COPY babel.cfg /opt/snikket-web-portal/babel.cfg

WORKDIR /opt/snikket-web-portal

RUN set -eu; \
    pip3 install -r requirements.txt; \
    pip3 install -r build-requirements.txt; \
    make;


FROM debian:bullseye-slim

ARG BUILD_SERIES=dev
ARG BUILD_ID=0

COPY docker/env.py /etc/snikket-web-portal/env.py

ENV SNIKKET_WEB_PYENV=/etc/snikket-web-portal/env.py

ENV SNIKKET_WEB_PROSODY_ENDPOINT=http://127.0.0.1:5280/

COPY requirements.txt /opt/snikket-web-portal/requirements.txt

WORKDIR /opt/snikket-web-portal

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update ; \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-setuptools python3-wheel build-essential libpython3-dev netcat; \
    pip3 install -r requirements.txt; \
    apt-get remove -y --autoremove build-essential libpython3-dev; \
    apt-get clean ; rm -rf /var/lib/apt/lists; \
    pip3 install hypercorn; \
    rm -rf /root/.cache;

HEALTHCHECK CMD nc -zv ${SNIKKET_TWEAK_PORTAL_INTERNAL_HTTP_INTERFACE:-127.0.0.1} ${SNIKKET_TWEAK_PORTAL_INTERNAL_HTTP_PORT:-5765}

COPY --from=build /opt/snikket-web-portal/snikket_web/ /opt/snikket-web-portal/snikket_web
COPY babel.cfg /opt/snikket-web-portal/babel.cfg

RUN echo "$BUILD_SERIES $BUILD_ID" > /opt/snikket-web-portal/.app_version

ADD docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
