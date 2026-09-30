FROM debian:trixie-slim AS build

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update ; \
    apt-get install -y --no-install-recommends \
        python3 python3-mypy python3-dotenv python3-toml python3-babel \
        sassc make;

COPY Makefile /opt/snikket-web-portal/Makefile
COPY snikket_web/ /opt/snikket-web-portal/snikket_web
COPY babel.cfg /opt/snikket-web-portal/babel.cfg

WORKDIR /opt/snikket-web-portal

RUN make


FROM debian:trixie-slim

ARG BUILD_SERIES=dev
ARG BUILD_ID=0

COPY docker/env.py /etc/snikket-web-portal/env.py

ENV SNIKKET_WEB_PYENV=/etc/snikket-web-portal/env.py

ENV SNIKKET_WEB_PROSODY_ENDPOINT=http://127.0.0.1:5280/

WORKDIR /opt/snikket-web-portal

COPY requirements.txt /opt/snikket-web-portal/requirements.txt

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update ; \
    apt-get install -y --no-install-recommends \
      netcat-traditional python3 python3-setuptools python3-pip \
      python3-typing-extensions ; \
      pip3 install --break-system-packages -r requirements.txt; \
    apt-get remove -y --purge python3-pip python3-setuptools; \
    apt-get clean ; rm -rf /var/lib/apt/lists; \
    rm -rf /root/.cache;

COPY --from=build /opt/snikket-web-portal/snikket_web/ /opt/snikket-web-portal/snikket_web
COPY babel.cfg /opt/snikket-web-portal/babel.cfg

RUN echo "$BUILD_SERIES $BUILD_ID" > /opt/snikket-web-portal/.app_version

ADD docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
