FROM debian:buster

ARG BUILD_SERIES=dev
ARG BUILD_ID=0

ENV DEBIAN_FRONTEND noninteractive

# This Dockerfile attempts to strike a balance between image size and time it
# takes to do an incremental build on changes.
# Improvements welcome.

RUN set -eu; \
    apt-get update ; \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-setuptools python3-wheel \
        libpython3-dev \
        make build-essential \
        ; \
    apt-get clean ; rm -rf /var/lib/apt/lists

COPY requirements.txt /opt/snikket-web-portal/requirements.txt
COPY build-requirements.txt /opt/snikket-web-portal/build-requirements.txt

WORKDIR /opt/snikket-web-portal

RUN set -eu; \
    pip3 install -r requirements.txt; \
    pip3 install -r build-requirements.txt; \
    rm -rf /root/.cache;

COPY Makefile /opt/snikket-web-portal/Makefile
COPY snikket_web/ /opt/snikket-web-portal/snikket_web
COPY babel.cfg /opt/snikket-web-portal/babel.cfg

# NOTE: abusing true(1) as a terrible way to disable a specific command. If
# one merged all the RUN commands into one, one would want to run the
# uninstall/remove commands there, but with the split up RUN commands it is
# rather pointless.
RUN set -eu; \
    make; \
    true pip3 uninstall -yr build-requirements.txt; \
    true apt-get remove -y build-essential make libpython3-dev; \
    true apt-get autoremove -y; \
    pip3 install hypercorn; \
    rm -rf /root/.cache; \
    apt-get clean ; rm -rf /var/lib/apt/lists

COPY docker/env.py /etc/snikket-web-portal/env.py
ENV SNIKKET_WEB_PYENV=/etc/snikket-web-portal/env.py

ENV SNIKKET_WEB_PROSODY_ENDPOINT=http://127.0.0.1:5280/

ADD docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
