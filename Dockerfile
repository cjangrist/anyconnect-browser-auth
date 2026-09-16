FROM ubuntu:noble AS openconnect-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
      autoconf \
      automake \
      build-essential \
      ca-certificates \
      git \
      gettext \
      libgnutls28-dev \
      liblz4-dev \
      libtool \
      libxml2-dev \
      pkg-config \
      vpnc-scripts \
      zlib1g-dev

ARG OPENCONNECT_COMMIT=70d1e79d1e55849dfc71dcc199b1edb535b547e4

RUN git clone https://gitlab.com/openconnect/openconnect.git /src/openconnect \
    && git -C /src/openconnect checkout "${OPENCONNECT_COMMIT}" \
    && cd /src/openconnect \
    && ./autogen.sh \
    && ./configure \
      --prefix=/usr \
      --without-gssapi \
      --without-libproxy \
      --without-libpskc \
      --without-stoken \
      --with-vpnc-script=/usr/share/vpnc-scripts/vpnc-script \
    && make --jobs="$(nproc)" \
    && make DESTDIR=/openconnect-root install

FROM openconnect-builder AS proxy-builder

ARG MICROSOCKS_COMMIT=98421a21c4adc4c77c0cf3a5d650cc28ad3e0107
ARG TINYPROXY_COMMIT=baecbf4c3e006fa68ab92f65bbd4138c47ede111
RUN git clone https://github.com/rofl0r/microsocks.git /src/microsocks \
    && git -C /src/microsocks checkout "${MICROSOCKS_COMMIT}" \
    && git clone https://github.com/tinyproxy/tinyproxy.git /src/tinyproxy \
    && git -C /src/tinyproxy checkout "${TINYPROXY_COMMIT}"
COPY docker/proxy-connect-recovery.patch /src/proxy-connect-recovery.patch
WORKDIR /src
RUN git apply --check proxy-connect-recovery.patch \
    && git apply proxy-connect-recovery.patch \
    && make -C microsocks CFLAGS="-O2 -Wall -std=c99" \
    && cd tinyproxy \
    && ./autogen.sh --prefix=/usr --disable-manpage-support \
    && make --jobs="$(nproc)"

FROM mcr.microsoft.com/playwright:v1.62.0-noble

ENV DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
      curl \
      iproute2 \
      iptables \
      iputils-ping \
      libgnutls30t64 \
      liblz4-1 \
      libxml2 \
      microsocks \
      tini \
      tinyproxy \
      vpnc-scripts \
      zlib1g \
    && npm install --global agent-browser@0.34.0

COPY --from=openconnect-builder /openconnect-root/ /
COPY --from=proxy-builder /src/microsocks/microsocks /usr/bin/microsocks
COPY --from=proxy-builder /src/tinyproxy/src/tinyproxy /usr/bin/tinyproxy
RUN ldconfig \
    && openconnect --version

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY docker/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY docker/vpnc-script /app/vpnc-script
COPY src/ ./
RUN chmod 0555 /app/vpn.js /app/vpnc-script

EXPOSE 8080 1080

ENTRYPOINT ["/usr/bin/tini", "--", "/app/vpn.js", "connect"]
