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

FROM mcr.microsoft.com/playwright:v1.62.0-noble

ENV DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
      curl \
      iproute2 \
      iptables \
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
RUN ldconfig \
    && openconnect --version

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY vpnc-script /app/vpnc-script
COPY vpn.js ./
RUN chmod 0555 /app/vpn.js /app/vpnc-script

EXPOSE 8080 1080

ENTRYPOINT ["/usr/bin/tini", "--", "/app/vpn.js", "connect"]
