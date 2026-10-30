FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    kea-dhcp6-server \
    sudo \
    make \
    iproute2 \
    libcap2-bin \
    iputils-ping \
    net-tools \
    procps \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN setcap cap_net_admin,cap_net_raw+ep "$(readlink -f "$(command -v ip)")" \
    && printf 'root ALL=(ALL) NOPASSWD: /usr/sbin/ip, /sbin/ip\n' > /etc/sudoers.d/dhcomply-ip \
    && chmod 0440 /etc/sudoers.d/dhcomply-ip

WORKDIR /workspace

COPY Makefile ./
COPY src/*.c src/*.h src/check_dad.sh ./src/
COPY lib/cJSON.c lib/cJSON.h ./lib/
COPY docker/entrypoint.sh docker/kea-dhcp6.conf.template ./docker/

RUN chmod +x src/check_dad.sh \
    && ln -sf /workspace/src/check_dad.sh /workspace/check_dad.sh \
    && make

EXPOSE 547/udp

# This network test harness requires root to configure interfaces, run Kea and
# tcpdump, and write /etc configuration. Run only in an isolated test network.
USER root

CMD ["sh", "/workspace/docker/entrypoint.sh"]
