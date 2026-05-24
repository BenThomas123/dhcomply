FROM debian:bookworm

RUN apt-get update && apt-get install -y \
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

COPY . .

RUN chmod +x src/check_dad.sh \
    && ln -sf /workspace/src/check_dad.sh /workspace/check_dad.sh \
    && make

EXPOSE 547/udp

CMD ["sh", "/workspace/docker/entrypoint.sh"]
