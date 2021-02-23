# build a container which can compile rust and run the project
FROM ubuntu:18.04
RUN apt-get update && apt install -y curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN apt install -y \
    sudo \
    net-tools \
    iptables \
    ethtool \
    iputils-ping \
    tcpdump \
    # ip command
    iproute2 \
    # nc command
    netcat \
    # for build
    gcc

COPY setup.sh /tmp/setup.sh