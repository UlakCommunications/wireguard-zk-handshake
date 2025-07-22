FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    libelf-dev \
    libssl-dev \
    git \
    curl \
    pkg-config \
    libclang-dev \
    clang \
    rustc cargo \
    net-tools iproute2 \
    kmod \
    sudo \
    linux-image-generic

# Add rust toolchain
RUN rustup default stable

WORKDIR /root

CMD ["/bin/bash"]
