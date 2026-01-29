FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG MAKE_JOBS=8

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    automake \
    build-essential \
    clang \
    cmake \
    git \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-iostreams-dev \
    libboost-thread-dev \
    libgmp-dev \
    libntl-dev \
    libsodium-dev \
    libssl-dev \
    libtool \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    curl \
    pkg-config \
    bash \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3 /usr/local/bin/python

RUN useradd -m -s /bin/bash artifact
USER artifact
WORKDIR /home/artifact

# TODO: switch back to main branch
RUN git clone --branch pets-artifact2026.2 https://github.com/spring-epfl/aid-distribution-with-assessments-artifacts \
 && cd aid-distribution-with-assessments-artifacts \
 && git submodule update --init --recursive

WORKDIR /home/artifact/aid-distribution-with-assessments-artifacts

# Build MP-SPDZ (see https://github.com/data61/MP-SPDZ)
RUN cd MP-SPDZ \
 && make -j ${MAKE_JOBS} semi-party.x

# Install Rust (using rust-toolchain for version)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/home/artifact/.cargo/bin:${PATH}"

# Install cargo-dinghy
RUN cargo install --locked cargo-dinghy

# Compile code
RUN cargo build --release
