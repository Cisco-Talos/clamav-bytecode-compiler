# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
FROM registry.hub.docker.com/library/ubuntu:20.04 AS builder

LABEL Maintainer="ClamAV bugs <clamav-bugs@external.cisco.com>"

WORKDIR /src
COPY . /src

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=clang-8
ENV CXX=clang++-8

RUN apt-get update -y && \
    apt-get install -y \
        wget \
        libncurses5 \
        binutils \
        git \
        python3 \
        python3-distutils \
        python3-pip \
        cmake \
        make \
        clang-8 \
    && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install pytest && \
    mkdir build && \
    cd build && \
    cmake .. -G "Unix Makefiles" \
        -D CMAKE_INSTALL_PREFIX=/usr \
        -D CMAKE_BUILD_TYPE=Release \
        -D ENABLE_EXAMPLES=OFF \
    && \
    make DESTDIR="/clambc" -j$(($(nproc) - 1)) && \
    make DESTDIR="/clambc" install

FROM registry.hub.docker.com/library/ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=clang-8
ENV CXX=clang++-8

COPY --from=builder "/clambc" "/"

RUN apt-get -y update && \
    apt install -y \
        python3 \
        clang-8 \
    && \
    rm -rf /var/lib/apt/lists/*
