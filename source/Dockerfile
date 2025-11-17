FROM ubuntu:18.04

RUN adduser --disabled-password --gecos '' ctf

# Update package lists and install build tools
RUN apt update && apt install -y \
    build-essential \
    gcc \
    gcc-multilib \
    g++-multilib \
    libc6-dev-i386 \
    make \
    python3 \
    python3-pip \
    python3-dev \
    git \
    libssl-dev \
    libffi-dev \
    wget

# Install pwntools for exploit development
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools

# Install checksec for verification
RUN apt install -y binutils

