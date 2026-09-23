FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    nlohmann-json3-dev \
    libspdlog-dev \
    libcurl4-openssl-dev \
    libnetfilter-queue-dev \
    iptables \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*[cite: 2]

WORKDIR /app

COPY src/ ./src/

CMD ["sleep", "infinity"]

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    python3 \
    && rm -rf /var/lib/apt/lists/*