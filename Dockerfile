FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN g++ -Iinclude -o sentinela \
    src/main.cpp \
    src/captura/Parser.cpp \
    src/regras/EngineRegras.cpp \
    -lpcap

CMD ["./sentinela"]