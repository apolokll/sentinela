FROM ubuntu:24.04

# Evita perguntas interativas durante a instalação
ENV DEBIAN_FRONTEND=noninteractive

# Ferramentas de build e bibliotecas do projeto
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
    && rm -rf /var/lib/apt/lists/*

# Diretório de trabalho dentro do container
WORKDIR /app

# Copia o código-fonte do host para o container
COPY . /app

# Mantém o container rodando (o binário será compilado depois)
CMD ["sleep", "infinity"]