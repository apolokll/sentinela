# Sentinela 🛡️

**Sentinela** é uma aplicação de Segurança da Informação desenvolvida em **C++17** voltada para o monitoramento de tráfego de rede em tempo real, detecção de anomalias/ataques e exportação de métricas de saúde operacional e tráfego para o **Zabbix**.

Este projeto faz parte do módulo de desenvolvimento de sistemas e monitoramento de segurança de rede.

---

## 🏗️ Arquitetura e Estrutura do Projeto

O projeto adota uma arquitetura orientada a objetos modular, utilizando *smart pointers* (`std::shared_ptr`), tratamento de exceções e padrões de projeto (*Strategy* e *Observer*).

```text
sentinela/
├── config/              # Arquivos de configuração dinâmica (JSON)
├── docs/                # Diagramas UML e documentação técnica
├── include/             # Arquivos de cabeçalho (.hpp)
│   ├── captura/         # Leitura de pacotes e parsing via libpcap
│   ├── core/            # Gestão de métricas, eventos e exceções
│   ├── exportadores/    # Integração com Zabbix (Trapper) e Graylog (GELF)
│   ├── modelos/         # Abstrações de Pacote (Ethernet, IP, TCP, UDP, ICMP)
│   └── regras/          # Engine de detecção de ataques e assinaturas
├── src/                 # Implementação dos módulos (.cpp)
├── tests/               # Testes unitários (Catch2 / Google Test)
├── CMakeLists.txt       # Configuração de build automatizado
├── Dockerfile           # Imagem da aplicação Sentinela
└── docker-compose.yml   # Orquestração do Sentinela, Alvo Web e Zabbix Stack
```

## ⚡ Funcionalidades

- **Captura em Tempo Real:** Captura de pacotes de rede utilizando `libpcap` na interface `any` (Ethernet, Wi-Fi e pontes virtuais do Docker).

- **Parsing de Protocolos:** Decodificação e inspeção de cabeçalhos Ethernet, IP, TCP, UDP e ICMP.

- **Engine de Regras:** Análise contínua de pacotes para identificação de varreduras de porta (Port Scan) e acessos a serviços sensíveis.

- **Métricas Operacionais:** Cálculo de vazão de tráfego (`pacotes_por_segundo`) e contagem acumulada de `alertas_disparados` de forma thread-safe.

- **Exportação Trapper:** Envio periódico de métricas para o **Zabbix Server** na porta `TCP 10051`.

## 🚀 Como Executar

### Pré-requisitos

- Docker e Docker Compose instalados.
- Compilador C++17 e CMake 3.14+ (para execução/compilação local sem container).
- Biblioteca `libpcap-dev` instalada no sistema.

### Executando via Docker Compose (Recomendado)

1. Suba todo o ambiente containerizado (Sentinela + Zabbix Server/Web/PostgreSQL + Alvo Web):

```bash
docker compose up --build -d
```

2. Acesse a interface web do Zabbix no seu navegador:

```text
http://localhost:8080
```

*(Credenciais padrão: `Admin` / `zabbix`)*

### Compilando e Executando Localmente

```bash
mkdir build && cd build
cmake ..
make
sudo ./sentinela
```

## 🧪 Testes de Ataque e Validação

Para testar o disparo de regras e a atualização das métricas no Zabbix, utilize ferramentas como `nmap` ou `hping3` contra o container alvo (`alvo-web` - `172.20.0.10`):

```bash
# Simulação de Port Scan contra o container alvo
nmap -sS -p 1-1024 172.50.0.10
```
