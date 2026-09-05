# Projeto Sentinela

Firewall e sistema de monitoramento de rede em C++20 para a disciplina de
Programação Orientada a Objetos. O projeto recebe pacotes por `libpcap`,
interpreta os protocolos suportados e aplica regras de detecção configuráveis.

Esta primeira entrega é **passiva**: o programa detecta e registra eventos, mas
não altera o tráfego nem regras do firewall do sistema operacional.

## Escopo da Entrega 1

- Captura de pacotes Ethernet/IP/TCP/UDP/ICMP com `libpcap`.
- Modelagem polimórfica de pacotes e regras.
- Detecção de varredura de portas, ping sweep e acesso a IP/porta bloqueado em
  modo alerta.
- Regras e limiares carregados de JSON.
- Eventos estruturados em log local e estatísticas periódicas no terminal.
- Testes unitários para parser, regras e componentes de estado, sem exigir uma
  interface de rede real.

O diagrama de responsabilidades, as fronteiras entre módulos e as decisões de
extensibilidade estão em [docs/architecture.md](docs/architecture.md).

## Dependências

| Item | Uso |
| --- | --- |
| Compilador com C++20 | Compilação do projeto |
| CMake 3.25 ou superior | Configuração do build |
| `libpcap` (headers de desenvolvimento) | Captura de pacotes |
| nlohmann/json | Leitura da configuração e eventos JSON |
| spdlog | Logging local |
| GoogleTest | Testes unitários |
| Ninja (opcional) | Build rápido |

Em Debian/Ubuntu, uma instalação típica é:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build libpcap-dev \
  nlohmann-json3-dev libspdlog-dev libgtest-dev
```

As dependências de produção devem ser resolvidas pelo CMake. GoogleTest pode ser
obtido pelo gerenciador de pacotes ou pelo mecanismo configurado no projeto; não
é necessário incluí-lo no código-fonte da aplicação.

## Compilar

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DSENTINELA_BUILD_TESTS=ON
cmake --build build
```

Sem Ninja, remova `-G Ninja`:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSENTINELA_BUILD_TESTS=ON
cmake --build build
```

## Executar testes

```bash
ctest --test-dir build --output-on-failure
```

Para desenvolver uma regra, execute primeiro seus testes unitários e só então
faça uma demonstração com captura real. Os testes usam bytes de pacotes e
relógio/contexto controlados; portanto, não dependem de privilégios nem de uma
rede externa.

## Configurar e executar

Comece pela configuração de exemplo e mantenha valores locais fora do Git:

```bash
cp config/sentinela.example.json config/sentinela.local.json
./build/sentinela --config config/sentinela.local.json --interface <interface>
```

Use `./build/sentinela --help` para conferir as opções implementadas. A
configuração deve definir, no mínimo, os limiares das regras, os destinos em
modo alerta e o caminho do log estruturado.

Captura em modo promíscuo normalmente exige `CAP_NET_RAW` e, em alguns sistemas,
`CAP_NET_ADMIN`. Em um ambiente de laboratório isolado, use `sudo` apenas para
o processo de demonstração ou conceda capacidades de forma consciente à cópia
local do binário. Não execute o capturador em redes de terceiros sem autorização.

## Demonstração segura

- Restrinja a demonstração à rede Docker da disciplina ou a uma máquina virtual
  própria; confirme a interface antes de iniciar a captura.
- Use somente o alvo e o atacante previstos no laboratório. Para a Entrega 1,
  `nmap` e ferramentas de geração de tráfego devem apontar exclusivamente para
  esse alvo autorizado.
- Não execute varreduras, flood ou captura promíscua em redes de colegas,
  institucionais ou públicas.
- Salve logs de demonstração em um diretório local ignorado pelo Git e remova
  endereços ou dados sensíveis antes de incluí-los no relatório.

## Limite entre as entregas

| Entrega 1 | Futuras extensões da Entrega 2 |
| --- | --- |
| Detectar, registrar e apresentar estatísticas | Aceitar/descartar com NFQUEUE e banimento temporário |
| Log local estruturado | GELF/Graylog, métricas Zabbix e evidências `.pcap` |
| Port scan, ping sweep e destino bloqueado em alerta | SYN flood e força bruta SSH |
| Interfaces de ação/exportação apenas passivas | Adaptadores ativos e integrações externas |

Manter essa separação evita que privilégios de firewall, dependências de
monitoramento e infraestrutura Docker escondam a qualidade do núcleo OO que é
avaliado na primeira entrega.
