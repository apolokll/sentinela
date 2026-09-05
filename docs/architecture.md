# Arquitetura — Entrega 1

## Objetivo e princípio de desenho

O núcleo da primeira entrega transforma tráfego capturado em eventos de
segurança locais. Ele deve ser fácil de testar sem uma placa de rede e fácil de
estender na segunda entrega sem reescrever as regras já validadas.

O fluxo e:

```text
libpcap ou arquivo .pcap -> CapturaPcap -> AnalisadorPacote -> Pacote
                                                          -> MotorRegras
                                                          -> EventoSeguranca
                                                          -> DespachanteAcoes -> Acao -> ExportadorJsonl
                                                          -> Estatisticas
```

`CapturaPcap` e os exportadores são adaptadores de borda. O domínio de
regras não conhece `pcap_t`, arquivos, `spdlog`, JSON nem argumentos da linha
de comando. Essa direção de dependências permite que um teste construa um
`PacoteTcp` ou forneça bytes a `AnalisadorPacote` sem privilégios de captura.

## Estrutura proposta

Os diretórios de módulo separam domínio, núcleo, regras, captura e exportação.
Classes e arquivos C++ usam nomes em português, sem acentos.

```text
.
├── CMakeLists.txt
├── README.md
├── config/
│   └── sentinela.example.json
├── docs/
│   ├── architecture.md
│   └── uml/                         # diagrama exportado para a entrega
├── include/sentinela/
│   ├── domain/
│   │   ├── Pacote.hpp
│   ├── core/
│   │   ├── Regra.hpp
│   │   ├── MotorRegras.hpp
│   │   ├── Acao.hpp
│   │   ├── DespachanteAcoes.hpp
│   │   ├── Configuracao.hpp
│   │   ├── EventoSeguranca.hpp
│   │   ├── Estatisticas.hpp
│   │   ├── AnalisadorPacote.hpp
│   │   ├── Excecoes.hpp
│   │   └── Tipos.hpp
│   ├── rules/
│   │   ├── RegraPortScan.hpp
│   │   ├── RegraPingSweep.hpp
│   │   └── RegraAcessoBloqueado.hpp
│   ├── capture/
│   │   └── CapturaPcap.hpp
│   └── exporter/
│       ├── Exportador.hpp
│       └── ExportadorJsonl.hpp
├── src/
│   ├── main.cpp
│   ├── domain/
│   ├── core/
│   ├── capture/
│   ├── rules/
│   └── exporter/
├── tests/
│   ├── test_analisador_pacote.cpp
│   ├── test_regras.cpp
│   ├── test_configuracao.cpp
│   └── test_estatisticas.cpp
└── scripts/
    └── demo-local.sh                # somente quando a demonstração for definida
```

Os cabeçalhos públicos ficam em `include/sentinela`; cada implementação tem o
mesmo caminho relativo em `src`. Um teste espelha esse caminho em `tests/unit`.
Arquivos `.pcap`, logs e builds não pertencem ao repositório; fixtures pequenas
e anonimizadas de bytes de pacotes podem ser versionadas em `tests/fixtures`.

## Modelo de domínio

### Pacotes

`Pacote` é uma classe abstrata, imutável após a construção, que concentra os
campos comuns: timestamp, IP de origem/destino, protocolo e tamanho capturado.
`PacoteTcp`, `PacoteUdp` e `PacoteIcmp` especializam apenas os dados de
transporte/controle necessários às regras. Por exemplo, `PacoteTcp` contém
portas e flags; `AnalisadorPacote` é o único componente que cria essas classes
a partir de bytes de um quadro.

### Detecção e estado

`Regra` define a interface polimórfica pura para avaliar um `Pacote` com um
contexto de execução. As implementações iniciais são:

- `RegraPortScan`: conta portas distintas observadas por par origem/destino em
  uma janela e considera apenas TCP SYN sem ACK.
- `RegraPingSweep`: conta destinos distintos de ICMP echo por origem em uma
  janela.
- `RegraAcessoBloqueado`: verifica IP e/ou porta contra a configuração e emite
  alerta, sem bloquear o pacote.

O estado temporal fica encapsulado nas regras de janela deslizante: elas usam
`unordered_map` para o estado por origem ou fluxo, `deque` para amostras dentro
da janela e `unordered_set` para contar portas ou destinos distintos. Cada
regra controla seu próprio cooldown e expiração, sem expor containers mutáveis.
Isso torna limiares e janelas de tempo determinísticos nos testes.

`MotorRegras` possui `std::vector<std::unique_ptr<Regra>>`, avalia cada regra e
coleta objetos `EventoSeguranca`. `Configuracao::carregar` valida o JSON e sua
fábrica interna cria a coleção concreta de regras, mantendo detalhes de JSON
fora do domínio.

### Eventos, ações e exportação

Uma regra não escreve arquivo nem imprime no terminal. Ela devolve um resultado
de detecção a partir do qual o `MotorRegras` cria um `EventoSeguranca` com
timestamp, origem, destino, portas quando aplicáveis, nome da regra e severidade.

`Acao` é uma segunda hierarquia abstrata. `AcaoRegistrar` e `AcaoAlertar`
encaminham eventos aos exportadores locais na Entrega 1; `AcaoPermitir` e
`AcaoDescartar` existem como contratos sem efeito de firewall nesta etapa. O
`DespachanteAcoes` associa `TipoAcao` à ação concreta e despacha cada evento.

`Exportador` é uma terceira interface de borda e `ExportadorJsonl` grava um
evento JSON por linha. Essa composição dá uma justificativa clara de Strategy:
o despachante troca a implementação de `Acao` sem condicional espalhado nas
regras. Na Entrega 2, novos exportadores podem ser adicionados sem alterar
`MotorRegras`.

`Estatisticas` observa os pacotes/eventos processados e apresenta taxas,
origens mais frequentes e alertas por tipo periodicamente. Ele é separado do
log para que a saída humana não altere a evidência estruturada.

## Captura e análise

`CapturaPcap` encapsula a vida útil de `pcap_t` em RAII e entrega bytes e
timestamp para um callback. Ele suporta duas fontes: replay de arquivo `.pcap`
e captura ao vivo. Sua responsabilidade termina ao receber o quadro; ele não
deve conhecer regras.

`AnalisadorPacote` valida comprimentos e cabeçalhos Ethernet, IPv4, TCP, UDP e
ICMP. Para protocolos ou quadros truncados, ele retorna ausência de pacote ou
lança uma exceção de análise bem definida conforme a gravidade. O programa
principal registra a falha e continua capturando; um pacote malformado não deve
encerrar a sessão.

## Configuração, exceções e observabilidade

`Configuracao::carregar` lê `config/sentinela.example.json`, valida tipos,
intervalos, regras e caminhos antes de iniciar a captura. Problemas de arquivo
ou esquema usam `ExcecaoConfiguracao`,
derivada de `ExcecaoSentinela`. Erros de captura e análise seguem a mesma
família de exceções para que `main.cpp` possa converter falhas em uma mensagem
útil e código de saída não zero.

O log de eventos é JSON Lines: cada linha é um objeto autocontido. Campos
mínimos: `timestamp`, `source_ip`, `destination_ip`, `source_port`,
`destination_port`, `protocol`, `rule`, `severity` e `message`. Campos sem
significado para um protocolo podem ser ausentes ou `null`, de modo consistente.

## Alvos CMake

O MVP expõe poucos alvos com fronteiras úteis:

- `sentinela_core`: domínio, regras, analisador, captura, ações, exportação,
  configuração e estatísticas.
- `sentinela`: executável de composição em `src/main.cpp`.
- `sentinela_tests`: testes registrados no CTest quando `BUILD_TESTING=ON`.

O alvo de núcleo usa C++20, avisos estritos e publica apenas `include/` como
interface. Ele depende de `libpcap` e nlohmann/json; GoogleTest entra somente
na suíte de testes. Separar os diretórios dentro da mesma biblioteca mantém o
MVP simples, sem abrir mão das fronteiras de dependência descritas acima.

## Ordem de implementação incremental

1. Criar os objetos de valor, `Pacote` e as subclasses, com testes de construção
   e encapsulamento.
2. Implementar `AnalisadorPacotes` sobre fixtures de bytes válidas, truncadas e
   de protocolo não suportado.
3. Implementar `EventoSeguranca`, `RastreadorAtividade`, `Regra` e cada regra
   com relógio/contexto controlável nos testes.
4. Compor `MotorRegras`, carregamento JSON e `ExportadorJsonLinhas`.
5. Adicionar `CapturadorPcap` e `EstatisticasConsole` somente depois que o
   pipeline puder ser executado por testes de integração com quadros simulados.
6. Fazer uma captura curta no laboratório Docker autorizado e registrar a
   evidência para a demonstração.

## Fronteira da Entrega 2

NFQUEUE, iptables, banimento automático, GELF/Graylog, Zabbix e escrita de
evidências `.pcap` são adaptadores posteriores. Eles podem implementar novas
subclasses de `Acao` ou `Exportador`, e novas regras podem usar
`RastreadorAtividade`, mas nenhum deles deve entrar no caminho crítico, nas
dependências obrigatórias ou no privilégio de execução da Entrega 1.
