#include "core/Configuracao.hpp"

#include "core/Excecoes.hpp"
#include "core/Regra.hpp"
#include "core/Tipos.hpp"
#include "rules/RegraAcessoBloqueado.hpp"
#include "rules/RegraPingSweep.hpp"
#include "rules/RegraPortScan.hpp"

#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <sstream>
#include <utility>

namespace sentinela {
namespace {

using json = nlohmann::json;

[[nodiscard]] std::string campoTextoObrigatorio(const json& objeto, const char* nome) {
    if (!objeto.contains(nome) || !objeto.at(nome).is_string()) {
        throw ExcecaoConfiguracao(std::string("Campo obrigatorio ausente ou invalido: ") + nome);
    }
    return objeto.at(nome).get<std::string>();
}

[[nodiscard]] bool campoBooleano(const json& objeto, const char* nome, const bool padrao) {
    if (!objeto.contains(nome)) {
        return padrao;
    }
    if (!objeto.at(nome).is_boolean()) {
        throw ExcecaoConfiguracao(std::string("Campo booleano invalido: ") + nome);
    }
    return objeto.at(nome).get<bool>();
}

[[nodiscard]] int campoInteiro(const json& objeto,
                                const char* nome,
                                const int padrao,
                                const int minimo,
                                const int maximo) {
    if (!objeto.contains(nome)) {
        return padrao;
    }
    if (!objeto.at(nome).is_number_integer()) {
        throw ExcecaoConfiguracao(std::string("Campo inteiro invalido: ") + nome);
    }
    const auto valor = objeto.at(nome).get<int>();
    if (valor < minimo || valor > maximo) {
        throw ExcecaoConfiguracao(std::string("Campo fora do intervalo permitido: ") + nome);
    }
    return valor;
}

[[nodiscard]] std::size_t campoLimiteObrigatorio(const json& objeto, const char* nome) {
    const auto limite = campoInteiro(objeto, nome, 0, 1, std::numeric_limits<int>::max());
    return static_cast<std::size_t>(limite);
}

[[nodiscard]] Severidade converterSeveridade(const std::string& texto) {
    if (texto == "informacao") {
        return Severidade::Informacao;
    }
    if (texto == "baixa") {
        return Severidade::Baixa;
    }
    if (texto == "media") {
        return Severidade::Media;
    }
    if (texto == "alta") {
        return Severidade::Alta;
    }
    if (texto == "critica") {
        return Severidade::Critica;
    }
    throw ExcecaoConfiguracao("Severidade desconhecida: " + texto);
}

[[nodiscard]] std::vector<std::uint16_t> lerPortas(const json& regra) {
    if (!regra.contains("portas")) {
        return {};
    }
    const auto& portasJson = regra.at("portas");
    if (!portasJson.is_array()) {
        throw ExcecaoConfiguracao("Campo portas deve ser uma lista");
    }
    std::vector<std::uint16_t> portas;
    portas.reserve(portasJson.size());
    for (const auto& portaJson : portasJson) {
        if (!portaJson.is_number_integer()) {
            throw ExcecaoConfiguracao("Cada porta deve ser um inteiro");
        }
        const auto porta = portaJson.get<int>();
        if (porta < 1 || porta > 65535) {
            throw ExcecaoConfiguracao("Porta fora do intervalo 1-65535");
        }
        portas.push_back(static_cast<std::uint16_t>(porta));
    }
    return portas;
}

} // namespace

const std::string& OpcoesCaptura::interface() const noexcept {
    return interface_;
}

bool OpcoesCaptura::modoPromiscuo() const noexcept {
    return modoPromiscuo_;
}

int OpcoesCaptura::snaplen() const noexcept {
    return snaplen_;
}

int OpcoesCaptura::timeoutMilissegundos() const noexcept {
    return timeoutMilissegundos_;
}

OpcoesCaptura OpcoesCaptura::comInterface(std::string interface) const {
    auto copia = *this;
    copia.interface_ = std::move(interface);
    return copia;
}

Configuracao Configuracao::carregar(const std::filesystem::path& caminho) {
    std::ifstream arquivo(caminho);
    if (!arquivo.is_open()) {
        throw ExcecaoConfiguracao("Nao foi possivel abrir a configuracao: " + caminho.string());
    }

    try {
        json raiz;
        arquivo >> raiz;
        if (!raiz.is_object()) {
            throw ExcecaoConfiguracao("A raiz da configuracao deve ser um objeto JSON");
        }

        Configuracao configuracao;
        configuracao.caminhoLog_ = caminho.parent_path() / "eventos.jsonl";
        if (raiz.contains("log_jsonl")) {
            if (!raiz.at("log_jsonl").is_string()) {
                throw ExcecaoConfiguracao("Campo log_jsonl deve ser texto");
            }
            configuracao.caminhoLog_ = caminho.parent_path() / raiz.at("log_jsonl").get<std::string>();
        }

        if (raiz.contains("captura")) {
            const auto& captura = raiz.at("captura");
            if (!captura.is_object()) {
                throw ExcecaoConfiguracao("Campo captura deve ser um objeto");
            }
            if (captura.contains("interface")) {
                configuracao.captura_.interface_ = campoTextoObrigatorio(captura, "interface");
            }
            configuracao.captura_.modoPromiscuo_ = campoBooleano(captura, "promiscuo", true);
            configuracao.captura_.snaplen_ = campoInteiro(captura, "snaplen", 65535, 68, 65535);
            configuracao.captura_.timeoutMilissegundos_ =
                campoInteiro(captura, "timeout_ms", 500, 1, 60000);
        }

        if (!raiz.contains("regras") || !raiz.at("regras").is_array()) {
            throw ExcecaoConfiguracao("Campo regras deve ser uma lista nao vazia");
        }
        const auto& regrasJson = raiz.at("regras");
        if (regrasJson.empty()) {
            throw ExcecaoConfiguracao("A configuracao deve habilitar pelo menos uma regra");
        }

        std::size_t indice = 0;
        for (const auto& regra : regrasJson) {
            ++indice;
            if (!regra.is_object()) {
                throw ExcecaoConfiguracao("Cada regra deve ser um objeto JSON");
            }
            if (!campoBooleano(regra, "habilitada", true)) {
                continue;
            }

            DefinicaoRegra definicao;
            definicao.tipo = campoTextoObrigatorio(regra, "tipo");
            definicao.identificador = regra.value("id", definicao.tipo + "-" + std::to_string(indice));
            if (regra.contains("id") && !regra.at("id").is_string()) {
                throw ExcecaoConfiguracao("Campo id deve ser texto");
            }

            if (definicao.tipo == "port_scan") {
                definicao.janela = std::chrono::seconds(campoInteiro(regra, "janela_segundos", 10, 1, 86400));
                definicao.cooldown = std::chrono::seconds(campoInteiro(regra, "cooldown_segundos", 30, 0, 86400));
                definicao.limite = campoLimiteObrigatorio(regra, "minimo_portas_distintas");
            } else if (definicao.tipo == "ping_sweep") {
                definicao.janela = std::chrono::seconds(campoInteiro(regra, "janela_segundos", 10, 1, 86400));
                definicao.cooldown = std::chrono::seconds(campoInteiro(regra, "cooldown_segundos", 30, 0, 86400));
                definicao.limite = campoLimiteObrigatorio(regra, "minimo_destinos_distintos");
            } else if (definicao.tipo == "acesso_bloqueado") {
                definicao.ipDestino = campoTextoObrigatorio(regra, "ip_destino");
                definicao.portas = lerPortas(regra);
                const auto severidade = regra.value("severidade", std::string("media"));
                if (regra.contains("severidade") && !regra.at("severidade").is_string()) {
                    throw ExcecaoConfiguracao("Campo severidade deve ser texto");
                }
                definicao.severidade = static_cast<int>(converterSeveridade(severidade));
            } else {
                throw ExcecaoConfiguracao("Tipo de regra desconhecido: " + definicao.tipo);
            }
            configuracao.definicoesRegras_.push_back(std::move(definicao));
        }

        if (configuracao.definicoesRegras_.empty()) {
            throw ExcecaoConfiguracao("Nenhuma regra habilitada foi encontrada");
        }
        return configuracao;
    } catch (const ExcecaoConfiguracao&) {
        throw;
    } catch (const nlohmann::json::exception& excecao) {
        throw ExcecaoConfiguracao("JSON invalido em " + caminho.string() + ": " + excecao.what());
    }
}

const OpcoesCaptura& Configuracao::captura() const noexcept {
    return captura_;
}

const std::filesystem::path& Configuracao::caminhoLog() const noexcept {
    return caminhoLog_;
}

std::vector<std::unique_ptr<Regra>> Configuracao::criarRegras() const {
    std::vector<std::unique_ptr<Regra>> regras;
    regras.reserve(definicoesRegras_.size());
    for (const auto& definicao : definicoesRegras_) {
        if (definicao.tipo == "port_scan") {
            regras.push_back(std::make_unique<RegraPortScan>(definicao.identificador,
                                                             definicao.janela,
                                                             definicao.limite,
                                                             definicao.cooldown));
        } else if (definicao.tipo == "ping_sweep") {
            regras.push_back(std::make_unique<RegraPingSweep>(definicao.identificador,
                                                              definicao.janela,
                                                              definicao.limite,
                                                              definicao.cooldown));
        } else if (definicao.tipo == "acesso_bloqueado") {
            regras.push_back(std::make_unique<RegraAcessoBloqueado>(
                definicao.identificador,
                definicao.ipDestino,
                definicao.portas,
                static_cast<Severidade>(definicao.severidade)));
        }
    }
    return regras;
}

} // namespace sentinela
