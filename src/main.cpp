#include "capture/CapturaPcap.hpp"
#include "core/AnalisadorPacote.hpp"
#include "core/Configuracao.hpp"
#include "core/DespachanteAcoes.hpp"
#include "core/Estatisticas.hpp"
#include "core/MotorRegras.hpp"
#include "exporter/ExportadorJsonl.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Argumentos {
    std::filesystem::path configuracao = "config/sentinela.json";
    std::optional<std::filesystem::path> arquivoPcap;
    std::optional<std::string> interface;
    std::chrono::seconds duracao{30};
    bool ajuda = false;
};

[[noreturn]] void erroUso(const std::string& mensagem) {
    throw std::invalid_argument(mensagem + "\nUse --help para ver os parametros disponiveis.");
}

[[nodiscard]] Argumentos lerArgumentos(const int quantidade, char* argumentos[]) {
    Argumentos resultado;
    for (int indice = 1; indice < quantidade; ++indice) {
        const std::string argumento = argumentos[indice];
        const auto proximo = [&]() -> std::string {
            if (indice + 1 >= quantidade) {
                erroUso("Falta um valor para " + argumento);
            }
            ++indice;
            return argumentos[indice];
        };

        if (argumento == "--help" || argumento == "-h") {
            resultado.ajuda = true;
        } else if (argumento == "--config") {
            resultado.configuracao = proximo();
        } else if (argumento == "--pcap") {
            resultado.arquivoPcap = proximo();
        } else if (argumento == "--interface") {
            resultado.interface = proximo();
        } else if (argumento == "--duracao") {
            try {
                const auto segundos = std::stoll(proximo());
                if (segundos < 0 || segundos > 86400) {
                    erroUso("--duracao deve estar entre 0 e 86400 segundos");
                }
                resultado.duracao = std::chrono::seconds(segundos);
            } catch (const std::invalid_argument&) {
                erroUso("--duracao deve ser um numero inteiro");
            } catch (const std::out_of_range&) {
                erroUso("--duracao esta fora do intervalo permitido");
            }
        } else {
            erroUso("Parametro desconhecido: " + argumento);
        }
    }
    if (resultado.arquivoPcap.has_value() && resultado.interface.has_value()) {
        erroUso("Use apenas uma fonte: --pcap ou --interface");
    }
    return resultado;
}

void imprimirAjuda(std::ostream& saida) {
    saida << "Uso:\n"
          << "  sentinela --config <arquivo.json> --pcap <arquivo.pcap>\n"
          << "  sentinela --config <arquivo.json> [--interface <nome>] [--duracao <segundos>]\n\n"
          << "Opcoes:\n"
          << "  --config <arquivo>     Configuracao JSON (padrao: config/sentinela.json)\n"
          << "  --pcap <arquivo>       Reprocessa um arquivo PCAP Ethernet offline\n"
          << "  --interface <nome>     Substitui a interface definida na configuracao\n"
          << "  --duracao <segundos>   Duracao da captura ao vivo; 0 significa sem limite (padrao: 30)\n"
          << "  --help, -h             Mostra esta ajuda\n";
}

void imprimirResumo(const sentinela::ResumoEstatisticas& resumo) {
    std::cout << "\n--- Estatisticas Sentinela ---\n"
              << "Pacotes analisados: " << resumo.totalPacotes() << '\n'
              << "Pacotes/s: " << std::fixed << std::setprecision(2) << resumo.pacotesPorSegundo() << '\n'
              << "Alertas: " << resumo.totalAlertas() << '\n';

    std::cout << "Principais origens:";
    if (resumo.principaisOrigens().empty()) {
        std::cout << " nenhuma\n";
    } else {
        std::cout << '\n';
        for (const auto& [origem, quantidade] : resumo.principaisOrigens()) {
            std::cout << "  - " << origem << ": " << quantidade << '\n';
        }
    }

    std::cout << "Alertas por regra:";
    if (resumo.alertasPorRegra().empty()) {
        std::cout << " nenhum\n";
    } else {
        std::cout << '\n';
        for (const auto& [regra, quantidade] : resumo.alertasPorRegra()) {
            std::cout << "  - " << regra << ": " << quantidade << '\n';
        }
    }
}

} // namespace

int main(const int quantidade, char* argumentos[]) {
    try {
        const auto argumentosLidos = lerArgumentos(quantidade, argumentos);
        if (argumentosLidos.ajuda) {
            imprimirAjuda(std::cout);
            return 0;
        }

        const auto configuracao = sentinela::Configuracao::carregar(argumentosLidos.configuracao);
        auto opcoesCaptura = configuracao.captura();
        if (argumentosLidos.interface.has_value()) {
            opcoesCaptura = opcoesCaptura.comInterface(*argumentosLidos.interface);
        }
        if (!argumentosLidos.arquivoPcap.has_value() && opcoesCaptura.interface().empty()) {
            erroUso("Informe --pcap, --interface ou captura.interface na configuracao");
        }

        auto exportador = std::make_shared<sentinela::ExportadorJsonl>(configuracao.caminhoLog());
        sentinela::DespachanteAcoes despachante({exportador});
        sentinela::MotorRegras motor(configuracao.criarRegras());
        sentinela::Estatisticas estatisticas;
        sentinela::AnalisadorPacote analisador;
        auto proximaExibicao = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        const auto processarQuadro = [&](const std::uint8_t* dados,
                                         const std::size_t tamanho,
                                         const std::chrono::system_clock::time_point timestamp) {
            auto pacote = analisador.analisar(dados, tamanho, timestamp);
            if (!pacote) {
                return;
            }
            estatisticas.registrarPacote(*pacote);
            for (auto& evento : motor.avaliar(*pacote)) {
                estatisticas.registrarAlerta(evento);
                despachante.despachar(evento);
            }
            if (std::chrono::steady_clock::now() >= proximaExibicao) {
                imprimirResumo(estatisticas.resumo());
                proximaExibicao = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            }
        };

        const sentinela::CapturaPcap captura(opcoesCaptura);
        if (argumentosLidos.arquivoPcap.has_value()) {
            std::cout << "Reprocessando PCAP: " << argumentosLidos.arquivoPcap->string() << '\n';
            captura.processarArquivo(*argumentosLidos.arquivoPcap, processarQuadro);
        } else {
            std::cout << "Capturando em " << opcoesCaptura.interface() << " por "
                      << argumentosLidos.duracao.count() << " segundos...\n";
            captura.capturarAoVivo(argumentosLidos.duracao, processarQuadro);
        }

        imprimirResumo(estatisticas.resumo());
        std::cout << "Eventos estruturados: " << configuracao.caminhoLog().string() << '\n';
        return 0;
    } catch (const std::exception& excecao) {
        std::cerr << "Erro: " << excecao.what() << '\n';
        return 1;
    }
}
