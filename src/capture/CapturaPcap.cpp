#include "capture/CapturaPcap.hpp"

#include "core/Excecoes.hpp"

#include <pcap/pcap.h>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <utility>

namespace sentinela {
namespace {

[[nodiscard]] std::chrono::system_clock::time_point converterTimestamp(const timeval& timestamp) {
    return std::chrono::system_clock::time_point{std::chrono::seconds(timestamp.tv_sec) +
                                                 std::chrono::microseconds(timestamp.tv_usec)};
}

struct ContextoCallback {
    const CapturaPcap::AoReceberQuadro* aoReceber = nullptr;
    std::exception_ptr excecao;
};

void aoReceberPacote(u_char* usuario, const pcap_pkthdr* cabecalho, const u_char* dados) {
    auto& contexto = *reinterpret_cast<ContextoCallback*>(usuario);
    if (contexto.excecao != nullptr) {
        return;
    }
    try {
        (*contexto.aoReceber)(dados,
                              static_cast<std::size_t>(cabecalho->caplen),
                              converterTimestamp(cabecalho->ts));
    } catch (...) {
        // Excecoes nunca podem atravessar o callback C da libpcap.
        contexto.excecao = std::current_exception();
    }
}

using ManipuladorPcap = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

[[nodiscard]] ManipuladorPcap assumirManipulador(pcap_t* bruto, const std::string& origem) {
    if (bruto == nullptr) {
        throw ExcecaoCaptura("Nao foi possivel abrir " + origem);
    }
    return ManipuladorPcap(bruto, &pcap_close);
}

void validarEnlaceEthernet(const pcap_t* manipulador) {
    if (pcap_datalink(manipulador) != DLT_EN10MB) {
        throw ExcecaoCaptura("Apenas capturas Ethernet (DLT_EN10MB) sao suportadas neste MVP");
    }
}

void relancarSeNecessario(const ContextoCallback& contexto) {
    if (contexto.excecao != nullptr) {
        std::rethrow_exception(contexto.excecao);
    }
}

} // namespace

CapturaPcap::CapturaPcap(OpcoesCaptura opcoes) : opcoes_(std::move(opcoes)) {}

void CapturaPcap::processarArquivo(const std::filesystem::path& caminho,
                                   const AoReceberQuadro& aoReceber) const {
    std::array<char, PCAP_ERRBUF_SIZE> erro{};
    auto manipulador = assumirManipulador(pcap_open_offline(caminho.c_str(), erro.data()),
                                          "o arquivo PCAP " + caminho.string() + ": " + erro.data());
    validarEnlaceEthernet(manipulador.get());

    ContextoCallback contexto{&aoReceber, nullptr};
    while (true) {
        pcap_pkthdr* cabecalho = nullptr;
        const u_char* dados = nullptr;
        const int resultado = pcap_next_ex(manipulador.get(), &cabecalho, &dados);
        if (resultado == 1) {
            aoReceberPacote(reinterpret_cast<u_char*>(&contexto), cabecalho, dados);
            relancarSeNecessario(contexto);
            continue;
        }
        if (resultado == -2) {
            break;
        }
        if (resultado == 0) {
            continue;
        }
        throw ExcecaoCaptura("Erro durante a leitura de " + caminho.string() + ": " + pcap_geterr(manipulador.get()));
    }
}

void CapturaPcap::capturarAoVivo(const std::chrono::seconds duracao,
                                 const AoReceberQuadro& aoReceber) const {
    if (opcoes_.interface().empty()) {
        throw ExcecaoCaptura("Nenhuma interface foi informada para a captura ao vivo");
    }

    std::array<char, PCAP_ERRBUF_SIZE> erro{};
    auto manipulador = assumirManipulador(
        pcap_open_live(opcoes_.interface().c_str(),
                       opcoes_.snaplen(),
                       opcoes_.modoPromiscuo() ? 1 : 0,
                       opcoes_.timeoutMilissegundos(),
                       erro.data()),
        "a interface " + opcoes_.interface() + ": " + erro.data());
    validarEnlaceEthernet(manipulador.get());

    ContextoCallback contexto{&aoReceber, nullptr};
    const auto inicio = std::chrono::steady_clock::now();
    do {
        const int resultado = pcap_dispatch(manipulador.get(), -1, aoReceberPacote,
                                            reinterpret_cast<u_char*>(&contexto));
        relancarSeNecessario(contexto);
        if (resultado == -1) {
            throw ExcecaoCaptura("Erro durante a captura em " + opcoes_.interface() + ": " +
                                 pcap_geterr(manipulador.get()));
        }
    } while (duracao <= std::chrono::seconds::zero() ||
             std::chrono::steady_clock::now() - inicio < duracao);
}

} // namespace sentinela
