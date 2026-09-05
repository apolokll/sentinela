#include "core/AnalisadorPacote.hpp"

#include "domain/Pacote.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace sentinela {
namespace {

constexpr std::size_t tamanhoCabecalhoEthernet = 14;
constexpr std::size_t tamanhoTagVlan = 4;
constexpr std::size_t tamanhoMinimoIpv4 = 20;
constexpr std::size_t tamanhoMinimoTcp = 20;
constexpr std::size_t tamanhoCabecalhoUdp = 8;
constexpr std::size_t tamanhoMinimoIcmp = 4;

constexpr std::uint16_t etherTypeIpv4 = 0x0800;
constexpr std::uint16_t etherTypeVlan = 0x8100;
constexpr std::uint16_t etherTypeVlanProvedor = 0x88A8;

constexpr std::uint8_t protocoloIcmp = 1;
constexpr std::uint8_t protocoloTcp = 6;
constexpr std::uint8_t protocoloUdp = 17;

[[nodiscard]] bool possuiBytes(const std::size_t tamanho,
                                const std::size_t deslocamento,
                                const std::size_t quantidade) noexcept {
    return deslocamento <= tamanho && quantidade <= tamanho - deslocamento;
}

[[nodiscard]] std::uint16_t lerU16EmOrdemDeRede(const std::uint8_t* dados) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(dados[0]) << 8U) | static_cast<std::uint16_t>(dados[1]));
}

[[nodiscard]] std::string paraTextoIpv4(const std::uint8_t* endereco) {
    return std::to_string(static_cast<unsigned int>(endereco[0])) + "." +
           std::to_string(static_cast<unsigned int>(endereco[1])) + "." +
           std::to_string(static_cast<unsigned int>(endereco[2])) + "." +
           std::to_string(static_cast<unsigned int>(endereco[3]));
}

} // namespace

std::unique_ptr<Pacote> AnalisadorPacote::analisar(
    const std::uint8_t* const dados,
    const std::size_t tamanho,
    const std::chrono::system_clock::time_point timestamp) const {
    if (dados == nullptr || !possuiBytes(tamanho, 0, tamanhoCabecalhoEthernet)) {
        return nullptr;
    }

    std::size_t deslocamentoRede = tamanhoCabecalhoEthernet;
    std::uint16_t etherType = lerU16EmOrdemDeRede(dados + 12);

    // Uma tag 802.1Q/802.1ad ocupa quatro bytes entre o cabeçalho Ethernet e o IP.
    if (etherType == etherTypeVlan || etherType == etherTypeVlanProvedor) {
        if (!possuiBytes(tamanho, deslocamentoRede, tamanhoTagVlan)) {
            return nullptr;
        }
        etherType = lerU16EmOrdemDeRede(dados + deslocamentoRede + 2);
        deslocamentoRede += tamanhoTagVlan;
    }

    if (etherType != etherTypeIpv4 || !possuiBytes(tamanho, deslocamentoRede, tamanhoMinimoIpv4)) {
        return nullptr;
    }

    const std::uint8_t versaoEIhl = dados[deslocamentoRede];
    const std::uint8_t versao = static_cast<std::uint8_t>(versaoEIhl >> 4U);
    const std::size_t tamanhoCabecalhoIpv4 =
        static_cast<std::size_t>(versaoEIhl & static_cast<std::uint8_t>(0x0FU)) * 4U;

    if (versao != 4U || tamanhoCabecalhoIpv4 < tamanhoMinimoIpv4 ||
        !possuiBytes(tamanho, deslocamentoRede, tamanhoCabecalhoIpv4)) {
        return nullptr;
    }

    const std::size_t tamanhoTotalIpv4 =
        static_cast<std::size_t>(lerU16EmOrdemDeRede(dados + deslocamentoRede + 2));
    if (tamanhoTotalIpv4 < tamanhoCabecalhoIpv4 ||
        !possuiBytes(tamanho, deslocamentoRede, tamanhoTotalIpv4)) {
        return nullptr;
    }

    const std::uint16_t campoFragmentacao = lerU16EmOrdemDeRede(dados + deslocamentoRede + 6);
    constexpr std::uint16_t mascaraDeslocamentoFragmento = 0x1FFF;
    if ((campoFragmentacao & mascaraDeslocamentoFragmento) != 0U) {
        // Fragmentos posteriores não contêm, necessariamente, o cabeçalho de transporte.
        return nullptr;
    }

    const std::size_t deslocamentoTransporte = deslocamentoRede + tamanhoCabecalhoIpv4;
    const std::size_t tamanhoDadosIpv4 = tamanhoTotalIpv4 - tamanhoCabecalhoIpv4;
    const std::string ipOrigem = paraTextoIpv4(dados + deslocamentoRede + 12);
    const std::string ipDestino = paraTextoIpv4(dados + deslocamentoRede + 16);
    const std::uint8_t protocolo = dados[deslocamentoRede + 9];

    switch (protocolo) {
    case protocoloTcp: {
        if (tamanhoDadosIpv4 < tamanhoMinimoTcp ||
            !possuiBytes(tamanho, deslocamentoTransporte, tamanhoMinimoTcp)) {
            return nullptr;
        }

        const std::size_t tamanhoCabecalhoTcp =
            static_cast<std::size_t>(dados[deslocamentoTransporte + 12] >> 4U) * 4U;
        if (tamanhoCabecalhoTcp < tamanhoMinimoTcp || tamanhoCabecalhoTcp > tamanhoDadosIpv4 ||
            !possuiBytes(tamanho, deslocamentoTransporte, tamanhoCabecalhoTcp)) {
            return nullptr;
        }

        const std::uint8_t flags = dados[deslocamentoTransporte + 13];
        constexpr std::uint8_t flagFin = 0x01;
        constexpr std::uint8_t flagSyn = 0x02;
        constexpr std::uint8_t flagRst = 0x04;
        constexpr std::uint8_t flagAck = 0x10;

        return std::make_unique<PacoteTcp>(
            ipOrigem,
            ipDestino,
            timestamp,
            tamanho,
            lerU16EmOrdemDeRede(dados + deslocamentoTransporte),
            lerU16EmOrdemDeRede(dados + deslocamentoTransporte + 2),
            (flags & flagSyn) != 0U,
            (flags & flagAck) != 0U,
            (flags & flagFin) != 0U,
            (flags & flagRst) != 0U);
    }
    case protocoloUdp: {
        if (tamanhoDadosIpv4 < tamanhoCabecalhoUdp ||
            !possuiBytes(tamanho, deslocamentoTransporte, tamanhoCabecalhoUdp)) {
            return nullptr;
        }

        const std::size_t tamanhoDatagramaUdp =
            static_cast<std::size_t>(lerU16EmOrdemDeRede(dados + deslocamentoTransporte + 4));
        if (tamanhoDatagramaUdp < tamanhoCabecalhoUdp || tamanhoDatagramaUdp > tamanhoDadosIpv4) {
            return nullptr;
        }

        return std::make_unique<PacoteUdp>(
            ipOrigem,
            ipDestino,
            timestamp,
            tamanho,
            lerU16EmOrdemDeRede(dados + deslocamentoTransporte),
            lerU16EmOrdemDeRede(dados + deslocamentoTransporte + 2));
    }
    case protocoloIcmp:
        if (tamanhoDadosIpv4 < tamanhoMinimoIcmp ||
            !possuiBytes(tamanho, deslocamentoTransporte, tamanhoMinimoIcmp)) {
            return nullptr;
        }

        return std::make_unique<PacoteIcmp>(
            ipOrigem,
            ipDestino,
            timestamp,
            tamanho,
            dados[deslocamentoTransporte],
            dados[deslocamentoTransporte + 1]);
    default:
        return nullptr;
    }
}

} // namespace sentinela
