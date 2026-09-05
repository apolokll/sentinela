#include "core/AnalisadorPacote.hpp"
#include "domain/Pacote.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

namespace sentinela {
namespace {

constexpr auto timestampTeste = std::chrono::system_clock::time_point{std::chrono::seconds{12345}};

void adicionarU16EmOrdemDeRede(std::vector<std::uint8_t>& quadro, const std::uint16_t valor) {
    quadro.push_back(static_cast<std::uint8_t>(valor >> 8U));
    quadro.push_back(static_cast<std::uint8_t>(valor & 0x00FFU));
}

std::vector<std::uint8_t> criarQuadroIpv4(const std::uint8_t protocolo,
                                           const std::vector<std::uint8_t>& dadosTransporte,
                                           const bool vlan = false) {
    std::vector<std::uint8_t> quadro{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC de destino
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // MAC de origem
    };

    if (vlan) {
        adicionarU16EmOrdemDeRede(quadro, 0x8100);
        adicionarU16EmOrdemDeRede(quadro, 42);
    }
    adicionarU16EmOrdemDeRede(quadro, 0x0800);

    const std::size_t tamanhoIpv4 = 20U + dadosTransporte.size();
    ASSERT_LE(tamanhoIpv4, 0xFFFFU);

    quadro.insert(quadro.end(), {
        0x45, // IPv4, IHL 5
        0x00,
    });
    adicionarU16EmOrdemDeRede(quadro, static_cast<std::uint16_t>(tamanhoIpv4));
    quadro.insert(quadro.end(), {
        0x00, 0x01, // identification
        0x00, 0x00, // flags e deslocamento de fragmento
        64,         // TTL
        protocolo,
        0x00, 0x00, // checksum, não é validado pelo parser
        192, 0, 2, 10,
        198, 51, 100, 7,
    });
    quadro.insert(quadro.end(), dadosTransporte.begin(), dadosTransporte.end());
    return quadro;
}

std::vector<std::uint8_t> criarTcp(const std::uint8_t flags) {
    return {
        0xC3, 0x50, // 50000
        0x00, 0x16, // 22
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, flags, // data offset 5 e flags
        0x20, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    };
}

std::vector<std::uint8_t> criarUdp() {
    return {
        0x30, 0x39, // 12345
        0x00, 0x35, // 53
        0x00, 0x08, // tamanho do datagrama UDP
        0x00, 0x00,
    };
}

TEST(AnalisadorPacoteTest, AnalisaTcpEFlags) {
    const auto quadro = criarQuadroIpv4(6, criarTcp(0x13)); // FIN, SYN e ACK
    const AnalisadorPacote analisador;

    const std::unique_ptr<Pacote> pacote = analisador.analisar(quadro.data(), quadro.size(), timestampTeste);

    ASSERT_NE(pacote, nullptr);
    const auto* tcp = dynamic_cast<const PacoteTcp*>(pacote.get());
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->ipOrigem(), "192.0.2.10");
    EXPECT_EQ(tcp->ipDestino(), "198.51.100.7");
    EXPECT_EQ(tcp->portaOrigem(), 50000);
    EXPECT_EQ(tcp->portaDestino(), 22);
    EXPECT_TRUE(tcp->syn());
    EXPECT_TRUE(tcp->ack());
    EXPECT_TRUE(tcp->fin());
    EXPECT_FALSE(tcp->rst());
    EXPECT_EQ(tcp->timestamp(), timestampTeste);
    EXPECT_EQ(tcp->tamanhoCapturado(), quadro.size());
}

TEST(AnalisadorPacoteTest, AnalisaTcpComUmaTagVlan) {
    const auto quadro = criarQuadroIpv4(6, criarTcp(0x02), true);
    const AnalisadorPacote analisador;

    const std::unique_ptr<Pacote> pacote = analisador.analisar(quadro.data(), quadro.size(), timestampTeste);

    ASSERT_NE(pacote, nullptr);
    EXPECT_NE(dynamic_cast<const PacoteTcp*>(pacote.get()), nullptr);
}

TEST(AnalisadorPacoteTest, AnalisaUdp) {
    const auto quadro = criarQuadroIpv4(17, criarUdp());
    const AnalisadorPacote analisador;

    const std::unique_ptr<Pacote> pacote = analisador.analisar(quadro.data(), quadro.size(), timestampTeste);

    ASSERT_NE(pacote, nullptr);
    const auto* udp = dynamic_cast<const PacoteUdp*>(pacote.get());
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(udp->portaOrigem(), 12345);
    EXPECT_EQ(udp->portaDestino(), 53);
}

TEST(AnalisadorPacoteTest, AnalisaIcmp) {
    const auto quadro = criarQuadroIpv4(1, {8, 0, 0, 0});
    const AnalisadorPacote analisador;

    const std::unique_ptr<Pacote> pacote = analisador.analisar(quadro.data(), quadro.size(), timestampTeste);

    ASSERT_NE(pacote, nullptr);
    const auto* icmp = dynamic_cast<const PacoteIcmp*>(pacote.get());
    ASSERT_NE(icmp, nullptr);
    EXPECT_EQ(icmp->tipoIcmp(), 8);
    EXPECT_EQ(icmp->codigo(), 0);
}

TEST(AnalisadorPacoteTest, RejeitaPacoteTruncado) {
    auto quadro = criarQuadroIpv4(6, criarTcp(0x02));
    quadro.pop_back();
    const AnalisadorPacote analisador;

    const std::unique_ptr<Pacote> pacote = analisador.analisar(quadro.data(), quadro.size(), timestampTeste);

    EXPECT_EQ(pacote, nullptr);
}

TEST(AnalisadorPacoteTest, RejeitaProtocoloIpv4NaoSuportado) {
    const auto quadro = criarQuadroIpv4(47, {0, 0, 0, 0}); // GRE
    const AnalisadorPacote analisador;

    const std::unique_ptr<Pacote> pacote = analisador.analisar(quadro.data(), quadro.size(), timestampTeste);

    EXPECT_EQ(pacote, nullptr);
}

} // namespace
} // namespace sentinela
