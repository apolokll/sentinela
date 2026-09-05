#include "domain/Pacote.hpp"

#include <utility>

namespace sentinela {

Pacote::Pacote(std::string ipOrigem,
               std::string ipDestino,
               const Protocolo protocolo,
               const std::chrono::system_clock::time_point timestamp,
               const std::size_t tamanhoCapturado)
    : ipOrigem_(std::move(ipOrigem)),
      ipDestino_(std::move(ipDestino)),
      protocolo_(protocolo),
      timestamp_(timestamp),
      tamanhoCapturado_(tamanhoCapturado) {}

const std::string& Pacote::ipOrigem() const noexcept {
    return ipOrigem_;
}

const std::string& Pacote::ipDestino() const noexcept {
    return ipDestino_;
}

Protocolo Pacote::protocolo() const noexcept {
    return protocolo_;
}

std::chrono::system_clock::time_point Pacote::timestamp() const noexcept {
    return timestamp_;
}

std::size_t Pacote::tamanhoCapturado() const noexcept {
    return tamanhoCapturado_;
}

std::optional<std::uint16_t> Pacote::portaOrigem() const noexcept {
    return std::nullopt;
}

std::optional<std::uint16_t> Pacote::portaDestino() const noexcept {
    return std::nullopt;
}

PacoteTcp::PacoteTcp(std::string ipOrigem,
                     std::string ipDestino,
                     const std::chrono::system_clock::time_point timestamp,
                     const std::size_t tamanhoCapturado,
                     const std::uint16_t portaOrigem,
                     const std::uint16_t portaDestino,
                     const bool syn,
                     const bool ack,
                     const bool fin,
                     const bool rst)
    : Pacote(std::move(ipOrigem), std::move(ipDestino), Protocolo::Tcp, timestamp, tamanhoCapturado),
      portaOrigem_(portaOrigem),
      portaDestino_(portaDestino),
      syn_(syn),
      ack_(ack),
      fin_(fin),
      rst_(rst) {}

std::string PacoteTcp::tipo() const {
    return "tcp";
}

std::optional<std::uint16_t> PacoteTcp::portaOrigem() const noexcept {
    return portaOrigem_;
}

std::optional<std::uint16_t> PacoteTcp::portaDestino() const noexcept {
    return portaDestino_;
}

bool PacoteTcp::syn() const noexcept {
    return syn_;
}

bool PacoteTcp::ack() const noexcept {
    return ack_;
}

bool PacoteTcp::fin() const noexcept {
    return fin_;
}

bool PacoteTcp::rst() const noexcept {
    return rst_;
}

PacoteUdp::PacoteUdp(std::string ipOrigem,
                     std::string ipDestino,
                     const std::chrono::system_clock::time_point timestamp,
                     const std::size_t tamanhoCapturado,
                     const std::uint16_t portaOrigem,
                     const std::uint16_t portaDestino)
    : Pacote(std::move(ipOrigem), std::move(ipDestino), Protocolo::Udp, timestamp, tamanhoCapturado),
      portaOrigem_(portaOrigem),
      portaDestino_(portaDestino) {}

std::string PacoteUdp::tipo() const {
    return "udp";
}

std::optional<std::uint16_t> PacoteUdp::portaOrigem() const noexcept {
    return portaOrigem_;
}

std::optional<std::uint16_t> PacoteUdp::portaDestino() const noexcept {
    return portaDestino_;
}

PacoteIcmp::PacoteIcmp(std::string ipOrigem,
                       std::string ipDestino,
                       const std::chrono::system_clock::time_point timestamp,
                       const std::size_t tamanhoCapturado,
                       const std::uint8_t tipoIcmp,
                       const std::uint8_t codigo)
    : Pacote(std::move(ipOrigem), std::move(ipDestino), Protocolo::Icmp, timestamp, tamanhoCapturado),
      tipoIcmp_(tipoIcmp),
      codigo_(codigo) {}

std::string PacoteIcmp::tipo() const {
    return "icmp";
}

std::uint8_t PacoteIcmp::tipoIcmp() const noexcept {
    return tipoIcmp_;
}

std::uint8_t PacoteIcmp::codigo() const noexcept {
    return codigo_;
}

} // namespace sentinela
