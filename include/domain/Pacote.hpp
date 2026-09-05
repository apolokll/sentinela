#pragma once

#include "core/Tipos.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace sentinela {

class Pacote {
public:
    virtual ~Pacote() = default;

    [[nodiscard]] const std::string& ipOrigem() const noexcept;
    [[nodiscard]] const std::string& ipDestino() const noexcept;
    [[nodiscard]] Protocolo protocolo() const noexcept;
    [[nodiscard]] std::chrono::system_clock::time_point timestamp() const noexcept;
    [[nodiscard]] std::size_t tamanhoCapturado() const noexcept;

    [[nodiscard]] virtual std::string tipo() const = 0;
    [[nodiscard]] virtual std::optional<std::uint16_t> portaOrigem() const noexcept;
    [[nodiscard]] virtual std::optional<std::uint16_t> portaDestino() const noexcept;

protected:
    Pacote(std::string ipOrigem,
           std::string ipDestino,
           Protocolo protocolo,
           std::chrono::system_clock::time_point timestamp,
           std::size_t tamanhoCapturado);

private:
    std::string ipOrigem_;
    std::string ipDestino_;
    Protocolo protocolo_;
    std::chrono::system_clock::time_point timestamp_;
    std::size_t tamanhoCapturado_;
};

class PacoteTcp final : public Pacote {
public:
    PacoteTcp(std::string ipOrigem,
              std::string ipDestino,
              std::chrono::system_clock::time_point timestamp,
              std::size_t tamanhoCapturado,
              std::uint16_t portaOrigem,
              std::uint16_t portaDestino,
              bool syn,
              bool ack,
              bool fin,
              bool rst);

    [[nodiscard]] std::string tipo() const override;
    [[nodiscard]] std::optional<std::uint16_t> portaOrigem() const noexcept override;
    [[nodiscard]] std::optional<std::uint16_t> portaDestino() const noexcept override;
    [[nodiscard]] bool syn() const noexcept;
    [[nodiscard]] bool ack() const noexcept;
    [[nodiscard]] bool fin() const noexcept;
    [[nodiscard]] bool rst() const noexcept;

private:
    std::uint16_t portaOrigem_;
    std::uint16_t portaDestino_;
    bool syn_;
    bool ack_;
    bool fin_;
    bool rst_;
};

class PacoteUdp final : public Pacote {
public:
    PacoteUdp(std::string ipOrigem,
              std::string ipDestino,
              std::chrono::system_clock::time_point timestamp,
              std::size_t tamanhoCapturado,
              std::uint16_t portaOrigem,
              std::uint16_t portaDestino);

    [[nodiscard]] std::string tipo() const override;
    [[nodiscard]] std::optional<std::uint16_t> portaOrigem() const noexcept override;
    [[nodiscard]] std::optional<std::uint16_t> portaDestino() const noexcept override;

private:
    std::uint16_t portaOrigem_;
    std::uint16_t portaDestino_;
};

class PacoteIcmp final : public Pacote {
public:
    PacoteIcmp(std::string ipOrigem,
               std::string ipDestino,
               std::chrono::system_clock::time_point timestamp,
               std::size_t tamanhoCapturado,
               std::uint8_t tipoIcmp,
               std::uint8_t codigo);

    [[nodiscard]] std::string tipo() const override;
    [[nodiscard]] std::uint8_t tipoIcmp() const noexcept;
    [[nodiscard]] std::uint8_t codigo() const noexcept;

private:
    std::uint8_t tipoIcmp_;
    std::uint8_t codigo_;
};

} // namespace sentinela
