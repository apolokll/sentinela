#pragma once

#include "core/Tipos.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace sentinela {

class Pacote;

class EventoSeguranca final {
public:
    EventoSeguranca(std::string identificadorRegra,
                    Severidade severidade,
                    std::string mensagem,
                    TipoAcao acaoSugerida,
                    const Pacote& pacote);

    [[nodiscard]] const std::string& identificadorRegra() const noexcept;
    [[nodiscard]] Severidade severidade() const noexcept;
    [[nodiscard]] const std::string& mensagem() const noexcept;
    [[nodiscard]] TipoAcao acaoSugerida() const noexcept;
    [[nodiscard]] const std::string& ipOrigem() const noexcept;
    [[nodiscard]] const std::string& ipDestino() const noexcept;
    [[nodiscard]] Protocolo protocolo() const noexcept;
    [[nodiscard]] std::optional<std::uint16_t> portaOrigem() const noexcept;
    [[nodiscard]] std::optional<std::uint16_t> portaDestino() const noexcept;
    [[nodiscard]] std::chrono::system_clock::time_point timestamp() const noexcept;

private:
    std::string identificadorRegra_;
    Severidade severidade_;
    std::string mensagem_;
    TipoAcao acaoSugerida_;
    std::string ipOrigem_;
    std::string ipDestino_;
    Protocolo protocolo_;
    std::optional<std::uint16_t> portaOrigem_;
    std::optional<std::uint16_t> portaDestino_;
    std::chrono::system_clock::time_point timestamp_;
};

} // namespace sentinela
