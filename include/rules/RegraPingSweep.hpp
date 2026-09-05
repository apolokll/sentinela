#pragma once

#include "core/Regra.hpp"

#include <chrono>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace sentinela {

class RegraPingSweep final : public Regra {
public:
    RegraPingSweep(std::string identificador,
                   std::chrono::seconds janela,
                   std::size_t minimoDestinosDistintos,
                   std::chrono::seconds cooldown);

    [[nodiscard]] std::optional<EventoSeguranca> avaliar(const Pacote& pacote) override;
    void reiniciar() override;

private:
    struct Sondagem {
        std::chrono::system_clock::time_point instante;
        std::string destino;
    };

    struct Estado {
        std::deque<Sondagem> sondagens;
        std::optional<std::chrono::system_clock::time_point> ultimoAlerta;
    };

    std::chrono::seconds janela_;
    std::size_t minimoDestinosDistintos_;
    std::chrono::seconds cooldown_;
    std::unordered_map<std::string, Estado> estados_;
    std::mutex mutex_;
};

} // namespace sentinela
