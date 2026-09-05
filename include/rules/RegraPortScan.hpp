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

class RegraPortScan final : public Regra {
public:
    RegraPortScan(std::string identificador,
                  std::chrono::seconds janela,
                  std::size_t minimoPortasDistintas,
                  std::chrono::seconds cooldown);

    [[nodiscard]] std::optional<EventoSeguranca> avaliar(const Pacote& pacote) override;
    void reiniciar() override;

private:
    struct Tentativa {
        std::chrono::system_clock::time_point instante;
        std::uint16_t porta;
    };

    struct Estado {
        std::deque<Tentativa> tentativas;
        std::optional<std::chrono::system_clock::time_point> ultimoAlerta;
    };

    [[nodiscard]] static std::string criarChave(const Pacote& pacote);

    std::chrono::seconds janela_;
    std::size_t minimoPortasDistintas_;
    std::chrono::seconds cooldown_;
    std::unordered_map<std::string, Estado> estados_;
    std::mutex mutex_;
};

} // namespace sentinela
