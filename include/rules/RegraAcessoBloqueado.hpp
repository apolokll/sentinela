#pragma once

#include "core/Regra.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace sentinela {

class RegraAcessoBloqueado final : public Regra {
public:
    RegraAcessoBloqueado(std::string identificador,
                         std::string ipDestino,
                         std::vector<std::uint16_t> portasBloqueadas,
                         Severidade severidade = Severidade::Media);

    [[nodiscard]] std::optional<EventoSeguranca> avaliar(const Pacote& pacote) override;
    void reiniciar() override;

private:
    std::string ipDestino_;
    std::unordered_set<std::uint16_t> portasBloqueadas_;
    Severidade severidade_;
};

} // namespace sentinela
