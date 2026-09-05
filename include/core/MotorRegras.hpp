#pragma once

#include "core/EventoSeguranca.hpp"

#include <memory>
#include <vector>

namespace sentinela {

class Pacote;
class Regra;

class MotorRegras final {
public:
    explicit MotorRegras(std::vector<std::unique_ptr<Regra>> regras);

    [[nodiscard]] std::vector<EventoSeguranca> avaliar(const Pacote& pacote);
    [[nodiscard]] std::size_t quantidadeRegras() const noexcept;
    void reiniciar();

private:
    std::vector<std::unique_ptr<Regra>> regras_;
};

} // namespace sentinela
