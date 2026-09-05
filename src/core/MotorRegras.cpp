#include "core/MotorRegras.hpp"

#include "core/Regra.hpp"
#include "domain/Pacote.hpp"

#include <utility>

namespace sentinela {

MotorRegras::MotorRegras(std::vector<std::unique_ptr<Regra>> regras) : regras_(std::move(regras)) {}

std::vector<EventoSeguranca> MotorRegras::avaliar(const Pacote& pacote) {
    std::vector<EventoSeguranca> eventos;
    for (const auto& regra : regras_) {
        if (auto evento = regra->avaliar(pacote); evento.has_value()) {
            eventos.push_back(std::move(*evento));
        }
    }
    return eventos;
}

std::size_t MotorRegras::quantidadeRegras() const noexcept {
    return regras_.size();
}

void MotorRegras::reiniciar() {
    for (const auto& regra : regras_) {
        regra->reiniciar();
    }
}

} // namespace sentinela
