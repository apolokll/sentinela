#include "core/Estatisticas.hpp"

#include "core/EventoSeguranca.hpp"
#include "domain/Pacote.hpp"

#include <algorithm>
#include <iterator>

namespace sentinela {

std::uint64_t ResumoEstatisticas::totalPacotes() const noexcept {
    return totalPacotes_;
}

std::uint64_t ResumoEstatisticas::totalAlertas() const noexcept {
    return totalAlertas_;
}

double ResumoEstatisticas::pacotesPorSegundo() const noexcept {
    return pacotesPorSegundo_;
}

const std::vector<std::pair<std::string, std::uint64_t>>& ResumoEstatisticas::principaisOrigens() const noexcept {
    return principaisOrigens_;
}

const std::vector<std::pair<std::string, std::uint64_t>>& ResumoEstatisticas::alertasPorRegra() const noexcept {
    return alertasPorRegra_;
}

Estatisticas::Estatisticas() : inicio_(std::chrono::steady_clock::now()) {}

void Estatisticas::registrarPacote(const Pacote& pacote) {
    std::scoped_lock lock(mutex_);
    ++totalPacotes_;
    ++pacotesPorOrigem_[pacote.ipOrigem()];
}

void Estatisticas::registrarAlerta(const EventoSeguranca& evento) {
    std::scoped_lock lock(mutex_);
    ++totalAlertas_;
    ++alertasPorRegra_[evento.identificadorRegra()];
}

ResumoEstatisticas Estatisticas::resumo(const std::size_t limiteOrigens) const {
    std::scoped_lock lock(mutex_);

    ResumoEstatisticas resultado;
    resultado.totalPacotes_ = totalPacotes_;
    resultado.totalAlertas_ = totalAlertas_;
    const auto decorrido = std::chrono::duration<double>(std::chrono::steady_clock::now() - inicio_).count();
    resultado.pacotesPorSegundo_ = decorrido > 0.0 ? static_cast<double>(totalPacotes_) / decorrido : 0.0;

    resultado.principaisOrigens_.assign(pacotesPorOrigem_.begin(), pacotesPorOrigem_.end());
    std::ranges::sort(resultado.principaisOrigens_, [](const auto& esquerdo, const auto& direito) {
        if (esquerdo.second != direito.second) {
            return esquerdo.second > direito.second;
        }
        return esquerdo.first < direito.first;
    });
    if (resultado.principaisOrigens_.size() > limiteOrigens) {
        resultado.principaisOrigens_.resize(limiteOrigens);
    }

    resultado.alertasPorRegra_.assign(alertasPorRegra_.begin(), alertasPorRegra_.end());
    std::ranges::sort(resultado.alertasPorRegra_, [](const auto& esquerdo, const auto& direito) {
        if (esquerdo.second != direito.second) {
            return esquerdo.second > direito.second;
        }
        return esquerdo.first < direito.first;
    });
    return resultado;
}

} // namespace sentinela
