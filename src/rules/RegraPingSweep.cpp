#include "rules/RegraPingSweep.hpp"

#include "domain/Pacote.hpp"

#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace sentinela {

RegraPingSweep::RegraPingSweep(std::string identificador,
                               const std::chrono::seconds janela,
                               const std::size_t minimoDestinosDistintos,
                               const std::chrono::seconds cooldown)
    : Regra(std::move(identificador), "Detecta echo requests ICMP para multiplos destinos"),
      janela_(janela),
      minimoDestinosDistintos_(minimoDestinosDistintos),
      cooldown_(cooldown) {
    if (janela_ <= std::chrono::seconds::zero() || minimoDestinosDistintos_ == 0 ||
        cooldown_ < std::chrono::seconds::zero()) {
        throw std::invalid_argument("Parametros invalidos para RegraPingSweep");
    }
}

std::optional<EventoSeguranca> RegraPingSweep::avaliar(const Pacote& pacote) {
    const auto* icmp = dynamic_cast<const PacoteIcmp*>(&pacote);
    if (icmp == nullptr || icmp->tipoIcmp() != 8U) {
        return std::nullopt;
    }

    const auto instante = pacote.timestamp();
    std::scoped_lock lock(mutex_);
    auto& estado = estados_[pacote.ipOrigem()];
    const auto limiteJanela = instante - janela_;
    while (!estado.sondagens.empty() && estado.sondagens.front().instante < limiteJanela) {
        estado.sondagens.pop_front();
    }
    estado.sondagens.push_back(Sondagem{instante, pacote.ipDestino()});

    std::unordered_set<std::string> destinos;
    for (const auto& sondagem : estado.sondagens) {
        destinos.insert(sondagem.destino);
    }
    if (destinos.size() < minimoDestinosDistintos_) {
        return std::nullopt;
    }
    if (estado.ultimoAlerta.has_value() && instante - *estado.ultimoAlerta < cooldown_) {
        return std::nullopt;
    }

    estado.ultimoAlerta = instante;
    std::ostringstream mensagem;
    mensagem << "Possivel ping sweep: " << destinos.size() << " destinos distintos em "
             << janela_.count() << "s";
    return EventoSeguranca(identificador(), Severidade::Media, mensagem.str(), TipoAcao::Alertar, pacote);
}

void RegraPingSweep::reiniciar() {
    std::scoped_lock lock(mutex_);
    estados_.clear();
}

} // namespace sentinela
