#include "rules/RegraAcessoBloqueado.hpp"

#include "domain/Pacote.hpp"

#include <sstream>
#include <utility>

namespace sentinela {

RegraAcessoBloqueado::RegraAcessoBloqueado(std::string identificador,
                                           std::string ipDestino,
                                           std::vector<std::uint16_t> portasBloqueadas,
                                           const Severidade severidade)
    : Regra(std::move(identificador), "Detecta acesso a destino ou porta sob politica de bloqueio"),
      ipDestino_(std::move(ipDestino)),
      portasBloqueadas_(portasBloqueadas.begin(), portasBloqueadas.end()),
      severidade_(severidade) {}

std::optional<EventoSeguranca> RegraAcessoBloqueado::avaliar(const Pacote& pacote) {
    if (pacote.ipDestino() != ipDestino_) {
        return std::nullopt;
    }

    const auto portaDestino = pacote.portaDestino();
    if (!portasBloqueadas_.empty() &&
        (!portaDestino.has_value() || !portasBloqueadas_.contains(*portaDestino))) {
        return std::nullopt;
    }

    std::ostringstream mensagem;
    mensagem << "Acesso a destino protegido " << ipDestino_;
    if (portaDestino.has_value()) {
        mensagem << ':' << *portaDestino;
    }
    return EventoSeguranca(identificador(), severidade_, mensagem.str(), TipoAcao::Alertar, pacote);
}

void RegraAcessoBloqueado::reiniciar() {
    // Esta regra nao possui estado temporal.
}

} // namespace sentinela
