#include "rules/RegraPortScan.hpp"

#include "domain/Pacote.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace sentinela {

RegraPortScan::RegraPortScan(std::string identificador,
                             const std::chrono::seconds janela,
                             const std::size_t minimoPortasDistintas,
                             const std::chrono::seconds cooldown)
    : Regra(std::move(identificador), "Detecta tentativas de conexao em multiplas portas"),
      janela_(janela),
      minimoPortasDistintas_(minimoPortasDistintas),
      cooldown_(cooldown) {
    if (janela_ <= std::chrono::seconds::zero() || minimoPortasDistintas_ == 0 ||
        cooldown_ < std::chrono::seconds::zero()) {
        throw std::invalid_argument("Parametros invalidos para RegraPortScan");
    }
}

std::optional<EventoSeguranca> RegraPortScan::avaliar(const Pacote& pacote) {
    const auto* tcp = dynamic_cast<const PacoteTcp*>(&pacote);
    if (tcp == nullptr || !tcp->syn() || tcp->ack()) {
        return std::nullopt;
    }

    const auto portaDestino = tcp->portaDestino();
    if (!portaDestino.has_value()) {
        return std::nullopt;
    }

    const auto instante = pacote.timestamp();
    std::scoped_lock lock(mutex_);
    auto& estado = estados_[criarChave(pacote)];
    const auto limiteJanela = instante - janela_;
    while (!estado.tentativas.empty() && estado.tentativas.front().instante < limiteJanela) {
        estado.tentativas.pop_front();
    }
    estado.tentativas.push_back(Tentativa{instante, *portaDestino});

    std::unordered_set<std::uint16_t> portas;
    for (const auto& tentativa : estado.tentativas) {
        portas.insert(tentativa.porta);
    }
    if (portas.size() < minimoPortasDistintas_) {
        return std::nullopt;
    }
    if (estado.ultimoAlerta.has_value() && instante - *estado.ultimoAlerta < cooldown_) {
        return std::nullopt;
    }

    estado.ultimoAlerta = instante;
    std::ostringstream mensagem;
    mensagem << "Possivel varredura de portas: " << portas.size() << " portas distintas em "
             << janela_.count() << "s";
    return EventoSeguranca(identificador(), Severidade::Alta, mensagem.str(), TipoAcao::Alertar, pacote);
}

void RegraPortScan::reiniciar() {
    std::scoped_lock lock(mutex_);
    estados_.clear();
}

std::string RegraPortScan::criarChave(const Pacote& pacote) {
    return pacote.ipOrigem() + "->" + pacote.ipDestino();
}

} // namespace sentinela
