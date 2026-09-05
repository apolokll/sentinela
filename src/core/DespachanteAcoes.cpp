#include "core/DespachanteAcoes.hpp"

#include "core/Acao.hpp"
#include "core/EventoSeguranca.hpp"

#include <stdexcept>
#include <utility>

namespace sentinela {

DespachanteAcoes::DespachanteAcoes(std::vector<std::shared_ptr<Exportador>> exportadores)
    : exportadores_(std::move(exportadores)) {
    acoes_.emplace(TipoAcao::Registrar, std::make_unique<AcaoRegistrar>());
    acoes_.emplace(TipoAcao::Alertar, std::make_unique<AcaoAlertar>());
    acoes_.emplace(TipoAcao::Permitir, std::make_unique<AcaoPermitir>());
    acoes_.emplace(TipoAcao::Descartar, std::make_unique<AcaoDescartar>());
}

void DespachanteAcoes::despachar(const EventoSeguranca& evento) const {
    const auto encontrado = acoes_.find(evento.acaoSugerida());
    if (encontrado == acoes_.end()) {
        throw std::logic_error("Nenhuma estrategia de acao foi registrada");
    }
    encontrado->second->executar(evento, exportadores_);
}

std::size_t DespachanteAcoes::quantidadeExportadores() const noexcept {
    return exportadores_.size();
}

} // namespace sentinela
