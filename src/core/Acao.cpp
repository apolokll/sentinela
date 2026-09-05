#include "core/Acao.hpp"

#include "core/EventoSeguranca.hpp"
#include "exporter/Exportador.hpp"

namespace sentinela {
namespace {

void exportarParaTodos(const EventoSeguranca& evento,
                       const std::vector<std::shared_ptr<Exportador>>& exportadores) {
    for (const auto& exportador : exportadores) {
        if (exportador) {
            exportador->exportar(evento);
        }
    }
}

} // namespace

TipoAcao AcaoRegistrar::tipo() const noexcept {
    return TipoAcao::Registrar;
}

std::string AcaoRegistrar::nome() const {
    return "registrar";
}

void AcaoRegistrar::executar(const EventoSeguranca& evento,
                             const std::vector<std::shared_ptr<Exportador>>& exportadores) const {
    exportarParaTodos(evento, exportadores);
}

TipoAcao AcaoAlertar::tipo() const noexcept {
    return TipoAcao::Alertar;
}

std::string AcaoAlertar::nome() const {
    return "alertar";
}

void AcaoAlertar::executar(const EventoSeguranca& evento,
                           const std::vector<std::shared_ptr<Exportador>>& exportadores) const {
    exportarParaTodos(evento, exportadores);
}

TipoAcao AcaoPermitir::tipo() const noexcept {
    return TipoAcao::Permitir;
}

std::string AcaoPermitir::nome() const {
    return "permitir";
}

void AcaoPermitir::executar(const EventoSeguranca& evento,
                            const std::vector<std::shared_ptr<Exportador>>& exportadores) const {
    // Na Entrega 1, a decisao e auditada. O veredito NFQUEUE entra na Entrega 2.
    exportarParaTodos(evento, exportadores);
}

TipoAcao AcaoDescartar::tipo() const noexcept {
    return TipoAcao::Descartar;
}

std::string AcaoDescartar::nome() const {
    return "descartar";
}

void AcaoDescartar::executar(const EventoSeguranca& evento,
                             const std::vector<std::shared_ptr<Exportador>>& exportadores) const {
    // Na Entrega 1, a decisao e auditada. O veredito NFQUEUE entra na Entrega 2.
    exportarParaTodos(evento, exportadores);
}

} // namespace sentinela
