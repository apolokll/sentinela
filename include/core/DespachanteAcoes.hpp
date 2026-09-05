#pragma once

#include "core/Tipos.hpp"

#include <map>
#include <memory>
#include <vector>

namespace sentinela {

class Acao;
class EventoSeguranca;
class Exportador;

class DespachanteAcoes final {
public:
    explicit DespachanteAcoes(std::vector<std::shared_ptr<Exportador>> exportadores);

    void despachar(const EventoSeguranca& evento) const;
    [[nodiscard]] std::size_t quantidadeExportadores() const noexcept;

private:
    std::map<TipoAcao, std::unique_ptr<Acao>> acoes_;
    std::vector<std::shared_ptr<Exportador>> exportadores_;
};

} // namespace sentinela
