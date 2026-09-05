#pragma once

#include <string>

namespace sentinela {

class EventoSeguranca;

class Exportador {
public:
    virtual ~Exportador() = default;

    [[nodiscard]] virtual std::string nome() const = 0;
    virtual void exportar(const EventoSeguranca& evento) = 0;
};

} // namespace sentinela
