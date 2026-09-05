#pragma once

#include "core/EventoSeguranca.hpp"

#include <optional>
#include <string>

namespace sentinela {

class Pacote;

class Regra {
public:
    virtual ~Regra() = default;

    [[nodiscard]] const std::string& identificador() const noexcept;
    [[nodiscard]] const std::string& descricao() const noexcept;
    [[nodiscard]] virtual std::optional<EventoSeguranca> avaliar(const Pacote& pacote) = 0;
    virtual void reiniciar() = 0;

protected:
    Regra(std::string identificador, std::string descricao);

private:
    std::string identificador_;
    std::string descricao_;
};

} // namespace sentinela
