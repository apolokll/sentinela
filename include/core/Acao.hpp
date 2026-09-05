#pragma once

#include "core/Tipos.hpp"

#include <memory>
#include <string>
#include <vector>

namespace sentinela {

class EventoSeguranca;
class Exportador;

class Acao {
public:
    virtual ~Acao() = default;

    [[nodiscard]] virtual TipoAcao tipo() const noexcept = 0;
    [[nodiscard]] virtual std::string nome() const = 0;
    virtual void executar(const EventoSeguranca& evento,
                          const std::vector<std::shared_ptr<Exportador>>& exportadores) const = 0;
};

class AcaoRegistrar final : public Acao {
public:
    [[nodiscard]] TipoAcao tipo() const noexcept override;
    [[nodiscard]] std::string nome() const override;
    void executar(const EventoSeguranca& evento,
                  const std::vector<std::shared_ptr<Exportador>>& exportadores) const override;
};

class AcaoAlertar final : public Acao {
public:
    [[nodiscard]] TipoAcao tipo() const noexcept override;
    [[nodiscard]] std::string nome() const override;
    void executar(const EventoSeguranca& evento,
                  const std::vector<std::shared_ptr<Exportador>>& exportadores) const override;
};

class AcaoPermitir final : public Acao {
public:
    [[nodiscard]] TipoAcao tipo() const noexcept override;
    [[nodiscard]] std::string nome() const override;
    void executar(const EventoSeguranca& evento,
                  const std::vector<std::shared_ptr<Exportador>>& exportadores) const override;
};

class AcaoDescartar final : public Acao {
public:
    [[nodiscard]] TipoAcao tipo() const noexcept override;
    [[nodiscard]] std::string nome() const override;
    void executar(const EventoSeguranca& evento,
                  const std::vector<std::shared_ptr<Exportador>>& exportadores) const override;
};

} // namespace sentinela
