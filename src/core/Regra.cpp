#include "core/Regra.hpp"

#include <utility>

namespace sentinela {

Regra::Regra(std::string identificador, std::string descricao)
    : identificador_(std::move(identificador)), descricao_(std::move(descricao)) {}

const std::string& Regra::identificador() const noexcept {
    return identificador_;
}

const std::string& Regra::descricao() const noexcept {
    return descricao_;
}

} // namespace sentinela
