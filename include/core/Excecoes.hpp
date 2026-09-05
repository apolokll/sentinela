#pragma once

#include <stdexcept>
#include <string>

namespace sentinela {

class ExcecaoConfiguracao final : public std::runtime_error {
public:
    explicit ExcecaoConfiguracao(const std::string& mensagem)
        : std::runtime_error(mensagem) {}
};

class ExcecaoCaptura final : public std::runtime_error {
public:
    explicit ExcecaoCaptura(const std::string& mensagem)
        : std::runtime_error(mensagem) {}
};

} // namespace sentinela
