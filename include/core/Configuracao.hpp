#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace sentinela {

class Regra;

class OpcoesCaptura final {
public:
    [[nodiscard]] const std::string& interface() const noexcept;
    [[nodiscard]] bool modoPromiscuo() const noexcept;
    [[nodiscard]] int snaplen() const noexcept;
    [[nodiscard]] int timeoutMilissegundos() const noexcept;
    [[nodiscard]] OpcoesCaptura comInterface(std::string interface) const;

private:
    friend class Configuracao;

    std::string interface_;
    bool modoPromiscuo_ = true;
    int snaplen_ = 65535;
    int timeoutMilissegundos_ = 500;
};

class Configuracao final {
public:
    static Configuracao carregar(const std::filesystem::path& caminho);

    [[nodiscard]] const OpcoesCaptura& captura() const noexcept;
    [[nodiscard]] const std::filesystem::path& caminhoLog() const noexcept;
    [[nodiscard]] std::vector<std::unique_ptr<Regra>> criarRegras() const;

private:
    struct DefinicaoRegra {
        std::string tipo;
        std::string identificador;
        std::chrono::seconds janela{10};
        std::chrono::seconds cooldown{30};
        std::size_t limite = 0;
        std::string ipDestino;
        std::vector<std::uint16_t> portas;
        int severidade = 2;
    };

    OpcoesCaptura captura_;
    std::filesystem::path caminhoLog_;
    std::vector<DefinicaoRegra> definicoesRegras_;
};

} // namespace sentinela
