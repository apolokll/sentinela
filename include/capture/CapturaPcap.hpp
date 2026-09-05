#pragma once

#include "core/Configuracao.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>

namespace sentinela {

class CapturaPcap final {
public:
    using AoReceberQuadro = std::function<void(const std::uint8_t* dados,
                                                std::size_t tamanho,
                                                std::chrono::system_clock::time_point timestamp)>;

    explicit CapturaPcap(OpcoesCaptura opcoes);

    void processarArquivo(const std::filesystem::path& caminho, const AoReceberQuadro& aoReceber) const;
    void capturarAoVivo(std::chrono::seconds duracao, const AoReceberQuadro& aoReceber) const;

private:
    OpcoesCaptura opcoes_;
};

} // namespace sentinela
