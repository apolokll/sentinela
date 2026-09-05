#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace sentinela {

class Pacote;

class AnalisadorPacote final {
public:
    [[nodiscard]] std::unique_ptr<Pacote> analisar(const std::uint8_t* dados,
                                                    std::size_t tamanho,
                                                    std::chrono::system_clock::time_point timestamp) const;
};

} // namespace sentinela
