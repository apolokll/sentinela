#pragma once

#include "exporter/Exportador.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace sentinela {

class ExportadorJsonl final : public Exportador {
public:
    explicit ExportadorJsonl(std::filesystem::path caminho);
    ~ExportadorJsonl() override;

    [[nodiscard]] std::string nome() const override;
    void exportar(const EventoSeguranca& evento) override;

private:
    std::filesystem::path caminho_;
    std::ofstream arquivo_;
    std::mutex mutex_;
};

} // namespace sentinela
