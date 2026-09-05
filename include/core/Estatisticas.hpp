#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>

namespace sentinela {

class EventoSeguranca;
class Pacote;

class ResumoEstatisticas final {
public:
    [[nodiscard]] std::uint64_t totalPacotes() const noexcept;
    [[nodiscard]] std::uint64_t totalAlertas() const noexcept;
    [[nodiscard]] double pacotesPorSegundo() const noexcept;
    [[nodiscard]] const std::vector<std::pair<std::string, std::uint64_t>>& principaisOrigens() const noexcept;
    [[nodiscard]] const std::vector<std::pair<std::string, std::uint64_t>>& alertasPorRegra() const noexcept;

private:
    friend class Estatisticas;

    std::uint64_t totalPacotes_ = 0;
    std::uint64_t totalAlertas_ = 0;
    double pacotesPorSegundo_ = 0.0;
    std::vector<std::pair<std::string, std::uint64_t>> principaisOrigens_;
    std::vector<std::pair<std::string, std::uint64_t>> alertasPorRegra_;
};

class Estatisticas final {
public:
    Estatisticas();

    void registrarPacote(const Pacote& pacote);
    void registrarAlerta(const EventoSeguranca& evento);
    [[nodiscard]] ResumoEstatisticas resumo(std::size_t limiteOrigens = 5) const;

private:
    std::chrono::steady_clock::time_point inicio_;
    std::uint64_t totalPacotes_ = 0;
    std::uint64_t totalAlertas_ = 0;
    std::unordered_map<std::string, std::uint64_t> pacotesPorOrigem_;
    std::unordered_map<std::string, std::uint64_t> alertasPorRegra_;
    mutable std::mutex mutex_;
};

} // namespace sentinela
