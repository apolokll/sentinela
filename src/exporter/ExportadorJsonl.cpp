#include "exporter/ExportadorJsonl.hpp"

#include "core/EventoSeguranca.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

namespace sentinela {
namespace {

[[nodiscard]] std::string formatarTimestamp(const std::chrono::system_clock::time_point instante) {
    const auto segundos = std::chrono::system_clock::to_time_t(instante);
    std::tm calendario{};
    gmtime_r(&segundos, &calendario);

    const auto desdeEpoca = instante.time_since_epoch();
    const auto milissegundos = std::chrono::duration_cast<std::chrono::milliseconds>(desdeEpoca).count() % 1000;
    std::ostringstream saida;
    saida << std::put_time(&calendario, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3)
          << milissegundos << 'Z';
    return saida.str();
}

} // namespace

ExportadorJsonl::ExportadorJsonl(std::filesystem::path caminho) : caminho_(std::move(caminho)) {
    if (!caminho_.parent_path().empty()) {
        std::filesystem::create_directories(caminho_.parent_path());
    }
    arquivo_.open(caminho_, std::ios::out | std::ios::app);
    if (!arquivo_.is_open()) {
        throw std::runtime_error("Nao foi possivel abrir o arquivo de eventos: " + caminho_.string());
    }
}

ExportadorJsonl::~ExportadorJsonl() {
    std::scoped_lock lock(mutex_);
    if (arquivo_.is_open()) {
        arquivo_.flush();
    }
}

std::string ExportadorJsonl::nome() const {
    return "jsonl:" + caminho_.string();
}

void ExportadorJsonl::exportar(const EventoSeguranca& evento) {
    nlohmann::json linha{
        {"timestamp", formatarTimestamp(evento.timestamp())},
        {"regra", evento.identificadorRegra()},
        {"severidade", paraTexto(evento.severidade())},
        {"acao_sugerida", paraTexto(evento.acaoSugerida())},
        {"mensagem", evento.mensagem()},
        {"ip_origem", evento.ipOrigem()},
        {"ip_destino", evento.ipDestino()},
        {"protocolo", paraTexto(evento.protocolo())},
    };
    if (const auto portaOrigem = evento.portaOrigem(); portaOrigem.has_value()) {
        linha["porta_origem"] = *portaOrigem;
    }
    if (const auto portaDestino = evento.portaDestino(); portaDestino.has_value()) {
        linha["porta_destino"] = *portaDestino;
    }

    std::scoped_lock lock(mutex_);
    arquivo_ << linha.dump() << '\n';
    arquivo_.flush();
    if (!arquivo_) {
        throw std::runtime_error("Falha ao escrever o evento em " + caminho_.string());
    }
}

} // namespace sentinela
