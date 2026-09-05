#include "core/EventoSeguranca.hpp"

#include "domain/Pacote.hpp"

#include <utility>

namespace sentinela {

EventoSeguranca::EventoSeguranca(std::string identificadorRegra,
                                 const Severidade severidade,
                                 std::string mensagem,
                                 const TipoAcao acaoSugerida,
                                 const Pacote& pacote)
    : identificadorRegra_(std::move(identificadorRegra)),
      severidade_(severidade),
      mensagem_(std::move(mensagem)),
      acaoSugerida_(acaoSugerida),
      ipOrigem_(pacote.ipOrigem()),
      ipDestino_(pacote.ipDestino()),
      protocolo_(pacote.protocolo()),
      portaOrigem_(pacote.portaOrigem()),
      portaDestino_(pacote.portaDestino()),
      timestamp_(pacote.timestamp()) {}

const std::string& EventoSeguranca::identificadorRegra() const noexcept {
    return identificadorRegra_;
}

Severidade EventoSeguranca::severidade() const noexcept {
    return severidade_;
}

const std::string& EventoSeguranca::mensagem() const noexcept {
    return mensagem_;
}

TipoAcao EventoSeguranca::acaoSugerida() const noexcept {
    return acaoSugerida_;
}

const std::string& EventoSeguranca::ipOrigem() const noexcept {
    return ipOrigem_;
}

const std::string& EventoSeguranca::ipDestino() const noexcept {
    return ipDestino_;
}

Protocolo EventoSeguranca::protocolo() const noexcept {
    return protocolo_;
}

std::optional<std::uint16_t> EventoSeguranca::portaOrigem() const noexcept {
    return portaOrigem_;
}

std::optional<std::uint16_t> EventoSeguranca::portaDestino() const noexcept {
    return portaDestino_;
}

std::chrono::system_clock::time_point EventoSeguranca::timestamp() const noexcept {
    return timestamp_;
}

} // namespace sentinela
