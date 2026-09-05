#pragma once

#include <string_view>

namespace sentinela {

enum class Protocolo {
    Tcp,
    Udp,
    Icmp,
};

enum class Severidade {
    Informacao,
    Baixa,
    Media,
    Alta,
    Critica,
};

enum class TipoAcao {
    Registrar,
    Alertar,
    Permitir,
    Descartar,
};

[[nodiscard]] constexpr std::string_view paraTexto(Protocolo protocolo) noexcept {
    switch (protocolo) {
    case Protocolo::Tcp:
        return "tcp";
    case Protocolo::Udp:
        return "udp";
    case Protocolo::Icmp:
        return "icmp";
    }
    return "desconhecido";
}

[[nodiscard]] constexpr std::string_view paraTexto(Severidade severidade) noexcept {
    switch (severidade) {
    case Severidade::Informacao:
        return "informacao";
    case Severidade::Baixa:
        return "baixa";
    case Severidade::Media:
        return "media";
    case Severidade::Alta:
        return "alta";
    case Severidade::Critica:
        return "critica";
    }
    return "desconhecida";
}

[[nodiscard]] constexpr std::string_view paraTexto(TipoAcao acao) noexcept {
    switch (acao) {
    case TipoAcao::Registrar:
        return "registrar";
    case TipoAcao::Alertar:
        return "alertar";
    case TipoAcao::Permitir:
        return "permitir";
    case TipoAcao::Descartar:
        return "descartar";
    }
    return "desconhecida";
}

} // namespace sentinela
