#include "regras/Regra.hpp"

// RegraPortaSensivel

bool RegraPortaSensivel::avaliar(const std::shared_ptr<Pacote>& pacote) {
    if (pacote->getProtocolo() == Protocolo::TCP) {
        auto pacoteTcp = std::dynamic_pointer_cast<PacoteTCP>(pacote);
        if (pacoteTcp && pacoteTcp->getPortaDestino() == portaAlvo) {
            return true;
        }
    }
    return false;
}

// RegraPorta (Port Scan)

RegraPorta::RegraPorta(std::string nome, std::string desc, uint32_t janelaSeg, uint32_t limiarPortas)
    : Regra(std::move(nome), std::move(desc)),
      janelaSegundos(janelaSeg),
      limiarPortas(limiarPortas) {}

bool RegraPorta::avaliar(const std::shared_ptr<Pacote>& pacote) {
    uint16_t portaDestino = 0;

    if (pacote->getProtocolo() == Protocolo::TCP) {
        auto tcp = std::dynamic_pointer_cast<PacoteTCP>(pacote);
        if (tcp) portaDestino = tcp->getPortaDestino();
    } else if (pacote->getProtocolo() == Protocolo::UDP) {
        auto udp = std::dynamic_pointer_cast<PacoteUDP>(pacote);
        if (udp) portaDestino = udp->getPortaDestino();
    } else {
        return false;
    }

    uint32_t tsAtual = pacote->getTimestamp();
    std::string ipOrigem = pacote->getIpOrigem();

    auto& historico = acessosPorIp[ipOrigem];
    historico.push_back({tsAtual, portaDestino});

    // Limpa registros antigos fora da janela de tempo
    uint32_t limiteTempo = (tsAtual > janelaSegundos) ? tsAtual - janelaSegundos : 0;
    while (!historico.empty() && historico.front().timestamp < limiteTempo) {
        historico.pop_front();
    }

    std::unordered_set<uint16_t> portasUnicas;
    for (const auto& acesso : historico) {
        portasUnicas.insert(acesso.porta);
    }

    return portasUnicas.size() >= limiarPortas;
}

// RegraSyn (SYN Flood)

RegraSyn::RegraSyn(std::string nome, std::string desc, uint32_t taxaMax, uint32_t janelaSeg)
    : Regra(std::move(nome), std::move(desc)),
      taxaMaxima(taxaMax),
      janelaSegundos(janelaSeg) {}

bool RegraSyn::avaliar(const std::shared_ptr<Pacote>& pacote) {
    if (pacote->getProtocolo() != Protocolo::TCP) return false;

    auto tcp = std::dynamic_pointer_cast<PacoteTCP>(pacote);
    if (!tcp || !tcp->isSYN() || tcp->isACK()) return false;

    uint32_t tsAtual = pacote->getTimestamp();
    std::string ipOrigem = pacote->getIpOrigem();

    auto& historico = pacotesSynPorIp[ipOrigem];
    historico.push_back(tsAtual);

    uint32_t limiteTempo = (tsAtual > janelaSegundos) ? tsAtual - janelaSegundos : 0;
    while (!historico.empty() && historico.front() < limiteTempo) {
        historico.pop_front();
    }

    return historico.size() >= taxaMaxima;
}

// RegraBloqueio

RegraBloqueio::RegraBloqueio(std::string nome, std::string desc)
    : Regra(std::move(nome), std::move(desc)) {}

void RegraBloqueio::adicionarIpBloqueado(const std::string& ip) {
    ipsBloqueados.insert(ip);
}

void RegraBloqueio::adicionarPortaBloqueada(uint16_t porta) {
    portasBloqueadas.insert(porta);
}

bool RegraBloqueio::avaliar(const std::shared_ptr<Pacote>& pacote) {
    if (ipsBloqueados.count(pacote->getIpOrigem()) > 0) {
        return true;
    }

    if (pacote->getProtocolo() == Protocolo::TCP) {
        auto tcp = std::dynamic_pointer_cast<PacoteTCP>(pacote);
        if (tcp && portasBloqueadas.count(tcp->getPortaDestino()) > 0) {
            return true;
        }
    } else if (pacote->getProtocolo() == Protocolo::UDP) {
        auto udp = std::dynamic_pointer_cast<PacoteUDP>(pacote);
        if (udp && portasBloqueadas.count(udp->getPortaDestino()) > 0) {
            return true;
        }
    }

    return false;
}