#include "modelos/Pacote.hpp"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sstream>

// Pacote Base

Pacote::Pacote(std::string orig, std::string dest, Protocolo prot, uint32_t ts)
    : ipOrigem(std::move(orig)), ipDestino(std::move(dest)), protocolo(prot), timestamp(ts) {}

std::string Pacote::getIpOrigem() const { return ipOrigem; }
std::string Pacote::getIpDestino() const { return ipDestino; }
Protocolo Pacote::getProtocolo() const { return protocolo; }
uint32_t Pacote::getTimestamp() const { return timestamp; }

std::string Pacote::toString() const {
    std::ostringstream ss;
    ss << "[" << timestamp << "] " << ipOrigem << " -> " << ipDestino;
    return ss.str();
}

std::unique_ptr<Pacote> Pacote::criarDoBuffer(const unsigned char* bytes, uint32_t tamanhocap) {
    if (tamanhocap < 14) return nullptr;

    uint16_t etherType = ntohs(*reinterpret_cast<const uint16_t*>(bytes + 12));
    if (etherType != 0x0800) return nullptr; // Filtra apenas IPv4[cite: 3]

    if (tamanhocap < 14 + sizeof(struct iphdr)) return nullptr;

    const struct iphdr* ipHeader = reinterpret_cast<const struct iphdr*>(bytes + 14);
    size_t ipHeaderLen = ipHeader->ihl * 4;

    if (tamanhocap < 14 + ipHeaderLen) return nullptr;

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->saddr), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->daddr), dstIp, INET_ADDRSTRLEN);

    const unsigned char* payload = bytes + 14 + ipHeaderLen;
    size_t payloadLen = tamanhocap - (14 + ipHeaderLen);
    uint32_t ts = 0; // Pode ser preenchido com a struct pcap_pkthdr se necessário

    if (ipHeader->protocol == IPPROTO_TCP) {
        if (payloadLen < sizeof(struct tcphdr)) return nullptr;
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(payload);
        return std::make_unique<PacoteTCP>(srcIp, dstIp, ts, ntohs(tcp->source), ntohs(tcp->dest), 
                                           tcp->syn, tcp->ack, tcp->fin, tcp->rst);
    } 
    else if (ipHeader->protocol == IPPROTO_UDP) {
        if (payloadLen < sizeof(struct udphdr)) return nullptr;
        const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(payload);
        return std::make_unique<PacoteUDP>(srcIp, dstIp, ts, ntohs(udp->source), ntohs(udp->dest));
    } 
    else if (ipHeader->protocol == IPPROTO_ICMP) {
        if (payloadLen < sizeof(struct icmphdr)) return nullptr;
        const struct icmphdr* icmp = reinterpret_cast<const struct icmphdr*>(payload);
        return std::make_unique<PacoteICMP>(srcIp, dstIp, ts, icmp->type, icmp->code);
    }

    return nullptr;
}

// PacoteTCP

PacoteTCP::PacoteTCP(std::string orig, std::string dest, uint32_t ts, 
                     uint16_t pOrig, uint16_t pDest, bool syn, bool ack, bool fin, bool rst)
    : Pacote(std::move(orig), std::move(dest), Protocolo::TCP, ts),
      portaOrigem(pOrig), portaDestino(pDest), flagSYN(syn), flagACK(ack), flagFIN(fin), flagRST(rst) {}

uint16_t PacoteTCP::getPortaOrigem() const { return portaOrigem; }
uint16_t PacoteTCP::getPortaDestino() const { return portaDestino; }
bool PacoteTCP::isSYN() const { return flagSYN; }
bool PacoteTCP::isACK() const { return flagACK; }
bool PacoteTCP::isFIN() const { return flagFIN; }
bool PacoteTCP::isRST() const { return flagRST; }

void PacoteTCP::exibirDetalhes() const {
    std::cout << toString() << "\n";
}

std::string PacoteTCP::toString() const {
    std::ostringstream ss;
    ss << "[TCP] " << ipOrigem << ":" << portaOrigem << " -> " << ipDestino << ":" << portaDestino
       << " (SYN:" << flagSYN << " ACK:" << flagACK << ")";
    return ss.str();
}

// PacoteUDP

PacoteUDP::PacoteUDP(std::string orig, std::string dest, uint32_t ts, uint16_t pOrig, uint16_t pDest)
    : Pacote(std::move(orig), std::move(dest), Protocolo::UDP, ts),
      portaOrigem(pOrig), portaDestino(pDest) {}

uint16_t PacoteUDP::getPortaOrigem() const { return portaOrigem; }
uint16_t PacoteUDP::getPortaDestino() const { return portaDestino; }

void PacoteUDP::exibirDetalhes() const {
    std::cout << toString() << "\n";
}

std::string PacoteUDP::toString() const {
    std::ostringstream ss;
    ss << "[UDP] " << ipOrigem << ":" << portaOrigem << " -> " << ipDestino << ":" << portaDestino;
    return ss.str();
}

// PacoteICMP

PacoteICMP::PacoteICMP(std::string orig, std::string dest, uint32_t ts, uint8_t t, uint8_t c)
    : Pacote(std::move(orig), std::move(dest), Protocolo::ICMP, ts), tipo(t), codigo(c) {}

uint8_t PacoteICMP::getTipo() const { return tipo; }
uint8_t PacoteICMP::getCodigo() const { return codigo; }

void PacoteICMP::exibirDetalhes() const {
    std::cout << toString() << "\n";
}

std::string PacoteICMP::toString() const {
    std::ostringstream ss;
    ss << "[ICMP] " << ipOrigem << " -> " << ipDestino 
       << " (Tipo: " << static_cast<int>(tipo) << ", Codigo: " << static_cast<int>(codigo) << ")";
    return ss.str();
}