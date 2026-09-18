#include "captura/Parser.hpp"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

std::shared_ptr<Pacote> Parser::parsearPacote(const struct pcap_pkthdr* header, const unsigned char* bytes) {
    // 1. Validação de tamanho mínimo para Ethernet (14 bytes)
    if (header->caplen < 14) {
        return nullptr;
    }

    // Pula o cabeçalho Ethernet (14 bytes)[cite: 3]
    uint16_t etherType = ntohs(*(uint16_t*)(bytes + 12));
    if (etherType != 0x0800) { // Garante que é IPv4 (0x0800)[cite: 3]
        return nullptr;
    }

    const unsigned char* ipHeaderBytes = bytes + 14;
    if (header->caplen < 14 + sizeof(struct iphdr)) {
        return nullptr;
    }

    const struct iphdr* ipHeader = (const struct iphdr*)ipHeaderBytes;
    
    char ipOrigemStr[INET_ADDRSTRLEN];
    char ipDestinoStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->saddr), ipOrigemStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->daddr), ipDestinoStr, INET_ADDRSTRLEN);

    uint32_t timestamp = header->ts.tv_sec;
    size_t ipHeaderLen = ipHeader->ihl * 4;
    const unsigned char* transportHeaderBytes = ipHeaderBytes + ipHeaderLen;

    // 2. Análise do protocolo da Camada de Transporte
    if (ipHeader->protocol == IPPROTO_TCP) {
        if (header->caplen < 14 + ipHeaderLen + sizeof(struct tcphdr)) return nullptr;
        const struct tcphdr* tcpHeader = (const struct tcphdr*)transportHeaderBytes;

        return std::make_shared<PacoteTCP>(
            ipOrigemStr, ipDestinoStr, timestamp,
            ntohs(tcpHeader->source), ntohs(tcpHeader->dest),
            tcpHeader->syn, tcpHeader->ack
        );
    } 
    else if (ipHeader->protocol == IPPROTO_UDP) {
        if (header->caplen < 14 + ipHeaderLen + sizeof(struct udphdr)) return nullptr;
        const struct udphdr* udpHeader = (const struct udphdr*)transportHeaderBytes;

        return std::make_shared<PacoteUDP>(
            ipOrigemStr, ipDestinoStr, timestamp,
            ntohs(udpHeader->source), ntohs(udpHeader->dest)
        );
    } 
    else if (ipHeader->protocol == IPPROTO_ICMP) {
        if (header->caplen < 14 + ipHeaderLen + sizeof(struct icmphdr)) return nullptr;
        const struct icmphdr* icmpHeader = (const struct icmphdr*)transportHeaderBytes;

        return std::make_shared<PacoteICMP>(
            ipOrigemStr, ipDestinoStr, timestamp,
            icmpHeader->type, icmpHeader->code
        );
    }

    return nullptr;
}