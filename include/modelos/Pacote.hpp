#ifndef PACOTE_HPP
#define PACOTE_HPP

#include <string>
#include <cstdint>
#include <iostream>

enum class Protocolo {
    TCP,
    UDP,
    ICMP,
    DESCONHECIDO
};

// Classe Abstrata (Exigência do Projeto)
class Pacote {
protected:
    std::string ipOrigem;
    std::string ipDestino;
    Protocolo protocolo;
    uint32_t timestamp;

public:
    Pacote(std::string orig, std::string dest, Protocolo prot, uint32_t ts)
        : ipOrigem(std::move(orig)), ipDestino(std::move(dest)), protocolo(prot), timestamp(ts) {}

    virtual ~Pacote() = default; // Destruidor virtual obrigatório

    // Métodos Getters (Encapsulamento rigoroso)
    std::string getIpOrigem() const { return ipOrigem; }
    std::string getIpDestino() const { return ipDestino; }
    Protocolo getProtocolo() const { return protocolo; }
    uint32_t getTimestamp() const { return timestamp; }

    // Método virtual puro
    virtual void exibirDetalhes() const = 0;
};

// Classe Derivada: PacoteTCP
class PacoteTCP : public Pacote {
private:
    uint16_t portaOrigem;
    uint16_t portaDestino;
    bool flagSYN;
    bool flagACK;

public:
    PacoteTCP(std::string orig, std::string dest, uint32_t ts, uint16_t pOrig, uint16_t pDest, bool syn, bool ack)
        : Pacote(std::move(orig), std::move(dest), Protocolo::TCP, ts),
          portaOrigem(pOrig), portaDestino(pDest), flagSYN(syn), flagACK(ack) {}

    uint16_t getPortaOrigem() const { return portaOrigem; }
    uint16_t getPortaDestino() const { return portaDestino; }
    bool isSYN() const { return flagSYN; }
    bool isACK() const { return flagACK; }

    void exibirDetalhes() const override {
        std::cout << "[TCP] " << ipOrigem << ":" << portaOrigem 
                  << " -> " << ipDestino << ":" << portaDestino 
                  << " (SYN: " << flagSYN << ", ACK: " << flagACK << ")\n";
    }
};

// Classe Derivada: PacoteUDP
class PacoteUDP : public Pacote {
private:
    uint16_t portaOrigem;
    uint16_t portaDestino;

public:
    PacoteUDP(std::string orig, std::string dest, uint32_t ts, uint16_t pOrig, uint16_t pDest)
        : Pacote(std::move(orig), std::move(dest), Protocolo::UDP, ts),
          portaOrigem(pOrig), portaDestino(pDest) {}

    uint16_t getPortaOrigem() const { return portaOrigem; }
    uint16_t getPortaDestino() const { return portaDestino; }

    void exibirDetalhes() const override {
        std::cout << "[UDP] " << ipOrigem << ":" << portaOrigem 
                  << " -> " << ipDestino << ":" << portaDestino << "\n";
    }
};

// Classe Derivada: PacoteICMP
class PacoteICMP : public Pacote {
private:
    uint8_t tipo;
    uint8_t codigo;

public:
    PacoteICMP(std::string orig, std::string dest, uint32_t ts, uint8_t t, uint8_t c)
        : Pacote(std::move(orig), std::move(dest), Protocolo::ICMP, ts),
          tipo(t), codigo(c) {}

    uint8_t getTipo() const { return tipo; }
    uint8_t getCodigo() const { return codigo; }

    void exibirDetalhes() const override {
        std::cout << "[ICMP] " << ipOrigem << " -> " << ipDestino 
                  << " (Tipo: " << (int)tipo << ", Codigo: " << (int)codigo << ")\n";
    }
};

#endif