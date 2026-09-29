#ifndef PACOTE_HPP
#define PACOTE_HPP

#include <string>
#include <cstdint>
#include <memory>
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
    Pacote(std::string orig, std::string dest, Protocolo prot, uint32_t ts);
    virtual ~Pacote() = default; // Destruidor virtual obrigatório

    // Métodos Getters (Encapsulamento rigoroso)
    std::string getIpOrigem() const;
    std::string getIpDestino() const;
    Protocolo getProtocolo() const;
    uint32_t getTimestamp() const;

    virtual std::string toString() const;

    // Método virtual puro
    virtual void exibirDetalhes() const = 0;

    // Factory Method para criar instâncias concretas a partir do buffer bruto do libpcap
    static std::unique_ptr<Pacote> criarDoBuffer(const unsigned char* bytes, uint32_t tamanhocap);
};

// Classe Derivada: PacoteTCP
class PacoteTCP : public Pacote {
private:
    uint16_t portaOrigem;
    uint16_t portaDestino;
    bool flagSYN;
    bool flagACK;
    bool flagFIN;
    bool flagRST;

public:
    PacoteTCP(std::string orig, std::string dest, uint32_t ts, 
              uint16_t pOrig, uint16_t pDest, 
              bool syn, bool ack, bool fin = false, bool rst = false);

    uint16_t getPortaOrigem() const;
    uint16_t getPortaDestino() const;
    bool isSYN() const;
    bool isACK() const;
    bool isFIN() const;
    bool isRST() const;

    void exibirDetalhes() const override;
    std::string toString() const override;
};

// Classe Derivada: PacoteUDP
class PacoteUDP : public Pacote {
private:
    uint16_t portaOrigem;
    uint16_t portaDestino;

public:
    PacoteUDP(std::string orig, std::string dest, uint32_t ts, uint16_t pOrig, uint16_t pDest);

    uint16_t getPortaOrigem() const;
    uint16_t getPortaDestino() const;

    void exibirDetalhes() const override;
    std::string toString() const override;
};

// Classe Derivada: PacoteICMP
class PacoteICMP : public Pacote {
private:
    uint8_t tipo;
    uint8_t codigo;

public:
    PacoteICMP(std::string orig, std::string dest, uint32_t ts, uint8_t t, uint8_t c);

    uint8_t getTipo() const;
    uint8_t getCodigo() const;

    void exibirDetalhes() const override;
    std::string toString() const override;
};

#endif // PACOTE_HPP