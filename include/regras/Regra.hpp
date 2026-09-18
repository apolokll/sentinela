#ifndef REGRA_HPP
#define REGRA_HPP

#include "modelos/Pacote.hpp"
#include <memory>
#include <string>

// Classe Abstrata para Regras de Detecção
class Regra {
protected:
    std::string nome;

public:
    explicit Regra(std::string n) : nome(std::move(n)) {}
    virtual ~Regra() = default;

    std::string getNome() const { return nome; }

    // Método Virtual Puro
    virtual bool avaliar(const std::shared_ptr<Pacote>& pacote) = 0;
};

// Exemplo de Regra Concreta: Alerta sobre acesso a uma porta sensível (Ex: SSH - 22)
class RegraPortaSensivel : public Regra {
private:
    uint16_t portaAlvo;

public:
    RegraPortaSensivel(std::string nome, uint16_t porta) 
        : Regra(std::move(nome)), portaAlvo(porta) {}

    bool avaliar(const std::shared_ptr<Pacote>& pacote) override {
        if (pacote->getProtocolo() == Protocolo::TCP) {
            auto pacoteTcp = std::dynamic_pointer_cast<PacoteTCP>(pacote);
            if (pacoteTcp && pacoteTcp->getPortaDestino() == portaAlvo) {
                return true; // Dispara alerta
            }
        }
        return false;
    }
};

#endif