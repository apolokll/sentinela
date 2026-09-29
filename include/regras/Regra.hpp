#ifndef REGRA_HPP
#define REGRA_HPP

#include "modelos/Pacote.hpp" // Ajuste o caminho se necessário (ex: "modelos/Pacote.hpp")
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>

// Estrutura auxiliar para rastrear conexões recentes por IP
struct AcessoPorta {
    uint32_t timestamp;
    uint16_t porta;
};

// Classe Abstrata para Regras de Detecção
class Regra {
protected:
    std::string nome;
    std::string descricao;

public:
    explicit Regra(std::string n, std::string desc = "") 
        : nome(std::move(n)), descricao(std::move(desc)) {}

    virtual ~Regra() = default;

    std::string getNome() const { return nome; }
    std::string getDescricao() const { return descricao; }

    // Método Virtual Puro
    virtual bool avaliar(const std::shared_ptr<Pacote>& pacote) = 0;
};

// Regra Concreta: Alerta sobre acesso a portas sensíveis (Ex: SSH - 22)
class RegraPortaSensivel : public Regra {
private:
    uint16_t portaAlvo;

public:
    RegraPortaSensivel(std::string nome, uint16_t porta, std::string desc = "") 
        : Regra(std::move(nome), std::move(desc)), portaAlvo(porta) {}

    bool avaliar(const std::shared_ptr<Pacote>& pacote) override;
};

// Regra Concreta: Detecção de Varredura de Portas (Port Scan)
class RegraPorta : public Regra {
private:
    uint32_t janelaSegundos;
    uint32_t limiarPortas;
    std::unordered_map<std::string, std::deque<AcessoPorta>> acessosPorIp;

public:
    RegraPorta(std::string nome, std::string desc, uint32_t janelaSeg, uint32_t limiarPortas);

    bool avaliar(const std::shared_ptr<Pacote>& pacote) override;
};

// Regra Concreta: Detecção de SYN Flood
class RegraSyn : public Regra {
private:
    uint32_t taxaMaxima;
    uint32_t janelaSegundos;
    std::unordered_map<std::string, std::deque<uint32_t>> pacotesSynPorIp;

public:
    RegraSyn(std::string nome, std::string desc, uint32_t taxaMax, uint32_t janelaSeg);

    bool avaliar(const std::shared_ptr<Pacote>& pacote) override;
};

// Regra Concreta: Bloqueio/Lista Negra de IPs e Portas
class RegraBloqueio : public Regra {
private:
    std::unordered_set<std::string> ipsBloqueados;
    std::unordered_set<uint16_t> portasBloqueadas;

public:
    RegraBloqueio(std::string nome, std::string desc = "");

    void adicionarIpBloqueado(const std::string& ip);
    void adicionarPortaBloqueada(uint16_t porta);

    bool avaliar(const std::shared_ptr<Pacote>& pacote) override;
};

#endif // REGRA_HPP