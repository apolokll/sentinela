#ifndef ENGINE_REGRAS_HPP
#define ENGINE_REGRAS_HPP

#include "regras/Regra.hpp"
#include <vector>
#include <memory>

class EngineRegras {
private:
    std::vector<std::shared_ptr<Regra>> regras;

public:
    void adicionarRegra(std::shared_ptr<Regra> regra);
    void processarPacote(const std::shared_ptr<Pacote>& pacote);
};

#endif