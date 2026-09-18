#include "regras/EngineRegras.hpp"
#include <iostream>

void EngineRegras::adicionarRegra(std::shared_ptr<Regra> regra) {
    regras.push_back(regra);
}

void EngineRegras::processarPacote(const std::shared_ptr<Pacote>& pacote) {
    if (!pacote) return;

    for (const auto& regra : regras) {
        if (regra->avaliar(pacote)) {
            std::cout << "[ALERTA DETECTADO] Regra: " << regra->getNome() << " disparada pelo pacote de IP: " 
                      << pacote->getIpOrigem() << "\n";
        }
    }
}