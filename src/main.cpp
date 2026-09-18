#include <iostream>
#include <pcap.h>

#include "captura/Parser.hpp"
#include "regras/EngineRegras.hpp"

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Altere para o nome da interface do container ou máquina local (ex: eth0 ou wlan0)
    const char* dev = "eth0"; 

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // Modo promíscuo ativado[cite: 3]
    if (handle == nullptr) {
        std::cerr << "Erro ao abrir dispositivo " << dev << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Sentinela iniciado na interface: " << dev << "...\n";

    // Inicializa a Engine de Regras
    EngineRegras engine;
    engine.adicionarRegra(std::make_shared<RegraPortaSensivel>("Acesso SSH Detectado", 22));

    int contadorPacotes = 0;
    while (contadorPacotes < 20) { // Captura 20 pacotes para teste
        struct pcap_pkthdr header;
        const unsigned char* packet = pcap_next(handle, &header);

        if (packet != nullptr) {
            auto pacoteObj = Parser::parsearPacote(&header, packet);
            if (pacoteObj) {
                pacoteObj->exibirDetalhes();
                engine.processarPacote(pacoteObj);
                contadorPacotes++;
            }
        }
    }

    pcap_close(handle); // Encerra o pcap adequadamente[cite: 3]
    std::cout << "Captura encerrada com sucesso.\n";
    return 0;
}