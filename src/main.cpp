#include <iostream>
#include <memory>
#include <pcap.h>
#include "captura/Parser.hpp"
#include "regras/EngineRegras.hpp"
#include "core/ContadorMetricas.hpp"

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = "any"; // Captura de todas as interfaces ativas (eth0, wlan0, etc.)

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Erro ao abrir dispositivo " << dev << ": " << errbuf << std::endl;
        return 1;
    }

    // Instancia o gestor de métricas partilhado
    auto metricas = std::make_shared<ContadorMetricas>();

    // Inicializa a Engine de Regras com suporte a métricas
    EngineRegras engine(metricas);
    engine.adicionarRegra(std::make_shared<RegraPortaSensivel>("Acesso SSH Detectado", 22));

    std::cout << "Sentinela iniciado na interface: " << dev << "...\n";

    while (true) { 
        struct pcap_pkthdr header;
        const unsigned char* packet = pcap_next(handle, &header);

        if (packet != nullptr) {
            // 1. Regista a chegada de um pacote nas métricas
            metricas->registrarPacote();

            // 2. Transforma em objeto e avalia nas regras
            auto pacoteObj = Parser::parsearPacote(&header, packet);
            if (pacoteObj) {
                engine.processarPacote(pacoteObj);
            }
        }

        // Exemplo de leitura das métricas expostas (aqui entra o ExportadorZabbix)
        // std::cout << "Pacotes/s: " << metricas->getPacotesPorSegundo() 
        //           << " | Alertas: " << metricas->getTotalAlertas() << "\r";
    }

    pcap_close(handle);
    return 0;
}