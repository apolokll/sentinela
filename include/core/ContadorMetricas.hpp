#ifndef CONTADOR_METRICAS_HPP
#define CONTADOR_METRICAS_HPP

#include <atomic>
#include <chrono>
#include <cstdint>

class ContadorMetricas {
private:
    std::atomic<uint64_t> totalPacotes{0};
    std::atomic<uint64_t> totalAlertas{0};
    std::atomic<uint64_t> pacotesNaJanela{0};

    std::chrono::steady_clock::time_point ultimoCalculo;
    std::atomic<double> pacotesPorSegundo{0.0};

public:
    ContadorMetricas() {
        ultimoCalculo = std::chrono::steady_clock::now();
    }

    // Incrementa a contagem a cada pacote processado
    void registrarPacote() {
        totalPacotes++;
        pacotesNaJanela++;
        atualizarPacotesPorSegundo();
    }

    // Incrementa a contagem a cada alerta disparado por uma regra
    void registrarAlerta() {
        totalAlertas++;
    }

    // Calcula os pacotes/s dinamicamente
    void atualizarPacotesPorSegundo() {
        auto agora = std::chrono::steady_clock::now();
        std::chrono::duration<double> decorrido = agora - ultimoCalculo;

        if (decorrido.count() >= 1.0) { // Atualiza a cada 1 segundo
            pacotesPorSegundo = pacotesNaJanela.load() / decorrido.count();
            pacotesNaJanela = 0;
            ultimoCalculo = agora;
        }
    }

    // Getters expostos para o ExportadorZabbix
    double getPacotesPorSegundo() const { return pacotesPorSegundo.load(); }
    uint64_t getTotalAlertas() const { return totalAlertas.load(); }
    uint64_t getTotalPacotes() const { return totalPacotes.load(); }
};

#endif