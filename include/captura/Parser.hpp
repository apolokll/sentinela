#ifndef PARSER_HPP
#define PARSER_HPP

#include "modelos/Pacote.hpp"
#include <memory>
#include <pcap.h>

class Parser {
public:
    // Analisa os bytes e retorna um smart pointer para Pacote polimórfico
    static std::shared_ptr<Pacote> parsearPacote(const struct pcap_pkthdr* header, const unsigned char* bytes);
};

#endif