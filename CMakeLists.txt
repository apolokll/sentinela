cmake_minimum_required(VERSION 3.14)
project(sentinela VERSION 1.0.0 LANGUAGES CXX)

# Exige o padrão C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ativa avisos do compilador para garantir boa qualidade de código
add_compile_options(-Wall -Wextra -Wpedantic)

# Localiza a biblioteca libpcap no sistema
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Inclui os cabeçalhos (.hpp) da pasta include/
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

# Coleta automaticamente todos os arquivos de implementação (.cpp)
file(GLOB_RECURSE SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

# Cria o executável 'sentinela' com os fontes encontrados
add_executable(sentinela ${SOURCES})

# Modifica as propriedades do target para incluir os diretórios de inclusão
target_include_directories(sentinela PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    ${PCAP_INCLUDE_DIRS}
)

# Vincula a libpcap ao executável
target_link_libraries(sentinela PRIVATE ${PCAP_LIBRARIES})

# Copia a pasta config/ para o diretório de build no momento do compile
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config DESTINATION ${CMAKE_BINARY_DIR})