cmake_minimum_required(VERSION 3.20)

project(sentinela VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
include(GoogleTest)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(nlohmann_json 3.11 REQUIRED)

add_library(sentinela_core
    src/domain/Pacote.cpp
    src/core/EventoSeguranca.cpp
    src/core/Regra.cpp
    src/core/MotorRegras.cpp
    src/core/Configuracao.cpp
    src/core/Estatisticas.cpp
    src/core/Acao.cpp
    src/core/DespachanteAcoes.cpp
    src/core/AnalisadorPacote.cpp
    src/rules/RegraPortScan.cpp
    src/rules/RegraPingSweep.cpp
    src/rules/RegraAcessoBloqueado.cpp
    src/exporter/ExportadorJsonl.cpp
    src/capture/CapturaPcap.cpp
)

target_include_directories(sentinela_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(sentinela_core
    PUBLIC
        PkgConfig::PCAP
        nlohmann_json::nlohmann_json
)

target_compile_options(sentinela_core
    PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion -Wshadow>
)

add_executable(sentinela src/main.cpp)
target_link_libraries(sentinela PRIVATE sentinela_core)

if(BUILD_TESTING)
    find_package(GTest REQUIRED)

    add_executable(sentinela_tests
        tests/test_analisador_pacote.cpp
    )
    target_link_libraries(sentinela_tests PRIVATE sentinela_core GTest::gtest_main)
    target_compile_options(sentinela_tests
        PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion -Wshadow>
    )
    gtest_discover_tests(sentinela_tests)
endif()
