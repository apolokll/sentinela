import socket
import json
import time

evento = {
    "version": "1.1",
    "host": "sentinela",
    "short_message": "Port scan detectado",
    "full_message": "172.20.0.99 varreu 15 portas em 10s",
    "timestamp": time.time(),  # Timestamp atual em tempo real
    "level": 3,
    "_regra": "RegraPortScan",
    "_ip_origem": "172.20.0.99"
}

# Envia via UDP para o serviço 'graylog' na rede Docker
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(json.dumps(evento).encode(), ("graylog", 12201))
print("Evento enviado com sucesso!")