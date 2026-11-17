#!/usr/bin/env python3
"""Gera um auth.log FICTÍCIO para testar a triagem (dados inventados, IPs de documentação)."""
import os
import random
from datetime import datetime, timedelta

random.seed(7)
linhas = []
base = datetime(2026, 11, 16, 0, 0, 0)


def ssh(t, ok, user, ip):
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 65000)
    res = "Accepted" if ok else "Failed"
    linhas.append((t, f"{t:%b %d %H:%M:%S} server sshd[{pid}]: {res} password for {user} from {ip} port {port} ssh2"))


def outro(t, msg):
    linhas.append((t, f"{t:%b %d %H:%M:%S} server {msg}"))


# Rotina normal da equipe (horário comercial, a partir da rede interna)
for dia in range(1):
    for user, ip in [("ana", "10.0.0.21"), ("bruno", "10.0.0.34"), ("deploy", "10.0.0.50")]:
        t = base + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
        if random.random() < 0.5:
            ssh(t - timedelta(seconds=40), False, user, ip)  # errou a senha uma vez
        ssh(t, True, user, ip)

# Força bruta 1: varredura de usuários comuns
t = base + timedelta(hours=2, minutes=14)
for i in range(38):
    ssh(t + timedelta(seconds=i * 7), False, random.choice(["root", "admin", "test", "oracle", "ubuntu"]), "203.0.113.45")

# Força bruta 2: insiste em "suporte" e CONSEGUE entrar (possível invasão)
t = base + timedelta(hours=3, minutes=2)
for i in range(12):
    ssh(t + timedelta(seconds=i * 20), False, "suporte", "198.51.100.77")
ssh(t + timedelta(seconds=12 * 20 + 5), True, "suporte", "198.51.100.77")

# Tentativas espaçadas (abaixo do limite de força bruta)
for h in (5, 11, 19):
    ssh(base + timedelta(hours=h, minutes=33), False, "root", "192.0.2.18")

# Login legítimo de madrugada (para conferir)
ssh(base + timedelta(hours=1, minutes=47), True, "bruno", "10.0.0.34")

# Ruído: eventos que não são login
for h in range(0, 24, 3):
    outro(base + timedelta(hours=h, minutes=1), f"CRON[{random.randint(1000,9999)}]: pam_unix(cron:session): session opened for user root")

linhas.sort(key=lambda x: x[0])
trecho = linhas[10:30]
random.shuffle(trecho)  # bagunça um trecho, como em logs reais concatenados
linhas[10:30] = trecho
os.makedirs("exemplos", exist_ok=True)
with open("exemplos/auth.log", "w") as f:
    f.write("\n".join(l for _, l in linhas) + "\n")
print(f"{len(linhas)} linhas geradas em exemplos/auth.log")
