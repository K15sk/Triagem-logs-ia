#!/usr/bin/env python3
"""
Triagem automática de logs SSH (auth.log).

Lê um arquivo auth.log, identifica padrões de ataque e gera um relatório
em Markdown, escrito para quem não é especialista em segurança.

Detecções:
  - Força bruta: IP com muitas falhas de senha em pouco tempo
  - Possível invasão: login aceito de um IP que errou a senha 3+ vezes na hora anterior
  - Acesso fora do horário: login aceito de madrugada
  - Usuários mais visados pelos ataques

Resumo por IA (opcional): se a variável ANTHROPIC_API_KEY estiver definida,
o script envia as estatísticas (não o log bruto) para a API do Claude e
inclui no relatório um resumo executivo com prioridades de ação.

Uso:
  python3 triagem_logs.py exemplos/auth.log
  python3 triagem_logs.py exemplos/auth.log --saida relatorio.md --limite 5
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime

PADRAO = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d{1,2})\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<resultado>Failed|Accepted) password for (?:invalid user )?(?P<usuario>\S+) "
    r"from (?P<ip>[\d.]+) port \d+"
)
MESES = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def ler_eventos(caminho, ano):
    """Converte cada linha relevante do log em um dicionário."""
    eventos, ignoradas = [], 0
    with open(caminho, encoding="utf-8", errors="replace") as f:
        for linha in f:
            m = PADRAO.match(linha.strip())
            if not m:
                ignoradas += 1
                continue
            quando = datetime.strptime(
                f"{ano}-{MESES[m['mes']]:02d}-{int(m['dia']):02d} {m['hora']}", "%Y-%m-%d %H:%M:%S")
            eventos.append({
                "quando": quando,
                "ok": m["resultado"] == "Accepted",
                "usuario": m["usuario"],
                "ip": m["ip"],
            })
    eventos.sort(key=lambda e: e["quando"])  # logs nem sempre vêm em ordem
    return eventos, ignoradas


def analisar(eventos, limite_falhas, janela_min, madrugada):
    falhas_por_ip = defaultdict(list)
    alvos = Counter()
    achados = {"forca_bruta": [], "invasao_suspeita": [], "fora_do_horario": []}

    for e in eventos:
        if not e["ok"]:
            falhas_por_ip[e["ip"]].append(e["quando"])
            alvos[e["usuario"]] += 1
            continue
        # Login aceito: o mesmo IP errou a senha várias vezes na última hora?
        # (1 ou 2 erros antes de entrar é só alguém digitando errado)
        anteriores = [t for t in falhas_por_ip[e["ip"]]
                      if 0 <= (e["quando"] - t).total_seconds() <= 3600]
        if len(anteriores) >= 3:
            achados["invasao_suspeita"].append({**e, "falhas_antes": len(anteriores)})
        if e["quando"].hour < madrugada[1] and e["quando"].hour >= madrugada[0]:
            achados["fora_do_horario"].append(e)

    # Força bruta: N falhas dentro de uma janela de tempo
    for ip, tempos in falhas_por_ip.items():
        tempos.sort()
        inicio = 0
        for fim in range(len(tempos)):
            while (tempos[fim] - tempos[inicio]).total_seconds() > janela_min * 60:
                inicio += 1
            if fim - inicio + 1 >= limite_falhas:
                achados["forca_bruta"].append({
                    "ip": ip, "falhas": len(tempos),
                    "primeira": tempos[0], "ultima": tempos[-1]})
                break

    achados["forca_bruta"].sort(key=lambda a: -a["falhas"])
    stats = {
        "total_eventos": len(eventos),
        "falhas": sum(not e["ok"] for e in eventos),
        "sucessos": sum(e["ok"] for e in eventos),
        "ips_distintos": len({e["ip"] for e in eventos}),
        "usuarios_mais_visados": alvos.most_common(5),
        "top_ips_falhas": Counter({ip: len(t) for ip, t in falhas_por_ip.items()}).most_common(5),
    }
    return achados, stats


def nivel_de_risco(achados):
    if achados["invasao_suspeita"]:
        return "ALTO", "Há indício de que um atacante conseguiu entrar."
    if achados["forca_bruta"]:
        return "MÉDIO", "Há ataques de força bruta em andamento, sem sinal de sucesso."
    if achados["fora_do_horario"]:
        return "BAIXO", "Só há acessos em horário incomum para conferir."
    return "BAIXO", "Nenhum padrão de ataque encontrado."


def resumo_ia(stats, achados, risco):
    """Pede ao Claude um resumo executivo. Envia só estatísticas, nunca o log."""
    chave = os.environ.get("ANTHROPIC_API_KEY")
    if not chave:
        return None
    dados = {
        "risco": risco,
        "estatisticas": stats,
        "forca_bruta": [{"ip": a["ip"], "falhas": a["falhas"]} for a in achados["forca_bruta"][:5]],
        "invasao_suspeita": [{"ip": a["ip"], "usuario": a["usuario"], "falhas_antes": a["falhas_antes"],
                              "quando": a["quando"].isoformat()} for a in achados["invasao_suspeita"]],
        "fora_do_horario": len(achados["fora_do_horario"]),
    }
    pedido = {
        "model": os.environ.get("MODELO_IA", "claude-haiku-5-5"),
        "max_tokens": 600,
        "messages": [{"role": "user", "content":
            "Você é analista de segurança. Com base nestes dados de triagem de um auth.log, "
            "escreva em português, para um gestor sem formação técnica: (1) o que aconteceu em 2 frases, "
            "(2) as 3 ações mais urgentes, em ordem. Não invente dados que não estejam aqui.\n\n"
            + json.dumps(dados, ensure_ascii=False, default=str)}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=json.dumps(pedido).encode(),
        headers={"x-api-key": chave, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            resposta = json.load(r)
        return "".join(b.get("text", "") for b in resposta.get("content", []))
    except Exception as erro:  # o relatório sai mesmo sem a IA
        return f"_Não foi possível gerar o resumo por IA ({erro})._"


def gerar_relatorio(arquivo, stats, achados, ignoradas, texto_ia):
    nivel, motivo = nivel_de_risco(achados)
    fmt = lambda d: d.strftime("%d/%m %H:%M:%S")
    L = [f"# Relatório de triagem: `{os.path.basename(arquivo)}`", "",
         f"**Nível de risco: {nivel}.** {motivo}", "",
         "## Visão geral", "",
         "| Indicador | Valor |", "|---|---|",
         f"| Tentativas de login analisadas | {stats['total_eventos']} |",
         f"| Senhas erradas | {stats['falhas']} |",
         f"| Logins aceitos | {stats['sucessos']} |",
         f"| IPs diferentes | {stats['ips_distintos']} |",
         f"| Linhas ignoradas (outros eventos) | {ignoradas} |", ""]

    if texto_ia:
        L += ["## Resumo executivo (gerado por IA)", "", texto_ia.strip(), ""]

    L += ["## Possíveis invasões", ""]
    if achados["invasao_suspeita"]:
        L += ["Login **aceito** vindo de um IP que errou a senha 3 ou mais vezes na hora anterior. Pode ser alguém que adivinhou a senha.", "",
              "| Quando | IP | Usuário | Falhas antes |", "|---|---|---|---|"]
        L += [f"| {fmt(a['quando'])} | {a['ip']} | {a['usuario']} | {a['falhas_antes']} |"
              for a in achados["invasao_suspeita"]]
    else:
        L.append("Nenhuma.")
    L.append("")

    L += ["## Ataques de força bruta", ""]
    if achados["forca_bruta"]:
        L += ["| IP | Falhas | Primeira | Última |", "|---|---|---|---|"]
        L += [f"| {a['ip']} | {a['falhas']} | {fmt(a['primeira'])} | {fmt(a['ultima'])} |"
              for a in achados["forca_bruta"]]
    else:
        L.append("Nenhum.")
    L.append("")

    L += ["## Logins aceitos de madrugada", ""]
    if achados["fora_do_horario"]:
        L += ["| Quando | IP | Usuário |", "|---|---|---|"]
        L += [f"| {fmt(e['quando'])} | {e['ip']} | {e['usuario']} |" for e in achados["fora_do_horario"]]
    else:
        L.append("Nenhum.")
    L.append("")

    L += ["## Usuários mais visados", "", "| Usuário | Senhas erradas |", "|---|---|"]
    L += [f"| {u} | {n} |" for u, n in stats["usuarios_mais_visados"]]
    L += ["", "## Ações recomendadas", ""]
    acoes = []
    if achados["invasao_suspeita"]:
        acoes.append("Trocar imediatamente a senha das contas da tabela de possíveis invasões e revisar o que foi feito nelas.")
    if achados["forca_bruta"]:
        acoes.append("Bloquear no firewall os IPs de força bruta e ativar uma proteção automática, como o fail2ban.")
    acoes.append("Desativar login por senha no SSH e usar chaves; bloquear login direto do usuário root.")
    L += [f"{i}. {a}" for i, a in enumerate(acoes, 1)]
    return "\n".join(L) + "\n"


def main():
    p = argparse.ArgumentParser(description="Triagem automática de auth.log")
    p.add_argument("arquivo", help="caminho do auth.log")
    p.add_argument("--saida", default="relatorio.md", help="arquivo do relatório (padrão: relatorio.md)")
    p.add_argument("--limite", type=int, default=5, help="falhas para considerar força bruta (padrão: 5)")
    p.add_argument("--janela", type=int, default=10, help="janela de tempo em minutos (padrão: 10)")
    p.add_argument("--ano", type=int, default=datetime.now().year, help="ano dos registros (o auth.log não traz o ano)")
    a = p.parse_args()

    if not os.path.exists(a.arquivo):
        sys.exit(f"Arquivo não encontrado: {a.arquivo}")
    eventos, ignoradas = ler_eventos(a.arquivo, a.ano)
    if not eventos:
        sys.exit("Nenhum evento de login SSH encontrado no arquivo.")
    achados, stats = analisar(eventos, a.limite, a.janela, madrugada=(0, 6))
    texto_ia = resumo_ia(stats, achados, nivel_de_risco(achados)[0])
    with open(a.saida, "w", encoding="utf-8") as f:
        f.write(gerar_relatorio(a.arquivo, stats, achados, ignoradas, texto_ia))

    nivel, motivo = nivel_de_risco(achados)
    print(f"Risco {nivel}: {motivo}")
    print(f"{len(achados['forca_bruta'])} IP(s) de força bruta · "
          f"{len(achados['invasao_suspeita'])} possível(is) invasão(ões) · "
          f"{len(achados['fora_do_horario'])} acesso(s) de madrugada")
    print(f"Relatório salvo em {a.saida}" + ("" if texto_ia else " (sem resumo por IA: defina ANTHROPIC_API_KEY)"))


if __name__ == "__main__":
    main()
