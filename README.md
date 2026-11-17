# Triagem automática de logs SSH com IA

Script em Python que lê um `auth.log` de um servidor Linux, encontra sinais de ataque e gera um relatório em português, escrito para quem não é da área de segurança. Opcionalmente, usa a API do Claude para escrever um resumo executivo com as ações mais urgentes.

## O problema

Um servidor exposto à internet recebe centenas de tentativas de login por dia. Ler o `auth.log` linha por linha para descobrir se alguém conseguiu entrar é lento, e o log muitas vezes nem está em ordem cronológica. Nos CTFs da faculdade eu fazia essa análise na mão, com `grep` e `sort`. Esta automação faz a triagem em segundos e entrega um resultado que um gestor consegue entender.

## O que a automação detecta

| Detecção | Regra |
|---|---|
| **Força bruta** | Um IP com 5 ou mais senhas erradas em 10 minutos (ajustável) |
| **Possível invasão** | Login aceito de um IP que errou a senha 3 ou mais vezes na hora anterior |
| **Acesso de madrugada** | Login aceito entre 0h e 6h |
| **Usuários mais visados** | Contas com mais tentativas de senha errada |

O relatório termina com um nível de risco (alto, médio ou baixo) e ações recomendadas.

## Como usar

Requer só Python 3, sem bibliotecas externas.

```bash
# 1. Gerar um log de exemplo (dados fictícios)
python3 gerar_exemplo.py

# 2. Rodar a triagem
python3 triagem_logs.py exemplos/auth.log --ano 2026

# Opções
python3 triagem_logs.py exemplos/auth.log --ano 2026 --limite 5 --janela 10 --saida relatorio.md
```

Saída no terminal:

```
Risco ALTO: Há indício de que um atacante conseguiu entrar.
2 IP(s) de força bruta · 1 possível(is) invasão(ões) · 2 acesso(s) de madrugada
Relatório salvo em relatorio.md
```

Veja o relatório completo gerado a partir do exemplo em [`relatorio_exemplo.md`](relatorio_exemplo.md).

### Resumo por IA (opcional)

Com uma chave da API da Anthropic, o relatório ganha uma seção de resumo executivo:

```bash
export ANTHROPIC_API_KEY="sua-chave"
python3 triagem_logs.py exemplos/auth.log --ano 2026
```

Por segurança, o script envia para a IA **apenas as estatísticas** (contagens, IPs suspeitos, horários), nunca o log completo. Sem a chave, ou se a API falhar, o relatório é gerado normalmente sem essa seção.

## Decisões de projeto

- **Ordenação antes da análise:** o `auth.log` pode vir fora de ordem (como no CTF "Na madruga"), então os eventos são ordenados por horário antes de qualquer regra.
- **Menos falsos positivos:** na primeira versão, qualquer login depois de um erro de senha virava "possível invasão", e funcionários que só digitaram errado uma vez apareciam como ataque. A regra foi ajustada para exigir 3 ou mais erros na hora anterior.
- **IA só onde ela agrega:** a detecção é feita por regras, que são previsíveis e auditáveis. A IA entra só para traduzir o resultado em linguagem de negócio.

## Como foi construído

Construído com o Claude (IA da Anthropic) como assistente de programação, a partir do tipo de análise que eu fazia manualmente nos CTFs da faculdade. Usar IA para transformar um processo manual em uma ferramenta foi parte do objetivo do projeto.

## Estrutura

```
.
├── triagem_logs.py          # a automação
├── gerar_exemplo.py         # gera um auth.log fictício em exemplos/ para testes
└── relatorio_exemplo.md     # relatório gerado a partir do log de exemplo
```

O log de exemplo não fica no repositório: ele é criado ao rodar `gerar_exemplo.py` (dados fictícios, com IPs reservados para documentação).

## Próximos passos

- Rodar automaticamente todo dia (cron) e enviar o relatório por e-mail ou Slack
- Bloquear os IPs de força bruta direto no firewall
- Suportar outros logs, como Apache e Windows (Sysmon)

---

Karen Simões Kroger · Segurança Cibernética · FIAP
