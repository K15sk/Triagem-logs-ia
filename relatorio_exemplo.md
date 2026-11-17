# Relatório de triagem: `auth.log`

**Nível de risco: ALTO.** Há indício de que um atacante conseguiu entrar.

## Visão geral

| Indicador | Valor |
|---|---|
| Tentativas de login analisadas | 61 |
| Senhas erradas | 56 |
| Logins aceitos | 5 |
| IPs diferentes | 6 |
| Linhas ignoradas (outros eventos) | 8 |

## Possíveis invasões

Login **aceito** vindo de um IP que errou a senha 3 ou mais vezes na hora anterior. Pode ser alguém que adivinhou a senha.

| Quando | IP | Usuário | Falhas antes |
|---|---|---|---|
| 16/11 03:06:05 | 198.51.100.77 | suporte | 12 |

## Ataques de força bruta

| IP | Falhas | Primeira | Última |
|---|---|---|---|
| 203.0.113.45 | 38 | 16/11 02:14:00 | 16/11 02:18:19 |
| 198.51.100.77 | 12 | 16/11 03:02:00 | 16/11 03:05:40 |

## Logins aceitos de madrugada

| Quando | IP | Usuário |
|---|---|---|
| 16/11 01:47:00 | 10.0.0.34 | bruno |
| 16/11 03:06:05 | 198.51.100.77 | suporte |

## Usuários mais visados

| Usuário | Senhas erradas |
|---|---|
| suporte | 12 |
| root | 9 |
| oracle | 9 |
| ubuntu | 8 |
| test | 8 |

## Ações recomendadas

1. Trocar imediatamente a senha das contas da tabela de possíveis invasões e revisar o que foi feito nelas.
2. Bloquear no firewall os IPs de força bruta e ativar uma proteção automática, como o fail2ban.
3. Desativar login por senha no SSH e usar chaves; bloquear login direto do usuário root.
