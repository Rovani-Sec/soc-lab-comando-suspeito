# 🔎 Investigação de Alerta — PowerShell EncodedCommand

## 1. Identificação

| Campo | Valor |
|---|---|
| Plataforma SIEM | Wazuh |
| Endpoint | Windows10 |
| Usuário | WINDOWS10\joao |
| Rule ID | 100106 |
| Nível | 12 |
| Fonte | Microsoft-Windows-Sysmon/Operational |
| Sysmon Event ID | 1 |
| Event Record ID | 65196 |
| Data/Hora UTC | 2026-09-05 23:40:05.667 |
| Data/Hora local | 2026-09-05 20:40:05.667 |
| Classificação inicial | Suspicious Activity |

---

## 2. Resumo do Alerta

O Wazuh gerou um alerta de alta severidade associado à execução de PowerShell utilizando o parâmetro `-EncodedCommand` (`-enc`).

A regra customizada 100106 foi criada para identificar parâmetros frequentemente associados à execução de comandos PowerShell codificados em Base64.

O evento foi posteriormente correlacionado com um evento Sysmon Event ID 1 (Process Creation).

---

## 3. Evidências

### 3.1 Processo Pai

O processo responsável pela criação do processo analisado foi:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
### Command Line:
```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -enc dwBoAG8AYQBtAG
```
### Processo Executado:
```text
C:\Windows\System32\whoami.exe
```

### Integrity Level: **High**

---

4. Análise do Payload

O parâmetro -enc indica o uso de -EncodedCommand.

Payload identificado:

```text
dwBoAG8AYQBtAGkA
```

Após a decodificação em Base64 utilizando UTF-16LE:
```text
whoami
```

O comando executado corresponde ao utilitário legítimo whoami,
utilizado para identificar o usuário atualmente logado.
