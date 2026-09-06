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

<img width="1369" height="819" alt="003-captura-windowsEvent" src="https://github.com/user-attachments/assets/8b57ec38-5c4b-4fed-b958-c85de15b9ca1" />

### Integrity Level: **High**



---

## 4. Análise do Payload

O parâmetro -enc indica o uso de -EncodedCommand.

Payload identificado:
```text
dwBoAG8AYQBtAGkA
```

Após a decodificação em Base64 utilizando CyberChef:
```text
whoami
```
<img width="1911" height="271" alt="005-decode-Base64" src="https://github.com/user-attachments/assets/7c1035fa-c44f-4354-b7c6-0acfbc2c0bff" />

O comando executado corresponde ao utilitário legítimo whoami,
utilizado para identificar o usuário atualmente logado.

---

## 5. Análise do Comportamento

Foram observados os seguintes indicadores:

PowerShell utilizado para execução do comando;
-ExecutionPolicy Bypass;
utilização de -EncodedCommand;
execução com Integrity Level High.

<img width="906" height="386" alt="004-captura-comando-ofuscado" src="https://github.com/user-attachments/assets/05e42af9-7d5f-422f-9875-97e7928f555a" />


Apesar desses indicadores justificarem a geração do alerta, o payload
analisado executou somente o comando legítimo whoami.

Não foram observadas, neste evento:

conexão de rede suspeita;
download de arquivos;
criação de payload;
persistência;
execução de malware.

---

## 6. MITRE ATT&CK
| Técnica                         | ID        | Evidência                      |
| ------------------------------- | --------- | ------------------------------ |
| PowerShell                      | T1059.001 | Execução através do PowerShell |
| Obfuscated Files or Information | T1027     | Comando codificado em Base64   |
| System Owner/User Discovery     | T1033     | Execução do `whoami`           |

---

## 7. Classificação

**Resultado:** Suspicious Activity

A detecção foi considerada válida, pois a regra identificou corretamente
a utilização de -EncodedCommand.
Entretanto, a investigação do payload demonstrou que o comando executado
foi apenas **whoami**, sem evidências adicionais de atividade maliciosa.

Classificação final: Benigno após investigação.

---
## 8. Conclusão

O alerta demonstrou um comportamento potencialmente suspeito de PowerShell,
porém a análise do processo, command line e payload não apresentou evidências
suficientes para caracterizar comprometimento.

O alerta pode ser encerrado como Benigno após investigação, mantendo o
monitoramento para possíveis eventos correlacionados.
