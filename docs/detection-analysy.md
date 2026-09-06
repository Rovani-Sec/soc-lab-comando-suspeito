# 🛡️ Análise da Detecção — Rule 100106

## 1. Objetivo

A regra `100106` foi desenvolvida para identificar possíveis execuções
de PowerShell utilizando comandos codificados através de Base64.

Esse comportamento pode estar relacionado à ofuscação de comandos e
execução de scripts durante atividades de pós-exploração.

---

## 2. Regra de Detecção

```xml
<group name="windows, powershell, evasion,">
  <rule id="100106" level="12">
    <if_group>windows</if_group>
    <regex>-enc|-encodedcommand|-e\s</regex>
    <description>Alerta de Alta Severidade: possível execução de PowerShell com comando codificado em Base64.</description>
    <mitre>T1059.001,T1027</mitre>
  </rule>
</group>
```
---

## 3. Lógica da Detecção

A regra procura parâmetros associados à utilização do
EncodedCommand do PowerShell.

### Principais indicadores:

Indicador	Descrição:
| Indicador         | Descrição                                                |
| ----------------- | -------------------------------------------------------- |
| `-enc`            | Abreviação de `-EncodedCommand`                          |
| `-EncodedCommand` | Parâmetro utilizado para executar comandos codificados   |
| `-e`              | Forma abreviada que pode aparecer em comandos PowerShell |

Quando esses indicadores são encontrados nos dados monitorados pelo
Wazuh, a regra pode gerar um alerta para investigação.

---

## 4. Severidade
**Level: 12**

O nível foi definido como alto devido ao potencial uso de comandos
PowerShell codificados em atividades de evasão, execução de payloads
ou pós-exploração.

A severidade do alerta não determina, isoladamente, que a atividade
seja maliciosa.

É necessária investigação contextual.

---

## 5. Telemetria Utilizada

O laboratório utiliza:
```text
Windows 10
Sysmon
Wazuh Agent
Wazuh Manager
Wazuh Dashboard
```
A validação da detecção utilizou o:
```text
Sysmon Event ID 1 — Process Creation
```
<img width="1369" height="819" alt="003-captura-windowsEvent" src="https://github.com/user-attachments/assets/c56adaa5-eaee-495b-a33e-d23ec355ddcb" />


Esse evento fornece informações importantes para investigação,
incluindo processo, processo pai, usuário e command line.

---

## 6. Validação da Regra

A detecção foi validada através de uma execução controlada de
PowerShell utilizando:

```text
-ExecutionPolicy Bypass
-EncodedCommand
```
Command Line observada:

```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -enc dwBoAG8AYQBtAGkA
```
O Wazuh identificou o comportamento e gerou:
```text
Rule ID: 100106
Level: 12
```

---

7. Análise do Payload

O payload utilizado no teste foi:
```text
dwBoAG8AYQBtAGkA
```
Após a decodificação utilizando Base64 com UTF-16LE:
```text
whoami
```
O comando executado é legítimo e foi utilizado neste laboratório
para validar a capacidade de detecção da regra.

---

8. MITRE ATT&CK

A detecção está relacionada às seguintes técnicas:

T1059.001 — PowerShell

O PowerShell foi utilizado para executar o comando.

T1027 — Obfuscated Files or Information

O comando foi codificado utilizando Base64.

A investigação também identificou:

T1033 — System Owner/User Discovery

O payload executou **_whoami_**, utilizado para identificar o usuário
atualmente logado.

---

## 9. Resultado

**Detecção:** _bem-sucedida_

A regra identificou corretamente a característica para a qual foi
desenvolvida: utilização de parâmetros associados ao
EncodedCommand.

O alerta foi posteriormente investigado e o payload foi identificado
como: **whoami**

Portanto, o evento foi classificado como:

*Benigno após investigação.*

---

## 10. Limitações

A regra baseada apenas em parâmetros como -enc pode gerar alertas
para atividades legítimas.

Por esse motivo, a regra deve ser utilizada como ponto inicial de
investigação e pode ser aprimorada através de correlação com:

```text
processo pai;
usuário;
Integrity Level;
conexões de rede;
criação de arquivos;
outros eventos Sysmon;
comportamento posterior à execução.
```

---

##11. Conclusão

A Rule 100106 demonstrou capacidade de detectar a utilização de
PowerShell com EncodedCommand.

O laboratório também demonstrou que uma detecção de alta severidade
não deve ser automaticamente classificada como incidente.

A análise do contexto e do payload é necessária para determinar a
natureza da atividade.
