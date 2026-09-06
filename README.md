# 🛡️ SOC Lab — Detecção de Comando PowerShell Ofuscado

Laboratório de detecção e análise de execução de comandos PowerShell utilizando codificação Base64 (-EncodedCommand), com coleta de eventos pelo Wazuh e aplicação de regra de detecção customizada.

## 🏗️ 1. Arquitetura do Laboratório

O ambiente simula uma rede corporativa segmentada, dividida entre zona de borda/segurança e infraestrutura de endpoints monitorados.

* **Gateway & Firewall de Borda:** pfSense (Responsável pela segmentação de rede, NAT e inspeção de tráfego com Suricata).
* **SIEM & Central de Inteligência:** Wazuh Manager (Coleta de logs, análise de segurança e motor de regras customizadas).
* **Endpoint Alvo (Vítima):** Windows 10 executando o Wazuh Agent (Monitoramento de eventos de segurança, auditoria de processos e integridade de arquivos).

---

## 🔍 2. Engenharia de Regras de Detecção Customizadas

Para mitigar lacunas em ameaças comuns de pós-exploração e reconhecimento, foram desenvolvidas regras customizadas no arquivo `local_rules.xml` do Wazuh:


### 🚨 Regra 100106: Execução de PowerShell Ofuscado (Base64)
```xml
Severidade: Alta
Rule ID: 100106
Objetivo: Detectar uso de parâmetros associados à execução de
          comandos PowerShell codificados/ofuscados.
```
* **Tática / Técnica MITRE ATT&CK:** [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* **Tática / Técnica MITRE AT&CK:** [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
* **Implementação (`local_rules.xml`):**
  ```xml
  <group name="windows,sysmon,powershell,evasion,">

  <!--
    Rule 100106
    Detecta execução de PowerShell utilizando EncodedCommand.
    Validada em laboratório com Sysmon Event ID 1.
  -->

  <rule id="100106" level="12">
    <if_sid>61603</if_sid>

    <regex type="pcre2">(?i)(?:-enc|-encodedcommand)\s+</regex>

    <description>
      Possível execução de PowerShell com comando codificado em Base64
    </description>

    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>

    <group>powershell,encoded_command,sysmon_event1,</group>
  </rule>

  </group>
  ```
 ### 📄 [Ver regra completa](config/local_rules.xml)
  ---

## 🔎 3. Investigação do Alerta

A regra `100106` foi validada através de uma execução controlada de PowerShell utilizando `-EncodedCommand`.

### Evidências principais

| Campo | Resultado |
|---|---|
| Endpoint | Windows10 |
| Usuário | WINDOWS10\joao |
| Sysmon Event ID | 1 — Process Creation |
| Processo pai | powershell.exe |
| Processo criado | whoami.exe |
| Rule ID | 100106 |
| Level | 12 |

### Command Line observada

```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -enc dwBoAG8AYQBtAGkA
```
O conteúdo Base64 foi decodificado para:

```text
whoami
```
A investigação demonstrou que a regra detectou corretamente o comportamento configurado, porém não foram encontradas evidências suficientes de atividade maliciosa.

Classificação final: Benigno após investigação.

📄 [Investigação completa](docs/investigation.md)

📄 [Análise da detecção](docs/detection-analysis.md)

---

## ✅ 4. Resultado do Laboratório

O laboratório validou com sucesso o fluxo de detecção e investigação:

```text
PowerShell
   ↓
-EncodedCommand
   ↓
Sysmon Event ID 1
   ↓
Wazuh Agent
   ↓
Rule 100106
   ↓
Alerta Level 12
   ↓
Investigação SOC
   ↓
Decodificação do payload
   ↓
Classificação: Benigno após investigação
```
---

### Competências demonstradas

- Engenharia de detecção no Wazuh
- Análise de eventos Sysmon
- Investigação de processos pai/filho
- Análise de Command Line
- Decodificação Base64
- Mapeamento MITRE ATT&CK
- Triagem e classificação de alertas

---

## 🧪 5. Reprodução do Laboratório

### Pré-requisitos

- Windows 10
- Sysmon configurado
- Wazuh Agent
- Wazuh Manager
- Regra `100106` instalada no Manager

### Comando utilizado para validação

Payload original:

```text
whoami
```
O comando foi codificado em Base64 utilizando UTF-16LE e executado através do PowerShell com -EncodedCommand.

---

### Fluxo de validação
- Executar o comando controlado no endpoint Windows.
- Confirmar a geração do Sysmon Event ID 1.
- Verificar o recebimento do evento pelo Wazuh Agent.
- Confirmar o acionamento da Rule 100106.
- Analisar o ParentCommandLine.
- Decodificar o conteúdo Base64.
- Classificar o alerta com base no contexto.

## O teste deve ser realizado apenas em ambiente controlado de laboratório.
