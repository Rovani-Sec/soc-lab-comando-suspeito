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
   <group name="windows, powershell, evasion">
      <rule id="100106" level="12">
        <if_group>windows</if_group>
        <regex>-enc|-encodedcommand|-e\s</regex>
        <description>Alerta de Alta Severidade: possível execução de PowerShell com comando codificado em Base64.</description>
        <mitre>T1059.001/T1027</mitre>
      </rule>
   </group>
  ```
