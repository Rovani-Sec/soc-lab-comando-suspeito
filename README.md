# 🛡️ Laboratório SOC N1: Monitoramento, Engenharia de Detecção e Resposta

Laboratório de Segurança Defensiva (Blue Team) construído para fins de estudo e simulação de ameaças, integrando roteamento de borda, SIEM, Endpoint Detection e visualização de dados em tempo real.

---

## 🏗️ 1. Arquitetura do Laboratório

O ambiente simula uma rede corporativa segmentada, dividida entre zona de borda/segurança e infraestrutura de endpoints monitorados.

* **Gateway & Firewall de Borda:** pfSense (Responsável pela segmentação de rede, NAT e inspeção de tráfego com Suricata).
* **SIEM & Central de Inteligência:** Wazuh Manager (Coleta de logs, análise de segurança e motor de regras customizadas).
* **Endpoint Alvo (Vítima):** Windows 10 executando o Wazuh Agent (Monitoramento de eventos de segurança, auditoria de processos e integridade de arquivos).

---

## 🔍 2. Engenharia de Regras de Detecção Customizadas

Para mitigar lacunas em ameaças comuns de pós-exploração e reconhecimento, foram desenvolvidas regras customizadas no arquivo `local_rules.xml` do Wazuh:


### 🚨 Regra 100106: Execução de PowerShell Ofuscado (Base64)
* **Objetivo:** Identificar tentativas de evasão de defesa e ocultação de payloads através da execução de comandos codificados em Base64 via PowerShell (`-enc`, `-encodedcommand`).
* **Tática / Técnica MITRE ATT&CK:** [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* **Implementação (`local_rules.xml`):**
  ```xml
  <group name="windows, powershell, evasion,">
    <rule id="100106" level="12">
      <if_group>windows</if_group>
      <regex>-enc|-encodedcommand|-e\s</regex>
      <description>Alerta Crítico SOC: Execução de script PowerShell ofuscado (Base64) detectada no endpoint.</description>
    </rule>
  </group>
  ```
