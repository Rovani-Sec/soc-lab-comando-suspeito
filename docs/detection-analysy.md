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


Esse evento fornece informações importantes para investigação,
incluindo processo, processo pai, usuário e command line.

--

