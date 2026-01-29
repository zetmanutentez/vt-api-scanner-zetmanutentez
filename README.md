# VT Scanner Operacional (PowerShell)

## Enquadramento
Ferramenta de apoio operacional para triagem de incidentes de segurança
recorrendo à API pública do VirusTotal.

Desenvolvida para utilização em ambientes institucionais, sem necessidade
de privilégios administrativos, respeitando políticas de segurança, proxy
e segmentação de rede.

---

## Objetivo
- Apoiar equipas técnicas na análise rápida de:
  - URLs
  - Hashes
  - Ficheiros
  - Domínios
  - Endereços IP
- Produzir uma resposta técnica consistente para o utilizador final
- Reduzir risco de erro humano na interpretação dos resultados

---

## Requisitos
- Windows
- PowerShell 5.1 ou superior (recomendado PowerShell 7)
- Chave de API VirusTotal (plano público)

---

## Configuração (sem privilégios administrativos)

### Opção recomendada — variável de ambiente
setx VT_APIKEY "SUA_API_KEY_AQUI"
(Reabrir o PowerShell após definir)

### Alternativa — ficheiro de configuração do utilizador
%USERPROFILE%\.vt_scanner.json

Conteúdo:
{"ApiKey":"SUA_API_KEY_AQUI"}

---

## Funcionamento
- Interface interativa por menu
- Deteção automática de proxy
- Relatórios guardados no Desktop do utilizador (VT_Reports)

---

## Segurança
- Nenhuma credencial embutida no código
- Relatórios locais por utilizador
- Compatível com ambientes com inspeção HTTPS

---

## Público-alvo
- Helpdesk
- Técnicos de informática
- Equipas de IT e Segurança
