# script-ctf

Guia (alto-nível) de Digitalização & Enumeração — metodologia, ferramentas e checklists
1) Planejamento e legalidade (pré-engajamento)

Obtenha autorização escrita (Rules of Engagement). Defina escopo: IPs/domínios permitidos, janelas de teste, ferramentas permitidas, limites de impacto.

Defina objetivos: inventário, avaliação de superfície de ataque, auditoria de configuração, etc.

Prepare backups, comunicação de emergência e plano de rollback.

Documente tudo (logs, horários, quem autorizou).

2) Reconhecimento passivo (OSINT)

Objetivo: coletar informações sem tocar o alvo diretamente.

O que buscar: domínios, subdomínios, certificados, exposição em Shodan/Censys, endereços de e-mail públicos, funcionários, infraestrutura cloud, registros DNS/WHOIS.

Ferramentas/comuns (propósito):

amass, subfinder, assetfinder — descoberta/passiva de subdomínios.

theHarvester — e-mails e hostnames públicos.

crt.sh / Certificate transparency — certificados e subdomínios.

Shodan, Censys, BinaryEdge — serviços expostos na Internet.

VirusTotal / urlscan — histórico de URLs e arquivos.

Entregável: lista de ativos, ranges IP, domínio/subdomínios, tecnologias aparentes.

3) Reconhecimento ativo (não-exploratório)

Objetivo: descobrir hosts e serviços com baixo impacto (sem explorar vulnerabilidades).

O que fazer: resolução DNS, verificação de portas abertas, fingerprinting de serviços, coleta de banners, certificados TLS.

Ferramentas/comuns (propósito):

masscan, rustscan — varredura rápida de portas (escala).

nmap — descoberta, fingerprint e scripts para coleta de informação.

sslyze, sslscan — análise de TLS/certificados.

whatweb, wappalyzer — identificar tecnologias web.

Observação: ajustar velocidade para evitar impacto/DoS; sempre respeitar o RoE.

4) Enumeração de serviços (por protocolo)

Objetivo: entender versões, credenciais expostas, diretórios, APIs, etc.

Web: descoberta de diretórios/endpoints, fingerprinting, forms, headers. Ferramentas: gobuster, ffuf, dirsearch, nikto, Burp/ZAP (proxy).

SMB/Windows/AD: enumeração de shares, usuários, políticas; ferramentas: smbclient, smbmap, enum4linux, crackmapexec, BloodHound (análise relacional).

DNS/LDAP/SMTP/SNMP: ferramentas dedicadas (dnsenum, dnsrecon, ldapsearch, snmpwalk, smtp-user-enum).

Bancos de dados: verifique exposição de serviços (MySQL, PostgreSQL, MongoDB) e versões.

Nota: não executar ações destrutivas (ex.: brute force sem autorização).

5) Varredura de vulnerabilidades (reconhecimento passivo e ativo)

Objetivo: identificar potenciais vulnerabilidades para priorização (não exploração sem autorização).

Ferramentas: scanners comerciais/opensource (Nessus, OpenVAS), nmap NSE, Nikto para web.

Recomenda: validar manualmente os achados; scanners geram falsos positivos.

6) Enumeração específica de aplicações web

Abordar OWASP Top 10: injection, auth flaws, XSS, CSRF, insecure direct object refs, SSRF, file upload, etc.

Ferramentas: Burp Suite (intercept/proxy), ZAP, wfuzz/ffuf para fuzzing, sqlmap (para testes em laboratório), ferramentas de análise de sessão/cookies.

Recomenda: keep a prova de conceito não destrutiva; focar em replicar e documentar.

7) Coleta de credenciais & password auditing (só em lab/autorizado)

Ferramentas de brute/credential stuffing: Hydra, Medusa, CrackMapExec.

Ferramentas offline: john, hashcat para cracking de hashes em ambiente controlado.

Usar wordlists atualizadas e política de uso ético.

8) Pós-enumeração / análise (alta prioridade)

Agrupar e priorizar achados (impacto x probabilidade).

Preparar recomendação de mitigação (patch, configuração, segmentação, monitoramento).

9) Relatório & Disclosure

Entregáveis: sumário executivo, evidências (prints/logs), lista de vulnerabilidades com CVSS/risco e passos de correção, timeline, recomendações de mitigação e retest.

Estabelecer canal de comunicação seguro para disclosure.

10) Limpeza

Assegure que não ficaram backdoors ou contas criadas. Remova artefatos e restaure snapshots se necessário.

Ferramentas — catálogo categorizado (descrição curta)

OSINT / Subdomain: amass, subfinder, assetfinder, theHarvester, crt.sh.

Port scanning / discovery: masscan, rustscan, nmap (fingerprint + scripts).

Web discovery / fuzzing: gobuster, ffuf, dirsearch, burp suite, zaproxy.

Web scanners: nikto, wpscan (WordPress-specific).

Vuln scanners (enterprise/open): Nessus, OpenVAS.

SSL/TLS & certs: sslyze, sslscan, openssl (consulta).

SMB/AD tools: smbclient, smbmap, enum4linux, crackmapexec, bloodhound, impacket (biblioteca).

Password cracking / hashes: john, hashcat.

Network sniffing / MITM: tcpdump, Wireshark, bettercap (uso apenas em lab/perm).

Exploit frameworks: Metasploit (framework).

Windows post-exploit / AD: Mimikatz, Rubeus, PowerSploit — apenas em ambiente controlado.

Automação / workflows: scripts Python/Go, nmap + jq + pipelines para parsing.
(Obs.: listei nomes e propósitos — não vou fornecer comandos de uso.)
