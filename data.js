window.TRAINING_DATA = {
  "chapters": [
    {
      "title": "1. Rolul SOC Analyst si fluxul alertelor",
      "minutes": 20,
      "content": "\nObiectivul unui SOC Analyst este sa monitorizeze, sa triageze, sa investigheze si sa escaladeze incidente de securitate. Intr-un interviu de 30 de minute se cauta mai ales gandire structurata, intelegere a logurilor si capacitatea de a explica clar deciziile.\n\nFlux tipic pentru o alerta:\n1. Validare: este alerta reala, duplicat, test sau zgomot?\n2. Context: cine, ce, cand, unde, cum; user, host, IP, proces, hash, port, locatie.\n3. Severitate: impact + probabilitate + criticitatea assetului.\n4. Investigatie: timeline, surse de log, corelare cu IOC/TTP, cautari in SIEM.\n5. Containment: dezactivare user, izolarea hostului, blocare IP/domain/hash, reset parola.\n6. Eradicare si recovery: eliminare persistenta, patching, restaurare, monitorizare.\n7. Raport: concluzie, dovezi, actiuni, recomandari, lectii invatate.\n\nClasificare uzuala:\n- True Positive: activitate malitioasa confirmata.\n- Benign True Positive: regula a detectat corect un comportament riscant, dar legitim.\n- False Positive: alerta fara risc real.\n- False Negative: incident nedetectat de reguli.\n\nCe sa spui la interviu:\n\"Incep cu validarea alertei si contextul assetului, construiesc un timeline din loguri, caut indicatori similari in mediul clientului, apoi escaladez cu dovezi clare si actiuni recomandate.\"\n",
      "key_points": [
        "Triage inseamna validare rapida + prioritizare, nu investigatie nesfarsita.",
        "Severitatea depinde de impact, probabilitate si criticitatea assetului.",
        "Un raport bun contine timeline, dovezi, concluzie si recomandari."
      ]
    },
    {
      "title": "2. Windows: loguri, Event IDs si investigatii",
      "minutes": 35,
      "content": "\nSurse principale:\n- Security.evtx: autentificari, privilegii, procese daca auditarea este activa.\n- System.evtx: servicii, drivere, erori de sistem.\n- Application.evtx: aplicatii si crash-uri.\n- PowerShell Operational: script blocks, module logging.\n- Sysmon: proces, network connection, file create, registry, DNS, driver load.\n\nEvent IDs importante:\n- 4624: Logon successful. Verifica Logon Type: 2 interactive, 3 network, 10 RDP.\n- 4625: Failed logon. Multe incercari pot indica brute force/password spraying.\n- 4634/4647: logoff.\n- 4672: special privileges assigned; posibil admin logon.\n- 4688: process creation; esential pentru command line.\n- 4697/7045: service installed; posibil persistenta.\n- 4720/4726: user created/deleted.\n- 4728/4732/4756: user added to privileged/local groups.\n- 4768/4769/4771: Kerberos auth/TGS/preauth failed.\n- 4776: NTLM authentication.\n- 1102: audit log cleared; foarte suspect.\n\nSysmon IDs utile:\n- 1 Process Create, 3 Network Connection, 7 Image Loaded, 10 Process Access, 11 File Create,\n  12/13/14 Registry, 22 DNS Query.\n\nComenzi suspecte:\n- powershell -enc, -nop, -w hidden\n- cmd /c whoami, net user, net localgroup administrators\n- certutil -urlcache, bitsadmin, mshta, rundll32, regsvr32, wmic, schtasks\n- vssadmin delete shadows, wbadmin delete catalog\n\nIntrebari de interviu frecvente:\n- Cum investighezi un 4625 masiv? Raspuns: agregare pe user/IP/host, pattern temporal, geolocatie/VPN, conturi afectate, logon type, urmat de blocare IP/reset parola daca e valid.\n- Cum vezi executie PowerShell malitioasa? Raspuns: 4688/Sysmon 1 + PowerShell logs + network/DNS + parent process + encoded command decoding.\n",
      "key_points": [
        "4624 nu inseamna automat benign; logon type si sursa conteaza.",
        "4688/Sysmon 1 cu command line este aur pentru investigatii.",
        "1102 audit log cleared este aproape mereu high severity."
      ]
    },
    {
      "title": "3. Linux: autentificare, procese si persistenta",
      "minutes": 25,
      "content": "\nLoguri utile:\n- /var/log/auth.log sau /var/log/secure: SSH, sudo, autentificari.\n- /var/log/syslog sau /var/log/messages: sistem si servicii.\n- journalctl: loguri systemd.\n- bash_history/zsh_history: comenzi, dar poate fi sters/manipulat.\n- auditd: execve, file changes, privilege events.\n\nIndicatori suspecti:\n- SSH brute force: multe \"Failed password\" de la aceeasi sursa sau multe useri.\n- Successful login dupa multe esecuri.\n- sudo neobisnuit sau user adaugat in sudoers.\n- procese din /tmp, /dev/shm, /var/tmp.\n- cron jobs, systemd services sau rc.local modificate.\n- chei SSH noi in ~/.ssh/authorized_keys.\n- outbound connections catre IP-uri necunoscute.\n\nComenzi de investigatie:\n- last, lastb, who, w\n- ps aux, top, lsof -i, ss -tulpn\n- find / -perm -4000 -type f 2>/dev/null pentru SUID\n- crontab -l, ls /etc/cron*, systemctl list-timers\n- journalctl -u ssh, journalctl --since \"1 hour ago\"\n\nRaspuns bun la interviu:\n\"Pe Linux verific auth.log pentru esecuri si login reusit, corelez userul cu sudo/auditd, verific procesele active si conexiunile, apoi caut persistenta in cron, systemd si authorized_keys.\"\n",
      "key_points": [
        "Login reusit dupa brute force este mai important decat brute force singur.",
        "Persistenta Linux apare des in cron, systemd, authorized_keys.",
        "Procesele rulate din /tmp sau /dev/shm sunt suspecte."
      ]
    },
    {
      "title": "4. Retele si protocoale pentru SOC",
      "minutes": 30,
      "content": "\nConcepte esentiale:\n- TCP handshake: SYN, SYN-ACK, ACK. Port scan poate avea multe SYN fara sesiuni complete.\n- UDP este connectionless; DNS, NTP, QUIC folosesc UDP.\n- DNS transforma nume in IP; investigheaza domenii noi, DGA, NXDOMAIN multe.\n- HTTP/HTTPS: metode, status codes, User-Agent, Host, URI, SNI, certificate.\n- SMTP/IMAP/POP3: email si phishing.\n- SMB/RDP/WinRM: miscari laterale si administrare Windows.\n- SSH: administrare Linux, brute force.\n- ICMP: ping, tunneling rar dar posibil.\n\nPorturi comune:\n- 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB, 3389 RDP, 5985/5986 WinRM.\n\nFirewall logs:\n- allow/deny, src_ip, dst_ip, src_port, dst_port, protocol, action, rule, bytes, session duration.\n- Un deny nu inseamna compromitere; un allow catre C2 cunoscut este mult mai important.\n\nSemne de activitate suspecta:\n- Beaconing: conexiuni periodice catre acelasi domeniu/IP.\n- Data exfiltration: volum mare outbound, destinatie neobisnuita, ore neobisnuite.\n- Port scanning: multe destinatii/porturi intr-un interval scurt.\n- Lateral movement: SMB/RDP/WinRM intre endpointuri.\n",
      "key_points": [
        "Pentru retea explica src/dst/protocol/action si contextul assetului.",
        "Beaconing periodic este un pattern clasic de C2.",
        "SMB/RDP/WinRM intre statii poate indica lateral movement."
      ]
    },
    {
      "title": "5. Microsoft 365 si Google Workspace",
      "minutes": 30,
      "content": "\nMicrosoft 365 surse:\n- Unified Audit Log: activitati user/admin.\n- Entra ID/Azure AD Sign-in logs: autentificari, MFA, conditional access.\n- Audit logs pentru Exchange: inbox rules, forwarding, mailbox access.\n- Defender for Office 365: phishing, malware, safe links.\n\nEvenimente suspecte M365:\n- Impossible travel sau login din tara neobisnuita.\n- MFA fatigue: multe push-uri MFA respinse urmate de succes.\n- Legacy authentication: IMAP/POP/SMTP AUTH fara MFA.\n- Inbox rule: forward extern, delete/move mesaje cu keywords financiare.\n- Consent grant pentru aplicatie OAuth necunoscuta.\n- Modificari admin/privilege escalation.\n\nGoogle Workspace:\n- Login audit: login success/fail, suspicious login.\n- Admin audit: schimbari de roluri, politici, 2FA.\n- Drive audit: share extern, download masiv.\n- Gmail audit/investigation: forwarding, delegation, filters.\n\nRaspuns la BEC/phishing:\n1. Identifica user afectat, IP, locatie, device, metoda auth.\n2. Revoca sesiuni/tokenuri, reset parola, impune MFA.\n3. Cauta inbox rules/forwarding/delegation/OAuth grants.\n4. Cauta emailuri trimise intern/extern si alte conturi afectate.\n5. Raporteaza impactul si recomanda hardening.\n",
      "key_points": [
        "Inbox rules si forwarding sunt cheie in BEC.",
        "Legacy auth ocoleste deseori MFA si trebuie dezactivata.",
        "OAuth consent malitios poate persista dupa resetarea parolei."
      ]
    },
    {
      "title": "6. AWS si cloud security basics",
      "minutes": 25,
      "content": "\nAWS loguri si servicii:\n- CloudTrail: API calls, cine a facut ce, cand si de unde.\n- GuardDuty: detectii managed pentru threat activity.\n- VPC Flow Logs: trafic retea in VPC.\n- IAM Access Analyzer: expuneri de acces.\n- CloudWatch: metrici si loguri.\n\nEvenimente CloudTrail suspecte:\n- ConsoleLogin fara MFA sau din locatie neobisnuita.\n- CreateAccessKey pentru user neobisnuit.\n- AttachUserPolicy/PutUserPolicy cu AdministratorAccess.\n- DisableTrail/DeleteTrail/StopLogging.\n- AuthorizeSecurityGroupIngress 0.0.0.0/0 pe SSH/RDP.\n- GetObject/ListBucket pe bucket sensibil sau exfiltrare.\n\nPrincipii:\n- Least privilege, MFA pentru root/admin, rotatie chei, separare roluri.\n- Nu folosi root account pentru activitati zilnice.\n- Blocheaza public access la S3 cand nu e necesar.\n\nRaspuns la cheie AWS compromisa:\n1. Dezactiveaza/roteste cheia.\n2. Verifica CloudTrail pentru actiuni facute cu access key id.\n3. Cauta resurse create: EC2, IAM users, policies, security groups.\n4. Evalueaza exfiltrarea S3 si cost abuse.\n",
      "key_points": [
        "CloudTrail este sursa principala pentru cine/ce/cand in AWS.",
        "DisableTrail sau StopLogging este high severity.",
        "CreateAccessKey + privilege changes poate indica compromitere IAM."
      ]
    },
    {
      "title": "7. Wazuh, SIEM si detection engineering",
      "minutes": 35,
      "content": "\nSIEM colecteaza, normalizeaza, coreleaza si alerteaza pe baza logurilor. Wazuh include agenti, manager, rules, decoders, dashboards si integrare cu OpenSearch/Elastic in multe arhitecturi.\n\nWazuh concepte:\n- Agent: colecteaza loguri, FIM, inventory, SCA.\n- Manager: proceseaza evenimente si reguli.\n- Decoder: extrage campuri din log brut.\n- Rule: conditii, nivel, grupuri, MITRE mapping.\n- FIM: File Integrity Monitoring.\n- Active response: actiuni automate controlate.\n\nRegula buna:\n- Are scop clar, campuri corecte, severitate potrivita.\n- Reduce false positive prin exceptii documentate.\n- Include mapping MITRE ATT&CK, de exemplu T1059 Command and Scripting Interpreter.\n- Are test cases cu loguri pozitive si negative.\n\nQuery mindset:\n- filtreaza pe timp, user, host, IP, event_id, process_name, parent_process, command_line.\n- cauta agregari: top users, top source IP, unique hosts, first seen.\n- pivoteaza: hash -> hosts, IP -> users, process -> command line.\n\nExemplu pseudo-Wazuh rule:\n<rule id=\"100100\" level=\"10\">\n  <if_sid>61603</if_sid>\n  <field name=\"win.eventdata.image\">powershell.exe</field>\n  <match>-enc|-encodedcommand|downloadstring</match>\n  <description>Suspicious PowerShell execution</description>\n  <mitre><id>T1059.001</id></mitre>\n</rule>\n",
      "key_points": [
        "Decoder extrage campuri; rule decide daca evenimentul devine alerta.",
        "Detection engineering inseamna detectie + testare + reducere false positive.",
        "MITRE ATT&CK ajuta la clasificarea TTP-urilor."
      ]
    },
    {
      "title": "8. EDR, malware si endpoint triage",
      "minutes": 25,
      "content": "\nEDR monitorizeaza endpointuri pentru procese, fisiere, registry, conexiuni, memory si comportamente suspecte.\n\nCe verifici intr-o alerta EDR:\n- Proces suspect: path, command line, parent process, user, integrity level.\n- Hash si reputation: VirusTotal, sandbox, internal prevalence.\n- Network: domenii/IP-uri, periodicitate, bytes.\n- Persistence: Run keys, services, scheduled tasks, startup folder, WMI subscriptions.\n- Lateral movement: credential dumping, RDP/SMB/WinRM.\n\nProcese si LOLBins:\n- powershell, cmd, wscript/cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, wmic, schtasks.\n\nCredential dumping indicators:\n- lsass access, procdump, comsvcs.dll MiniDump, mimikatz strings, suspicious handle access.\n\nContainment:\n- izolare host prin EDR, kill process, quarantine file, block hash, collect triage package, reset credentiale.\n",
      "key_points": [
        "Parent-child process relationship este esential.",
        "LOLBins sunt utilitare legitime abuzate de atacatori.",
        "Izolarea hostului este containment, nu rezolvare completa."
      ]
    },
    {
      "title": "9. Incident Response si raportare",
      "minutes": 30,
      "content": "\nModel NIST IR:\n1. Preparation\n2. Detection and Analysis\n3. Containment, Eradication and Recovery\n4. Post-Incident Activity\n\nPentru un incident, documenteaza:\n- Summary: ce s-a intamplat, impact, status.\n- Timeline: toate evenimentele relevante cu timestamp si timezone.\n- Scope: useri, hosturi, IP-uri, aplicatii, date afectate.\n- Evidence: loguri, alert IDs, hashes, screenshots unde e cazul.\n- Actions taken: blocari, resetari, izolari, reguli adaugate.\n- Recommendations: MFA, patching, detections, hardening, training.\n\nPrioritizare:\n- Critical: ransomware, exfiltrare, admin compromise, production critical.\n- High: malware confirmat, credential compromise, lateral movement.\n- Medium: suspicious behavior fara impact confirmat.\n- Low: scan, blocked attempt, benign policy violation.\n\nSub presiune:\n- Pastreaza calmul, noteaza timestampurile, comunica clar ce stii si ce nu stii, nu presupune fara dovezi.\n",
      "key_points": [
        "Timeline-ul este coloana vertebrala a raportului de incident.",
        "Containment rapid trebuie echilibrat cu pastrarea dovezilor.",
        "Comunica incertitudinea: confirmat, probabil, neconfirmat."
      ]
    },
    {
      "title": "10. Threat Intelligence, OSINT, Dark Web si Telegram",
      "minutes": 30,
      "content": "\nThreat Intelligence transforma date brute in informatie actionabila.\n\nTipuri:\n- Strategic: riscuri pentru business.\n- Operational: campanii, grupuri, tinte.\n- Tactical: TTP-uri MITRE.\n- Technical: IOC-uri: IP, domain, URL, hash, email, JA3.\n\nOSINT surse:\n- WHOIS/RDAP, DNS history, Certificate Transparency, URLScan, VirusTotal, Shodan/Censys, GitHub, paste sites, social media.\n- Pentru Telegram/Dark Web: monitorizare controlata, fara interactiune ilegala, colectare de dovezi, verificarea credibilitatii.\n\nEvaluarea unui IOC:\n- Este recent? Are reputatie? Este shared infrastructure/CDN? Este specific campaniei?\n- Un IOC singur nu inseamna incident; trebuie corelat cu loguri interne.\n\nDark Web/Telegram use cases:\n- credential leaks, mentions ale companiei/clientului, data dumps, ransomware leak sites, phishing kits, malware C2.\n\nEtica si legal:\n- Nu cumperi date, nu intri in sisteme, nu interactionezi cu actori malitiosi fara aprobare clara.\n- Raportezi ce ai gasit, cu sursa, timestamp si nivel de incredere.\n",
      "key_points": [
        "IOC-urile trebuie validate si corelate cu telemetria interna.",
        "OSINT bun are sursa, timestamp si confidence level.",
        "Nu depasi limitele legale in Dark Web/Telegram monitoring."
      ]
    },
    {
      "title": "11. Atacuri comune si MITRE ATT&CK",
      "minutes": 35,
      "content": "\nMITRE ATT&CK organizeaza tehnici folosite de atacatori pe tactici:\n- Initial Access: phishing, exploit public-facing app, valid accounts.\n- Execution: PowerShell, command shell, scripts.\n- Persistence: services, scheduled tasks, registry run keys.\n- Privilege Escalation: token impersonation, vulnerable driver.\n- Defense Evasion: log clearing, obfuscation, disable tools.\n- Credential Access: LSASS dumping, phishing, browser credentials.\n- Discovery: whoami, net user, ipconfig, nltest.\n- Lateral Movement: RDP, SMB, PsExec, WinRM.\n- Command and Control: HTTPS beaconing, DNS tunneling.\n- Exfiltration: cloud storage, HTTPS upload, email.\n- Impact: ransomware, data destruction.\n\nScenarii de explicat:\n- Phishing -> credential theft -> M365 login -> inbox rule -> BEC.\n- Malware -> PowerShell download -> persistence -> C2 beaconing.\n- Ransomware -> privilege escalation -> lateral movement -> shadow copies deleted -> encryption.\n\nFraze bune:\n\"Nu ma bazez doar pe IOC-uri; caut TTP-uri si comportamente care raman valabile cand infrastructura atacatorului se schimba.\"\n",
      "key_points": [
        "TTP-urile sunt mai stabile decat IP-urile si hashurile.",
        "Lantul de atac ajuta la investigatie si la raportare.",
        "MITRE mapping face detectiile si rapoartele mai clare."
      ]
    },
    {
      "title": "12. Intrebari comportamentale si raspunsuri STAR",
      "minutes": 20,
      "content": "\nInterviul poate testa si potrivirea pentru ture, remote work si lucru sub presiune.\n\nStructura STAR:\n- Situation: contextul.\n- Task: ce trebuia rezolvat.\n- Action: ce ai facut concret.\n- Result: rezultat masurabil sau lectie invatata.\n\nIntrebari posibile:\n- De ce SOC Analyst?\n- Cum reactionezi cand ai 20 de alerte simultan?\n- Ce faci daca nu stii o tehnologie?\n- Cum comunici o suspiciune fara dovezi complete?\n- Esti confortabil cu ture vineri-sambata?\n\nRaspuns pentru disponibilitate:\n\"Da, inteleg ca programul este exclusiv in intervalul vineri 15:00 - sambata 23:00, in rotatie. Pentru mine este potrivit deoarece pot planifica din timp si pot mentine atentie ridicata pe durata turei.\"\n\nRaspuns cand nu stii:\n\"As spune transparent ca nu am confirmarea inca, apoi as verifica documentatia, logurile relevante si as cere validare de la colegii IR/Threat Hunting daca impactul este ridicat.\"\n",
      "key_points": [
        "Arata metoda, nu pretinde ca stii tot.",
        "Pentru presiune: prioritizezi dupa severitate si impact.",
        "Confirma clar disponibilitatea pentru programul de weekend."
      ]
    }
  ],
  "quizBank": [
    {
      "q": "Ce inseamna True Positive intr-un SOC?",
      "a": [
        "Alerta confirma activitate reala",
        "Alerta este zgomot",
        "Regula lipseste",
        "Sistemul e offline"
      ],
      "c": 0,
      "e": "True Positive inseamna alerta valida, chiar daca poate fi benign true positive."
    },
    {
      "q": "Windows Event ID 4625 indica:",
      "a": [
        "Logon esuat",
        "Logon reusit",
        "Proces creat",
        "Audit log sters"
      ],
      "c": 0,
      "e": "4625 = failed logon."
    },
    {
      "q": "Windows Event ID 1102 este important deoarece indica:",
      "a": [
        "Audit log cleared",
        "User creat",
        "Kerberos TGS",
        "DNS query"
      ],
      "c": 0,
      "e": "Stergerea logurilor este tehnica de defense evasion."
    },
    {
      "q": "Ce Logon Type indica de obicei RDP?",
      "a": [
        "10",
        "3",
        "2",
        "7"
      ],
      "c": 0,
      "e": "Logon Type 10 este RemoteInteractive/RDP."
    },
    {
      "q": "Care Sysmon ID indica process creation?",
      "a": [
        "1",
        "3",
        "11",
        "22"
      ],
      "c": 0,
      "e": "Sysmon Event ID 1 = Process Create."
    },
    {
      "q": "Care comanda PowerShell este suspecta?",
      "a": [
        "powershell -enc ...",
        "Get-Date",
        "Get-Help",
        "Write-Host test"
      ],
      "c": 0,
      "e": "-enc/-encodedcommand ascunde comenzi codate Base64."
    },
    {
      "q": "Pe Linux, unde verifici SSH failed logins?",
      "a": [
        "/var/log/auth.log sau /var/log/secure",
        "/etc/passwd",
        "/tmp",
        "/boot"
      ],
      "c": 0,
      "e": "Autentificarile SSH sunt in auth.log/secure, in functie de distributie."
    },
    {
      "q": "Ce locatie Linux pentru executie este frecvent suspecta?",
      "a": [
        "/tmp",
        "/usr/bin",
        "/etc",
        "/opt/app semnat"
      ],
      "c": 0,
      "e": "Malware ruleaza des din directoare temporare."
    },
    {
      "q": "Portul 445 este asociat cu:",
      "a": [
        "SMB",
        "SSH",
        "DNS",
        "RDP"
      ],
      "c": 0,
      "e": "445/TCP este SMB."
    },
    {
      "q": "Beaconing inseamna:",
      "a": [
        "Conexiuni periodice catre acelasi C2",
        "Logon local",
        "Patch update",
        "DNS normal"
      ],
      "c": 0,
      "e": "Beaconing este pattern periodic de comunicare C2."
    },
    {
      "q": "In M365, o regula inbox care forwardeaza extern poate indica:",
      "a": [
        "BEC/cont compromis",
        "Patch Windows",
        "Scan intern",
        "Backup local"
      ],
      "c": 0,
      "e": "Forwarding extern este indicator clasic de BEC."
    },
    {
      "q": "Legacy authentication este riscanta deoarece:",
      "a": [
        "Poate ocoli MFA",
        "Cripteaza fisiere",
        "Blocheaza DNS",
        "Sterge audit logs"
      ],
      "c": 0,
      "e": "Protocoalele legacy nu suporta mereu MFA modern."
    },
    {
      "q": "In AWS, CloudTrail raspunde la intrebarea:",
      "a": [
        "Cine a facut ce, cand si de unde",
        "Ce proces ruleaza local",
        "Ce email e spam",
        "Ce fisier are hash"
      ],
      "c": 0,
      "e": "CloudTrail logheaza API calls."
    },
    {
      "q": "Ce eveniment AWS este high severity?",
      "a": [
        "StopLogging/DeleteTrail",
        "DescribeInstances",
        "ListBuckets autorizat",
        "GetCallerIdentity"
      ],
      "c": 0,
      "e": "Oprirea loggingului indica defense evasion."
    },
    {
      "q": "In Wazuh, decoderul are rolul de a:",
      "a": [
        "Extrage campuri din log",
        "Izola hostul",
        "Sterge alerta",
        "Reseta parola"
      ],
      "c": 0,
      "e": "Decoderul parseaza logul brut."
    },
    {
      "q": "O regula de detectie buna trebuie sa aiba:",
      "a": [
        "Scop, severitate, testare si false positive control",
        "Doar nivel maxim",
        "Fara documentatie",
        "Doar IOC-uri vechi"
      ],
      "c": 0,
      "e": "Detection engineering include testare si tuning."
    },
    {
      "q": "MITRE T1059 se refera la:",
      "a": [
        "Command and Scripting Interpreter",
        "Phishing",
        "Data encrypted",
        "Valid accounts"
      ],
      "c": 0,
      "e": "T1059 include PowerShell, shell, scripts."
    },
    {
      "q": "Ce este un LOLBin?",
      "a": [
        "Utilitar legitim abuzat de atacatori",
        "Un firewall",
        "Un cont admin",
        "Un format de log"
      ],
      "c": 0,
      "e": "Exemple: certutil, mshta, rundll32."
    },
    {
      "q": "Accesarea LSASS de catre un proces suspect poate indica:",
      "a": [
        "Credential dumping",
        "DNS tunneling",
        "Port scan",
        "Inbox rule"
      ],
      "c": 0,
      "e": "LSASS contine materiale de autentificare."
    },
    {
      "q": "Primul pas intr-un incident confirmat este de obicei:",
      "a": [
        "Containment cu pastrarea dovezilor",
        "Stergerea tuturor logurilor",
        "Ignorarea alertei",
        "Publicarea pe social media"
      ],
      "c": 0,
      "e": "Containment limiteaza impactul, dar dovezile trebuie pastrate."
    },
    {
      "q": "Un raport de incident bun contine:",
      "a": [
        "Summary, timeline, scope, evidence, actions, recommendations",
        "Doar screenshot",
        "Doar opinie",
        "Doar severitate"
      ],
      "c": 0,
      "e": "Raportul trebuie sa fie actionabil."
    },
    {
      "q": "OSINT corect trebuie sa includa:",
      "a": [
        "Sursa, timestamp si confidence",
        "Doar link vag",
        "Date cumparate ilegal",
        "Fara verificare"
      ],
      "c": 0,
      "e": "Threat intel trebuie evaluat si documentat."
    },
    {
      "q": "Un IOC singur inseamna automat incident?",
      "a": [
        "Nu, trebuie corelat cu loguri interne",
        "Da, intotdeauna",
        "Doar daca e IP",
        "Doar daca e hash"
      ],
      "c": 0,
      "e": "IOC-urile au nevoie de context."
    },
    {
      "q": "Ce tactica MITRE include RDP/SMB/PsExec?",
      "a": [
        "Lateral Movement",
        "Impact",
        "Collection",
        "Reconnaissance"
      ],
      "c": 0,
      "e": "Acestea sunt tehnici de miscare laterala."
    },
    {
      "q": "Ce faci daca ai 20 de alerte simultan?",
      "a": [
        "Prioritizez dupa severitate, asset critic si impact",
        "Le inchid pe toate",
        "Aleg la intamplare",
        "Astept finalul turei"
      ],
      "c": 0,
      "e": "Triage inseamna prioritizare structurata."
    },
    {
      "q": "Ce campuri sunt esentiale intr-un firewall log?",
      "a": [
        "src/dst IP, port, protocol, action, rule, bytes",
        "Doar hostname",
        "Doar user agent",
        "Doar screenshot"
      ],
      "c": 0,
      "e": "Firewall logs necesita context de trafic."
    },
    {
      "q": "MFA fatigue inseamna:",
      "a": [
        "Multe push-uri MFA pana userul accepta",
        "Reset DNS",
        "Scan porturi",
        "Download fisier"
      ],
      "c": 0,
      "e": "Atacatorul preseaza userul sa accepte MFA."
    },
    {
      "q": "OAuth consent malitios este periculos pentru ca:",
      "a": [
        "Poate persista dupa reset parola",
        "Dezactiveaza BIOS",
        "Blocheaza SMB",
        "Formateaza disk"
      ],
      "c": 0,
      "e": "Tokenurile/aplicatiile autorizate trebuie revocate."
    },
    {
      "q": "Ce faci la suspiciune de cheie AWS compromisa?",
      "a": [
        "Dezactivez cheia si verific CloudTrail",
        "Sterg toate conturile",
        "Ignor daca nu e root",
        "O trimit pe email"
      ],
      "c": 0,
      "e": "Access key id permite pivot in CloudTrail."
    },
    {
      "q": "Ce inseamna false positive?",
      "a": [
        "Alerta fara risc real",
        "Incident nedetectat",
        "Atac confirmat",
        "User blocat"
      ],
      "c": 0,
      "e": "False positive este alerta nevalida."
    },
    {
      "q": "Ce indica Windows Event ID 4624?",
      "a": [
        "logon reusit",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Verifica Logon Type, sursa, user si asset."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4624?",
      "a": [
        "Verifica Logon Type, sursa, user si asset.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Verifica Logon Type, sursa, user si asset."
    },
    {
      "q": "Ce indica Windows Event ID 4625?",
      "a": [
        "logon esuat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Multe 4625 pot indica brute force sau password spraying."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4625?",
      "a": [
        "Multe 4625 pot indica brute force sau password spraying.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Multe 4625 pot indica brute force sau password spraying."
    },
    {
      "q": "Ce indica Windows Event ID 4634?",
      "a": [
        "logoff",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Ajuta la timeline pentru sesiuni Windows."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4634?",
      "a": [
        "Ajuta la timeline pentru sesiuni Windows.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Ajuta la timeline pentru sesiuni Windows."
    },
    {
      "q": "Ce indica Windows Event ID 4648?",
      "a": [
        "logon cu credentiale explicite",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Poate indica runas, lateral movement sau tool administrativ."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4648?",
      "a": [
        "Poate indica runas, lateral movement sau tool administrativ.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Poate indica runas, lateral movement sau tool administrativ."
    },
    {
      "q": "Ce indica Windows Event ID 4672?",
      "a": [
        "privilegii speciale atribuite",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Apare cand un cont privilegiat se autentifica."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4672?",
      "a": [
        "Apare cand un cont privilegiat se autentifica.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Apare cand un cont privilegiat se autentifica."
    },
    {
      "q": "Ce indica Windows Event ID 4688?",
      "a": [
        "proces creat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Este critic daca include command line."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4688?",
      "a": [
        "Este critic daca include command line.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Este critic daca include command line."
    },
    {
      "q": "Ce indica Windows Event ID 4697?",
      "a": [
        "serviciu instalat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Instalarea de servicii poate indica persistenta."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4697?",
      "a": [
        "Instalarea de servicii poate indica persistenta.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Instalarea de servicii poate indica persistenta."
    },
    {
      "q": "Ce indica Windows Event ID 4720?",
      "a": [
        "user creat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "User creat neasteptat poate indica persistenta."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4720?",
      "a": [
        "User creat neasteptat poate indica persistenta.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "User creat neasteptat poate indica persistenta."
    },
    {
      "q": "Ce indica Windows Event ID 4722?",
      "a": [
        "user activat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Conturile reactivate trebuie verificate."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4722?",
      "a": [
        "Conturile reactivate trebuie verificate.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Conturile reactivate trebuie verificate."
    },
    {
      "q": "Ce indica Windows Event ID 4723?",
      "a": [
        "incercare schimbare parola",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Poate indica activitate de cont sau atac."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4723?",
      "a": [
        "Poate indica activitate de cont sau atac.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Poate indica activitate de cont sau atac."
    },
    {
      "q": "Ce indica Windows Event ID 4724?",
      "a": [
        "resetare parola",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Resetarile neasteptate pot indica abuz de privilegii."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4724?",
      "a": [
        "Resetarile neasteptate pot indica abuz de privilegii.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Resetarile neasteptate pot indica abuz de privilegii."
    },
    {
      "q": "Ce indica Windows Event ID 4726?",
      "a": [
        "user sters",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Stergerea conturilor poate fi malitioasa sau administrativa."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4726?",
      "a": [
        "Stergerea conturilor poate fi malitioasa sau administrativa.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Stergerea conturilor poate fi malitioasa sau administrativa."
    },
    {
      "q": "Ce indica Windows Event ID 4728?",
      "a": [
        "membru adaugat in grup global privilegiat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Important pentru privilege escalation."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4728?",
      "a": [
        "Important pentru privilege escalation.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Important pentru privilege escalation."
    },
    {
      "q": "Ce indica Windows Event ID 4732?",
      "a": [
        "membru adaugat in grup local",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Administrators local este critic."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4732?",
      "a": [
        "Administrators local este critic.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Administrators local este critic."
    },
    {
      "q": "Ce indica Windows Event ID 4738?",
      "a": [
        "user modificat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Verifica schimbari pe conturi sensibile."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4738?",
      "a": [
        "Verifica schimbari pe conturi sensibile.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Verifica schimbari pe conturi sensibile."
    },
    {
      "q": "Ce indica Windows Event ID 4740?",
      "a": [
        "account lockout",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Poate urma unui brute force."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4740?",
      "a": [
        "Poate urma unui brute force.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Poate urma unui brute force."
    },
    {
      "q": "Ce indica Windows Event ID 4768?",
      "a": [
        "Kerberos TGT solicitat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Util pentru autentificare Kerberos."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4768?",
      "a": [
        "Util pentru autentificare Kerberos.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Util pentru autentificare Kerberos."
    },
    {
      "q": "Ce indica Windows Event ID 4769?",
      "a": [
        "Kerberos service ticket solicitat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Relevant pentru Kerberoasting si access tracking."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4769?",
      "a": [
        "Relevant pentru Kerberoasting si access tracking.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Relevant pentru Kerberoasting si access tracking."
    },
    {
      "q": "Ce indica Windows Event ID 4771?",
      "a": [
        "Kerberos pre-auth failed",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Poate indica parola gresita sau atac."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4771?",
      "a": [
        "Poate indica parola gresita sau atac.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Poate indica parola gresita sau atac."
    },
    {
      "q": "Ce indica Windows Event ID 4776?",
      "a": [
        "NTLM authentication",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Important pentru autentificari legacy."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 4776?",
      "a": [
        "Important pentru autentificari legacy.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Important pentru autentificari legacy."
    },
    {
      "q": "Ce indica Windows Event ID 7045?",
      "a": [
        "serviciu instalat",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Foarte relevant pentru persistenta Windows."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 7045?",
      "a": [
        "Foarte relevant pentru persistenta Windows.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Foarte relevant pentru persistenta Windows."
    },
    {
      "q": "Ce indica Windows Event ID 1102?",
      "a": [
        "audit log cleared",
        "DNS query",
        "scan de port",
        "modificare firewall Linux"
      ],
      "c": 0,
      "e": "Stergerea jurnalului este high severity."
    },
    {
      "q": "Intr-o alerta Windows, de ce este relevant Event ID 1102?",
      "a": [
        "Stergerea jurnalului este high severity.",
        "Este doar un eveniment de retea fara context",
        "Indica automat ransomware",
        "Nu se foloseste in SOC"
      ],
      "c": 0,
      "e": "Stergerea jurnalului este high severity."
    },
    {
      "q": "Ce inseamna Windows Logon Type 2?",
      "a": [
        "interactive local",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 2 indica logon local la consola."
    },
    {
      "q": "Ce inseamna Windows Logon Type 3?",
      "a": [
        "network",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 3 apare des pentru SMB/acces retea."
    },
    {
      "q": "Ce inseamna Windows Logon Type 4?",
      "a": [
        "batch",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 4 este asociat joburilor batch."
    },
    {
      "q": "Ce inseamna Windows Logon Type 5?",
      "a": [
        "service",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 5 apare cand porneste un serviciu."
    },
    {
      "q": "Ce inseamna Windows Logon Type 7?",
      "a": [
        "unlock",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 7 inseamna deblocare sesiune."
    },
    {
      "q": "Ce inseamna Windows Logon Type 8?",
      "a": [
        "network cleartext",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 8 poate implica credentiale transmise catre serviciu."
    },
    {
      "q": "Ce inseamna Windows Logon Type 10?",
      "a": [
        "remote interactive/RDP",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 10 este RDP/RemoteInteractive."
    },
    {
      "q": "Ce inseamna Windows Logon Type 11?",
      "a": [
        "cached interactive",
        "DNS tunneling",
        "proces creat",
        "audit log cleared"
      ],
      "c": 0,
      "e": "Logon Type 11 foloseste credentiale cached."
    },
    {
      "q": "Ce indica Sysmon Event ID 1?",
      "a": [
        "Process Create",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Arata procesul, parent process si command line."
    },
    {
      "q": "De ce este util Sysmon 1 in investigatii?",
      "a": [
        "Arata procesul, parent process si command line.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Arata procesul, parent process si command line."
    },
    {
      "q": "Ce indica Sysmon Event ID 3?",
      "a": [
        "Network Connection",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Coreleaza procesul cu conexiunea outbound/inbound."
    },
    {
      "q": "De ce este util Sysmon 3 in investigatii?",
      "a": [
        "Coreleaza procesul cu conexiunea outbound/inbound.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Coreleaza procesul cu conexiunea outbound/inbound."
    },
    {
      "q": "Ce indica Sysmon Event ID 7?",
      "a": [
        "Image Loaded",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Ajuta la detectii de DLL/load suspect."
    },
    {
      "q": "De ce este util Sysmon 7 in investigatii?",
      "a": [
        "Ajuta la detectii de DLL/load suspect.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Ajuta la detectii de DLL/load suspect."
    },
    {
      "q": "Ce indica Sysmon Event ID 10?",
      "a": [
        "Process Access",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Relevant pentru LSASS access si credential dumping."
    },
    {
      "q": "De ce este util Sysmon 10 in investigatii?",
      "a": [
        "Relevant pentru LSASS access si credential dumping.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Relevant pentru LSASS access si credential dumping."
    },
    {
      "q": "Ce indica Sysmon Event ID 11?",
      "a": [
        "File Create",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Ajuta la urmarirea fisierelor create de procese."
    },
    {
      "q": "De ce este util Sysmon 11 in investigatii?",
      "a": [
        "Ajuta la urmarirea fisierelor create de procese.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Ajuta la urmarirea fisierelor create de procese."
    },
    {
      "q": "Ce indica Sysmon Event ID 12?",
      "a": [
        "Registry Object Created/Deleted",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Relevant pentru persistenta in registry."
    },
    {
      "q": "De ce este util Sysmon 12 in investigatii?",
      "a": [
        "Relevant pentru persistenta in registry.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Relevant pentru persistenta in registry."
    },
    {
      "q": "Ce indica Sysmon Event ID 13?",
      "a": [
        "Registry Value Set",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Detecteaza modificari de chei Run/RunOnce."
    },
    {
      "q": "De ce este util Sysmon 13 in investigatii?",
      "a": [
        "Detecteaza modificari de chei Run/RunOnce.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Detecteaza modificari de chei Run/RunOnce."
    },
    {
      "q": "Ce indica Sysmon Event ID 14?",
      "a": [
        "Registry Object Renamed",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Poate indica modificari suspecte de registry."
    },
    {
      "q": "De ce este util Sysmon 14 in investigatii?",
      "a": [
        "Poate indica modificari suspecte de registry.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Poate indica modificari suspecte de registry."
    },
    {
      "q": "Ce indica Sysmon Event ID 15?",
      "a": [
        "FileCreateStreamHash",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Poate arata alternate data streams."
    },
    {
      "q": "De ce este util Sysmon 15 in investigatii?",
      "a": [
        "Poate arata alternate data streams.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Poate arata alternate data streams."
    },
    {
      "q": "Ce indica Sysmon Event ID 22?",
      "a": [
        "DNS Query",
        "MFA push",
        "S3 bucket policy",
        "Inbox rule"
      ],
      "c": 0,
      "e": "Coreleaza procesul cu domeniul interogat."
    },
    {
      "q": "De ce este util Sysmon 22 in investigatii?",
      "a": [
        "Coreleaza procesul cu domeniul interogat.",
        "Inlocuieste complet EDR",
        "Confirma automat exfiltrarea",
        "Este irelevant pentru endpoint"
      ],
      "c": 0,
      "e": "Coreleaza procesul cu domeniul interogat."
    },
    {
      "q": "Cu ce serviciu este asociat portul 20/21?",
      "a": [
        "FTP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Transfer fisiere; poate fi folosit pentru exfiltrare."
    },
    {
      "q": "De ce ar conta portul 20/21 intr-o alerta SOC?",
      "a": [
        "Transfer fisiere; poate fi folosit pentru exfiltrare.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Transfer fisiere; poate fi folosit pentru exfiltrare."
    },
    {
      "q": "Cu ce serviciu este asociat portul 22?",
      "a": [
        "SSH",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Administrare Linux si tinta comuna de brute force."
    },
    {
      "q": "De ce ar conta portul 22 intr-o alerta SOC?",
      "a": [
        "Administrare Linux si tinta comuna de brute force.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Administrare Linux si tinta comuna de brute force."
    },
    {
      "q": "Cu ce serviciu este asociat portul 23?",
      "a": [
        "Telnet",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Protocol necriptat, risc major."
    },
    {
      "q": "De ce ar conta portul 23 intr-o alerta SOC?",
      "a": [
        "Protocol necriptat, risc major.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Protocol necriptat, risc major."
    },
    {
      "q": "Cu ce serviciu este asociat portul 25?",
      "a": [
        "SMTP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Trimitere email; relevant pentru spam/phishing."
    },
    {
      "q": "De ce ar conta portul 25 intr-o alerta SOC?",
      "a": [
        "Trimitere email; relevant pentru spam/phishing.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Trimitere email; relevant pentru spam/phishing."
    },
    {
      "q": "Cu ce serviciu este asociat portul 53?",
      "a": [
        "DNS",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Rezolvare nume; relevant pentru C2 si tunneling."
    },
    {
      "q": "De ce ar conta portul 53 intr-o alerta SOC?",
      "a": [
        "Rezolvare nume; relevant pentru C2 si tunneling.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Rezolvare nume; relevant pentru C2 si tunneling."
    },
    {
      "q": "Cu ce serviciu este asociat portul 80?",
      "a": [
        "HTTP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Trafic web necriptat."
    },
    {
      "q": "De ce ar conta portul 80 intr-o alerta SOC?",
      "a": [
        "Trafic web necriptat.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Trafic web necriptat."
    },
    {
      "q": "Cu ce serviciu este asociat portul 88?",
      "a": [
        "Kerberos",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Autentificare Windows domain."
    },
    {
      "q": "De ce ar conta portul 88 intr-o alerta SOC?",
      "a": [
        "Autentificare Windows domain.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Autentificare Windows domain."
    },
    {
      "q": "Cu ce serviciu este asociat portul 110?",
      "a": [
        "POP3",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Email legacy."
    },
    {
      "q": "De ce ar conta portul 110 intr-o alerta SOC?",
      "a": [
        "Email legacy.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Email legacy."
    },
    {
      "q": "Cu ce serviciu este asociat portul 123?",
      "a": [
        "NTP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Timp; poate fi abuzat in amplificare DDoS."
    },
    {
      "q": "De ce ar conta portul 123 intr-o alerta SOC?",
      "a": [
        "Timp; poate fi abuzat in amplificare DDoS.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Timp; poate fi abuzat in amplificare DDoS."
    },
    {
      "q": "Cu ce serviciu este asociat portul 135?",
      "a": [
        "RPC",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Windows RPC, relevant lateral movement."
    },
    {
      "q": "De ce ar conta portul 135 intr-o alerta SOC?",
      "a": [
        "Windows RPC, relevant lateral movement.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Windows RPC, relevant lateral movement."
    },
    {
      "q": "Cu ce serviciu este asociat portul 139?",
      "a": [
        "NetBIOS",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Windows file sharing legacy."
    },
    {
      "q": "De ce ar conta portul 139 intr-o alerta SOC?",
      "a": [
        "Windows file sharing legacy.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Windows file sharing legacy."
    },
    {
      "q": "Cu ce serviciu este asociat portul 143?",
      "a": [
        "IMAP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Email access."
    },
    {
      "q": "De ce ar conta portul 143 intr-o alerta SOC?",
      "a": [
        "Email access.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Email access."
    },
    {
      "q": "Cu ce serviciu este asociat portul 389?",
      "a": [
        "LDAP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Directory services."
    },
    {
      "q": "De ce ar conta portul 389 intr-o alerta SOC?",
      "a": [
        "Directory services.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Directory services."
    },
    {
      "q": "Cu ce serviciu este asociat portul 443?",
      "a": [
        "HTTPS",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Trafic web criptat, C2 frecvent pe HTTPS."
    },
    {
      "q": "De ce ar conta portul 443 intr-o alerta SOC?",
      "a": [
        "Trafic web criptat, C2 frecvent pe HTTPS.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Trafic web criptat, C2 frecvent pe HTTPS."
    },
    {
      "q": "Cu ce serviciu este asociat portul 445?",
      "a": [
        "SMB",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "File sharing si lateral movement Windows."
    },
    {
      "q": "De ce ar conta portul 445 intr-o alerta SOC?",
      "a": [
        "File sharing si lateral movement Windows.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "File sharing si lateral movement Windows."
    },
    {
      "q": "Cu ce serviciu este asociat portul 465?",
      "a": [
        "SMTPS",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "SMTP peste TLS."
    },
    {
      "q": "De ce ar conta portul 465 intr-o alerta SOC?",
      "a": [
        "SMTP peste TLS.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "SMTP peste TLS."
    },
    {
      "q": "Cu ce serviciu este asociat portul 587?",
      "a": [
        "SMTP submission",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Trimitere email autentificata."
    },
    {
      "q": "De ce ar conta portul 587 intr-o alerta SOC?",
      "a": [
        "Trimitere email autentificata.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Trimitere email autentificata."
    },
    {
      "q": "Cu ce serviciu este asociat portul 993?",
      "a": [
        "IMAPS",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "IMAP peste TLS."
    },
    {
      "q": "De ce ar conta portul 993 intr-o alerta SOC?",
      "a": [
        "IMAP peste TLS.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "IMAP peste TLS."
    },
    {
      "q": "Cu ce serviciu este asociat portul 995?",
      "a": [
        "POP3S",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "POP3 peste TLS."
    },
    {
      "q": "De ce ar conta portul 995 intr-o alerta SOC?",
      "a": [
        "POP3 peste TLS.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "POP3 peste TLS."
    },
    {
      "q": "Cu ce serviciu este asociat portul 1433?",
      "a": [
        "MSSQL",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Baza de date Microsoft SQL Server."
    },
    {
      "q": "De ce ar conta portul 1433 intr-o alerta SOC?",
      "a": [
        "Baza de date Microsoft SQL Server.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Baza de date Microsoft SQL Server."
    },
    {
      "q": "Cu ce serviciu este asociat portul 1521?",
      "a": [
        "Oracle DB",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Baza de date Oracle."
    },
    {
      "q": "De ce ar conta portul 1521 intr-o alerta SOC?",
      "a": [
        "Baza de date Oracle.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Baza de date Oracle."
    },
    {
      "q": "Cu ce serviciu este asociat portul 3306?",
      "a": [
        "MySQL",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Baza de date MySQL/MariaDB."
    },
    {
      "q": "De ce ar conta portul 3306 intr-o alerta SOC?",
      "a": [
        "Baza de date MySQL/MariaDB.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Baza de date MySQL/MariaDB."
    },
    {
      "q": "Cu ce serviciu este asociat portul 3389?",
      "a": [
        "RDP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Remote desktop Windows, tinta de brute force."
    },
    {
      "q": "De ce ar conta portul 3389 intr-o alerta SOC?",
      "a": [
        "Remote desktop Windows, tinta de brute force.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Remote desktop Windows, tinta de brute force."
    },
    {
      "q": "Cu ce serviciu este asociat portul 5432?",
      "a": [
        "PostgreSQL",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Baza de date PostgreSQL."
    },
    {
      "q": "De ce ar conta portul 5432 intr-o alerta SOC?",
      "a": [
        "Baza de date PostgreSQL.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Baza de date PostgreSQL."
    },
    {
      "q": "Cu ce serviciu este asociat portul 5985?",
      "a": [
        "WinRM HTTP",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Administrare Windows remote."
    },
    {
      "q": "De ce ar conta portul 5985 intr-o alerta SOC?",
      "a": [
        "Administrare Windows remote.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Administrare Windows remote."
    },
    {
      "q": "Cu ce serviciu este asociat portul 5986?",
      "a": [
        "WinRM HTTPS",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Administrare Windows remote peste TLS."
    },
    {
      "q": "De ce ar conta portul 5986 intr-o alerta SOC?",
      "a": [
        "Administrare Windows remote peste TLS.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Administrare Windows remote peste TLS."
    },
    {
      "q": "Cu ce serviciu este asociat portul 6379?",
      "a": [
        "Redis",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Data store, risc daca este expus public."
    },
    {
      "q": "De ce ar conta portul 6379 intr-o alerta SOC?",
      "a": [
        "Data store, risc daca este expus public.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Data store, risc daca este expus public."
    },
    {
      "q": "Cu ce serviciu este asociat portul 8080?",
      "a": [
        "HTTP alternate/proxy",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Port web alternativ."
    },
    {
      "q": "De ce ar conta portul 8080 intr-o alerta SOC?",
      "a": [
        "Port web alternativ.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Port web alternativ."
    },
    {
      "q": "Cu ce serviciu este asociat portul 8443?",
      "a": [
        "HTTPS alternate",
        "Kerberoasting",
        "Sysmon Process Create",
        "CloudTrail"
      ],
      "c": 0,
      "e": "Port TLS alternativ."
    },
    {
      "q": "De ce ar conta portul 8443 intr-o alerta SOC?",
      "a": [
        "Port TLS alternativ.",
        "Este mereu benign",
        "Este folosit doar local",
        "Nu apare in firewall logs"
      ],
      "c": 0,
      "e": "Port TLS alternativ."
    },
    {
      "q": "Pe Linux, ce verifici pentru /var/log/auth.log?",
      "a": [
        "autentificari si sudo pe Debian/Ubuntu",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Aici cauti SSH failed/success si sudo."
    },
    {
      "q": "De ce este relevant /var/log/auth.log intr-o investigatie Linux?",
      "a": [
        "Aici cauti SSH failed/success si sudo.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Aici cauti SSH failed/success si sudo."
    },
    {
      "q": "Pe Linux, ce verifici pentru /var/log/secure?",
      "a": [
        "autentificari pe RHEL/CentOS",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Echivalent frecvent pentru auth events."
    },
    {
      "q": "De ce este relevant /var/log/secure intr-o investigatie Linux?",
      "a": [
        "Echivalent frecvent pentru auth events.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Echivalent frecvent pentru auth events."
    },
    {
      "q": "Pe Linux, ce verifici pentru journalctl?",
      "a": [
        "interogare loguri systemd",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Util pentru servicii si timeline."
    },
    {
      "q": "De ce este relevant journalctl intr-o investigatie Linux?",
      "a": [
        "Util pentru servicii si timeline.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Util pentru servicii si timeline."
    },
    {
      "q": "Pe Linux, ce verifici pentru last?",
      "a": [
        "ultimele loginuri reusite",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Ajuta la validarea accesului interactiv."
    },
    {
      "q": "De ce este relevant last intr-o investigatie Linux?",
      "a": [
        "Ajuta la validarea accesului interactiv.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Ajuta la validarea accesului interactiv."
    },
    {
      "q": "Pe Linux, ce verifici pentru lastb?",
      "a": [
        "loginuri esuate",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Util pentru brute force pe Linux."
    },
    {
      "q": "De ce este relevant lastb intr-o investigatie Linux?",
      "a": [
        "Util pentru brute force pe Linux.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Util pentru brute force pe Linux."
    },
    {
      "q": "Pe Linux, ce verifici pentru ss -tulpn?",
      "a": [
        "socketuri si procese ascultand/conectate",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Ajuta la analiza conexiunilor."
    },
    {
      "q": "De ce este relevant ss -tulpn intr-o investigatie Linux?",
      "a": [
        "Ajuta la analiza conexiunilor.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Ajuta la analiza conexiunilor."
    },
    {
      "q": "Pe Linux, ce verifici pentru lsof -i?",
      "a": [
        "fisiere/socketuri de retea deschise",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Leaga procesul de conexiune."
    },
    {
      "q": "De ce este relevant lsof -i intr-o investigatie Linux?",
      "a": [
        "Leaga procesul de conexiune.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Leaga procesul de conexiune."
    },
    {
      "q": "Pe Linux, ce verifici pentru crontab -l?",
      "a": [
        "joburi cron user",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Persistenta frecventa pe Linux."
    },
    {
      "q": "De ce este relevant crontab -l intr-o investigatie Linux?",
      "a": [
        "Persistenta frecventa pe Linux.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Persistenta frecventa pe Linux."
    },
    {
      "q": "Pe Linux, ce verifici pentru systemctl list-timers?",
      "a": [
        "timere systemd",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Persistenta/automatizari systemd."
    },
    {
      "q": "De ce este relevant systemctl list-timers intr-o investigatie Linux?",
      "a": [
        "Persistenta/automatizari systemd.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Persistenta/automatizari systemd."
    },
    {
      "q": "Pe Linux, ce verifici pentru authorized_keys?",
      "a": [
        "chei SSH autorizate",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Cheile adaugate pot permite persistenta."
    },
    {
      "q": "De ce este relevant authorized_keys intr-o investigatie Linux?",
      "a": [
        "Cheile adaugate pot permite persistenta.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Cheile adaugate pot permite persistenta."
    },
    {
      "q": "Pe Linux, ce verifici pentru /tmp?",
      "a": [
        "director temporar frecvent abuzat",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Executia din /tmp este suspecta."
    },
    {
      "q": "De ce este relevant /tmp intr-o investigatie Linux?",
      "a": [
        "Executia din /tmp este suspecta.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Executia din /tmp este suspecta."
    },
    {
      "q": "Pe Linux, ce verifici pentru /dev/shm?",
      "a": [
        "memorie partajata folosita pentru executie stealth",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Malware foloseste des /dev/shm."
    },
    {
      "q": "De ce este relevant /dev/shm intr-o investigatie Linux?",
      "a": [
        "Malware foloseste des /dev/shm.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Malware foloseste des /dev/shm."
    },
    {
      "q": "Pe Linux, ce verifici pentru sudoers?",
      "a": [
        "configuratie privilegii sudo",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Modificarile pot indica privilege escalation."
    },
    {
      "q": "De ce este relevant sudoers intr-o investigatie Linux?",
      "a": [
        "Modificarile pot indica privilege escalation.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Modificarile pot indica privilege escalation."
    },
    {
      "q": "Pe Linux, ce verifici pentru auditd?",
      "a": [
        "audit avansat Linux",
        "MFA push in Entra ID",
        "CloudTrail API calls",
        "Inbox forwarding"
      ],
      "c": 0,
      "e": "Poate loga execve, file changes, privilege events."
    },
    {
      "q": "De ce este relevant auditd intr-o investigatie Linux?",
      "a": [
        "Poate loga execve, file changes, privilege events.",
        "Este doar pentru design grafic",
        "Nu poate contine dovezi",
        "Este folosit doar in AWS"
      ],
      "c": 0,
      "e": "Poate loga execve, file changes, privilege events."
    },
    {
      "q": "In Microsoft 365, ce inseamna Unified Audit Log?",
      "a": [
        "activitati user/admin in Microsoft 365",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Sursa centrala pentru activitati M365."
    },
    {
      "q": "De ce investighezi Unified Audit Log intr-un caz M365?",
      "a": [
        "Sursa centrala pentru activitati M365.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Sursa centrala pentru activitati M365."
    },
    {
      "q": "In Microsoft 365, ce inseamna Entra ID Sign-in logs?",
      "a": [
        "autentificari si conditional access",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Verifica IP, locatie, MFA, status."
    },
    {
      "q": "De ce investighezi Entra ID Sign-in logs intr-un caz M365?",
      "a": [
        "Verifica IP, locatie, MFA, status.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Verifica IP, locatie, MFA, status."
    },
    {
      "q": "In Microsoft 365, ce inseamna Impossible travel?",
      "a": [
        "loginuri imposibile geografic",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Poate indica cont compromis."
    },
    {
      "q": "De ce investighezi Impossible travel intr-un caz M365?",
      "a": [
        "Poate indica cont compromis.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Poate indica cont compromis."
    },
    {
      "q": "In Microsoft 365, ce inseamna MFA fatigue?",
      "a": [
        "push-uri MFA repetate pana la accept",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Atacatorul preseaza userul."
    },
    {
      "q": "De ce investighezi MFA fatigue intr-un caz M365?",
      "a": [
        "Atacatorul preseaza userul.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Atacatorul preseaza userul."
    },
    {
      "q": "In Microsoft 365, ce inseamna Legacy authentication?",
      "a": [
        "autentificare veche fara MFA modern",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Trebuie blocata unde se poate."
    },
    {
      "q": "De ce investighezi Legacy authentication intr-un caz M365?",
      "a": [
        "Trebuie blocata unde se poate.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Trebuie blocata unde se poate."
    },
    {
      "q": "In Microsoft 365, ce inseamna Inbox forwarding?",
      "a": [
        "redirectionare externa de email",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Indicator clasic de BEC."
    },
    {
      "q": "De ce investighezi Inbox forwarding intr-un caz M365?",
      "a": [
        "Indicator clasic de BEC.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Indicator clasic de BEC."
    },
    {
      "q": "In Microsoft 365, ce inseamna Inbox rule?",
      "a": [
        "regula de mutare/stergere/forward",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Atacatorii ascund emailuri si raspunsuri."
    },
    {
      "q": "De ce investighezi Inbox rule intr-un caz M365?",
      "a": [
        "Atacatorii ascund emailuri si raspunsuri.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Atacatorii ascund emailuri si raspunsuri."
    },
    {
      "q": "In Microsoft 365, ce inseamna OAuth consent?",
      "a": [
        "aplicatie autorizata sa acceseze date",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Poate persista dupa reset parola."
    },
    {
      "q": "De ce investighezi OAuth consent intr-un caz M365?",
      "a": [
        "Poate persista dupa reset parola.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Poate persista dupa reset parola."
    },
    {
      "q": "In Microsoft 365, ce inseamna Mailbox delegation?",
      "a": [
        "acces delegat la mailbox",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Poate fi abuzat pentru persistenta."
    },
    {
      "q": "De ce investighezi Mailbox delegation intr-un caz M365?",
      "a": [
        "Poate fi abuzat pentru persistenta.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Poate fi abuzat pentru persistenta."
    },
    {
      "q": "In Microsoft 365, ce inseamna Defender for Office?",
      "a": [
        "detectii phishing/malware email",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Ajuta la analiza campaniilor email."
    },
    {
      "q": "De ce investighezi Defender for Office intr-un caz M365?",
      "a": [
        "Ajuta la analiza campaniilor email.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Ajuta la analiza campaniilor email."
    },
    {
      "q": "In Microsoft 365, ce inseamna Safe Links?",
      "a": [
        "protectie URL in email",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Ajuta la blocarea linkurilor malitioase."
    },
    {
      "q": "De ce investighezi Safe Links intr-un caz M365?",
      "a": [
        "Ajuta la blocarea linkurilor malitioase.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Ajuta la blocarea linkurilor malitioase."
    },
    {
      "q": "In Microsoft 365, ce inseamna Message trace?",
      "a": [
        "urmarire flux email",
        "Port de retea",
        "Event ID Sysmon",
        "Comanda Linux"
      ],
      "c": 0,
      "e": "Util pentru phishing si BEC."
    },
    {
      "q": "De ce investighezi Message trace intr-un caz M365?",
      "a": [
        "Util pentru phishing si BEC.",
        "Este mereu false positive",
        "Nu are legatura cu emailul",
        "Sterge automat malware"
      ],
      "c": 0,
      "e": "Util pentru phishing si BEC."
    },
    {
      "q": "In AWS, ce reprezinta CloudTrail?",
      "a": [
        "audit pentru API calls AWS",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Raspunde la cine/ce/cand/de unde."
    },
    {
      "q": "De ce conteaza CloudTrail intr-o investigatie cloud?",
      "a": [
        "Raspunde la cine/ce/cand/de unde.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Raspunde la cine/ce/cand/de unde."
    },
    {
      "q": "In AWS, ce reprezinta GuardDuty?",
      "a": [
        "detectii managed AWS",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Semnaleaza activitati suspecte in cloud."
    },
    {
      "q": "De ce conteaza GuardDuty intr-o investigatie cloud?",
      "a": [
        "Semnaleaza activitati suspecte in cloud.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Semnaleaza activitati suspecte in cloud."
    },
    {
      "q": "In AWS, ce reprezinta VPC Flow Logs?",
      "a": [
        "trafic retea in VPC",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Util pentru conexiuni si exfiltrare."
    },
    {
      "q": "De ce conteaza VPC Flow Logs intr-o investigatie cloud?",
      "a": [
        "Util pentru conexiuni si exfiltrare.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Util pentru conexiuni si exfiltrare."
    },
    {
      "q": "In AWS, ce reprezinta ConsoleLogin?",
      "a": [
        "login in consola AWS",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Verifica MFA, IP si rezultat."
    },
    {
      "q": "De ce conteaza ConsoleLogin intr-o investigatie cloud?",
      "a": [
        "Verifica MFA, IP si rezultat.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Verifica MFA, IP si rezultat."
    },
    {
      "q": "In AWS, ce reprezinta CreateAccessKey?",
      "a": [
        "cheie noua pentru user IAM",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Poate indica persistenta."
    },
    {
      "q": "De ce conteaza CreateAccessKey intr-o investigatie cloud?",
      "a": [
        "Poate indica persistenta.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Poate indica persistenta."
    },
    {
      "q": "In AWS, ce reprezinta AttachUserPolicy?",
      "a": [
        "atasare politica IAM",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Poate indica escaladare privilegii."
    },
    {
      "q": "De ce conteaza AttachUserPolicy intr-o investigatie cloud?",
      "a": [
        "Poate indica escaladare privilegii.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Poate indica escaladare privilegii."
    },
    {
      "q": "In AWS, ce reprezinta StopLogging?",
      "a": [
        "oprire logging CloudTrail",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Defense evasion high severity."
    },
    {
      "q": "De ce conteaza StopLogging intr-o investigatie cloud?",
      "a": [
        "Defense evasion high severity.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Defense evasion high severity."
    },
    {
      "q": "In AWS, ce reprezinta DeleteTrail?",
      "a": [
        "stergere trail CloudTrail",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Defense evasion high severity."
    },
    {
      "q": "De ce conteaza DeleteTrail intr-o investigatie cloud?",
      "a": [
        "Defense evasion high severity.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Defense evasion high severity."
    },
    {
      "q": "In AWS, ce reprezinta AuthorizeSecurityGroupIngress?",
      "a": [
        "deschidere regula inbound",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Verifica 0.0.0.0/0 pe SSH/RDP."
    },
    {
      "q": "De ce conteaza AuthorizeSecurityGroupIngress intr-o investigatie cloud?",
      "a": [
        "Verifica 0.0.0.0/0 pe SSH/RDP.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Verifica 0.0.0.0/0 pe SSH/RDP."
    },
    {
      "q": "In AWS, ce reprezinta S3 Block Public Access?",
      "a": [
        "control impotriva expunerii publice",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Reduce riscul de data exposure."
    },
    {
      "q": "De ce conteaza S3 Block Public Access intr-o investigatie cloud?",
      "a": [
        "Reduce riscul de data exposure.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Reduce riscul de data exposure."
    },
    {
      "q": "In AWS, ce reprezinta Root account?",
      "a": [
        "cont AWS cu privilegii maxime",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Nu trebuie folosit zilnic si necesita MFA."
    },
    {
      "q": "De ce conteaza Root account intr-o investigatie cloud?",
      "a": [
        "Nu trebuie folosit zilnic si necesita MFA.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Nu trebuie folosit zilnic si necesita MFA."
    },
    {
      "q": "In AWS, ce reprezinta Access Analyzer?",
      "a": [
        "analiza acces extern",
        "Windows Logon Type",
        "Wazuh decoder",
        "M365 inbox rule"
      ],
      "c": 0,
      "e": "Ajuta la identificarea resurselor expuse."
    },
    {
      "q": "De ce conteaza Access Analyzer intr-o investigatie cloud?",
      "a": [
        "Ajuta la identificarea resurselor expuse.",
        "Este doar cosmetic",
        "Nu apare in loguri",
        "Este folosit doar pentru Linux local"
      ],
      "c": 0,
      "e": "Ajuta la identificarea resurselor expuse."
    },
    {
      "q": "In Wazuh, ce este agent?",
      "a": [
        "colecteaza telemetrie de pe endpoint",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Agentul trimite evenimente catre manager."
    },
    {
      "q": "De ce este important agent in detection engineering?",
      "a": [
        "Agentul trimite evenimente catre manager.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Agentul trimite evenimente catre manager."
    },
    {
      "q": "In Wazuh, ce este manager?",
      "a": [
        "proceseaza evenimente si reguli",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Managerul coreleaza si genereaza alerte."
    },
    {
      "q": "De ce este important manager in detection engineering?",
      "a": [
        "Managerul coreleaza si genereaza alerte.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Managerul coreleaza si genereaza alerte."
    },
    {
      "q": "In Wazuh, ce este decoder?",
      "a": [
        "extrage campuri din log brut",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Fara decoder bun, regula nu are campuri utile."
    },
    {
      "q": "De ce este important decoder in detection engineering?",
      "a": [
        "Fara decoder bun, regula nu are campuri utile.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Fara decoder bun, regula nu are campuri utile."
    },
    {
      "q": "In Wazuh, ce este rule?",
      "a": [
        "conditie care genereaza alerta",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Regula stabileste nivel, descriere si grupuri."
    },
    {
      "q": "De ce este important rule in detection engineering?",
      "a": [
        "Regula stabileste nivel, descriere si grupuri.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Regula stabileste nivel, descriere si grupuri."
    },
    {
      "q": "In Wazuh, ce este FIM?",
      "a": [
        "File Integrity Monitoring",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Detecteaza modificari de fisiere."
    },
    {
      "q": "De ce este important FIM in detection engineering?",
      "a": [
        "Detecteaza modificari de fisiere.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Detecteaza modificari de fisiere."
    },
    {
      "q": "In Wazuh, ce este SCA?",
      "a": [
        "Security Configuration Assessment",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Verifica hardening/configuratii."
    },
    {
      "q": "De ce este important SCA in detection engineering?",
      "a": [
        "Verifica hardening/configuratii.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Verifica hardening/configuratii."
    },
    {
      "q": "In Wazuh, ce este active response?",
      "a": [
        "actiune automata controlata",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Poate bloca IP sau executa raspuns local."
    },
    {
      "q": "De ce este important active response in detection engineering?",
      "a": [
        "Poate bloca IP sau executa raspuns local.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Poate bloca IP sau executa raspuns local."
    },
    {
      "q": "In Wazuh, ce este MITRE mapping?",
      "a": [
        "legare detectie de tehnica ATT&CK",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Ajuta la raportare si coverage."
    },
    {
      "q": "De ce este important MITRE mapping in detection engineering?",
      "a": [
        "Ajuta la raportare si coverage.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Ajuta la raportare si coverage."
    },
    {
      "q": "In Wazuh, ce este false positive tuning?",
      "a": [
        "reducerea zgomotului fara pierderea detectiei",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Necesita exceptii si testare."
    },
    {
      "q": "De ce este important false positive tuning in detection engineering?",
      "a": [
        "Necesita exceptii si testare.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Necesita exceptii si testare."
    },
    {
      "q": "In Wazuh, ce este dashboard?",
      "a": [
        "vizualizare si agregare",
        "Port TCP",
        "Comanda PowerShell",
        "Eveniment CloudTrail"
      ],
      "c": 0,
      "e": "Ajuta la monitorizare si trenduri."
    },
    {
      "q": "De ce este important dashboard in detection engineering?",
      "a": [
        "Ajuta la monitorizare si trenduri.",
        "Nu ajuta investigatia",
        "Este folosit doar pentru HR",
        "Confirma automat toate incidentele"
      ],
      "c": 0,
      "e": "Ajuta la monitorizare si trenduri."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Initial Access?",
      "a": [
        "phishing, exploit public-facing app, valid accounts",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Tactica de intrare initiala."
    },
    {
      "q": "Cum folosesti Initial Access intr-un raport SOC?",
      "a": [
        "Tactica de intrare initiala.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Tactica de intrare initiala."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Execution?",
      "a": [
        "PowerShell, command shell, scripts",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Rulare de cod/comenzi."
    },
    {
      "q": "Cum folosesti Execution intr-un raport SOC?",
      "a": [
        "Rulare de cod/comenzi.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Rulare de cod/comenzi."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Persistence?",
      "a": [
        "services, scheduled tasks, run keys",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Mentinere acces."
    },
    {
      "q": "Cum folosesti Persistence intr-un raport SOC?",
      "a": [
        "Mentinere acces.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Mentinere acces."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Privilege Escalation?",
      "a": [
        "crestere privilegii",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Atacatorul obtine drepturi mai mari."
    },
    {
      "q": "Cum folosesti Privilege Escalation intr-un raport SOC?",
      "a": [
        "Atacatorul obtine drepturi mai mari.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Atacatorul obtine drepturi mai mari."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Defense Evasion?",
      "a": [
        "log clearing, obfuscation, disable tools",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Evitarea detectiei."
    },
    {
      "q": "Cum folosesti Defense Evasion intr-un raport SOC?",
      "a": [
        "Evitarea detectiei.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Evitarea detectiei."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Credential Access?",
      "a": [
        "LSASS dumping, phishing credentials",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Obtinere credentiale."
    },
    {
      "q": "Cum folosesti Credential Access intr-un raport SOC?",
      "a": [
        "Obtinere credentiale.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Obtinere credentiale."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Discovery?",
      "a": [
        "whoami, net user, ipconfig",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Recunoastere interna."
    },
    {
      "q": "Cum folosesti Discovery intr-un raport SOC?",
      "a": [
        "Recunoastere interna.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Recunoastere interna."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Lateral Movement?",
      "a": [
        "RDP, SMB, PsExec, WinRM",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Miscare intre sisteme."
    },
    {
      "q": "Cum folosesti Lateral Movement intr-un raport SOC?",
      "a": [
        "Miscare intre sisteme.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Miscare intre sisteme."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Command and Control?",
      "a": [
        "HTTPS beaconing, DNS tunneling",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Comunicare cu atacatorul."
    },
    {
      "q": "Cum folosesti Command and Control intr-un raport SOC?",
      "a": [
        "Comunicare cu atacatorul.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Comunicare cu atacatorul."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Exfiltration?",
      "a": [
        "upload date catre destinatie externa",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Scoaterea datelor din mediu."
    },
    {
      "q": "Cum folosesti Exfiltration intr-un raport SOC?",
      "a": [
        "Scoaterea datelor din mediu.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Scoaterea datelor din mediu."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna Impact?",
      "a": [
        "ransomware, data destruction",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Afectarea disponibilitatii/integritatii."
    },
    {
      "q": "Cum folosesti Impact intr-un raport SOC?",
      "a": [
        "Afectarea disponibilitatii/integritatii.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Afectarea disponibilitatii/integritatii."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna T1059?",
      "a": [
        "Command and Scripting Interpreter",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Include PowerShell si shell."
    },
    {
      "q": "Cum folosesti T1059 intr-un raport SOC?",
      "a": [
        "Include PowerShell si shell.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Include PowerShell si shell."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna T1003?",
      "a": [
        "OS Credential Dumping",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Include dumping LSASS."
    },
    {
      "q": "Cum folosesti T1003 intr-un raport SOC?",
      "a": [
        "Include dumping LSASS.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Include dumping LSASS."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna T1078?",
      "a": [
        "Valid Accounts",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Folosirea conturilor valide compromise."
    },
    {
      "q": "Cum folosesti T1078 intr-un raport SOC?",
      "a": [
        "Folosirea conturilor valide compromise.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Folosirea conturilor valide compromise."
    },
    {
      "q": "In MITRE ATT&CK, ce inseamna T1021?",
      "a": [
        "Remote Services",
        "un port firewall",
        "un dashboard Wazuh",
        "un logon type"
      ],
      "c": 0,
      "e": "Include RDP/SMB/WinRM pentru lateral movement."
    },
    {
      "q": "Cum folosesti T1021 intr-un raport SOC?",
      "a": [
        "Include RDP/SMB/WinRM pentru lateral movement.",
        "Il folosesc ca parola",
        "Il ignor mereu",
        "Il folosesc doar pentru design UI"
      ],
      "c": 0,
      "e": "Include RDP/SMB/WinRM pentru lateral movement."
    },
    {
      "q": "In EDR, ce inseamna parent process?",
      "a": [
        "procesul care a lansat procesul suspect",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Winword -> PowerShell este mult mai suspect decat admin shell legitim."
    },
    {
      "q": "De ce verifici parent process intr-o alerta endpoint?",
      "a": [
        "Winword -> PowerShell este mult mai suspect decat admin shell legitim.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Winword -> PowerShell este mult mai suspect decat admin shell legitim."
    },
    {
      "q": "In EDR, ce inseamna command line?",
      "a": [
        "argumentele folosite la executie",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Arata intentia procesului."
    },
    {
      "q": "De ce verifici command line intr-o alerta endpoint?",
      "a": [
        "Arata intentia procesului.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Arata intentia procesului."
    },
    {
      "q": "In EDR, ce inseamna hash reputation?",
      "a": [
        "reputatia fisierului dupa hash",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Ajuta la triage, dar nu este suficienta singura."
    },
    {
      "q": "De ce verifici hash reputation intr-o alerta endpoint?",
      "a": [
        "Ajuta la triage, dar nu este suficienta singura.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Ajuta la triage, dar nu este suficienta singura."
    },
    {
      "q": "In EDR, ce inseamna process isolation?",
      "a": [
        "izolarea hostului prin EDR",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Containment rapid pentru a limita impactul."
    },
    {
      "q": "De ce verifici process isolation intr-o alerta endpoint?",
      "a": [
        "Containment rapid pentru a limita impactul.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Containment rapid pentru a limita impactul."
    },
    {
      "q": "In EDR, ce inseamna quarantine?",
      "a": [
        "mutarea/blocarea fisierului suspect",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Reduce riscul de executie."
    },
    {
      "q": "De ce verifici quarantine intr-o alerta endpoint?",
      "a": [
        "Reduce riscul de executie.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Reduce riscul de executie."
    },
    {
      "q": "In EDR, ce inseamna LSASS access?",
      "a": [
        "acces la procesul cu credentiale",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Indicator de credential dumping."
    },
    {
      "q": "De ce verifici LSASS access intr-o alerta endpoint?",
      "a": [
        "Indicator de credential dumping.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Indicator de credential dumping."
    },
    {
      "q": "In EDR, ce inseamna scheduled task?",
      "a": [
        "task programat pentru persistenta",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Tehnica frecventa pe Windows."
    },
    {
      "q": "De ce verifici scheduled task intr-o alerta endpoint?",
      "a": [
        "Tehnica frecventa pe Windows.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Tehnica frecventa pe Windows."
    },
    {
      "q": "In EDR, ce inseamna Run key?",
      "a": [
        "cheie registry de autostart",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Persistenta Windows clasica."
    },
    {
      "q": "De ce verifici Run key intr-o alerta endpoint?",
      "a": [
        "Persistenta Windows clasica.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Persistenta Windows clasica."
    },
    {
      "q": "In EDR, ce inseamna rundll32?",
      "a": [
        "LOLB in Windows",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Poate rula DLL-uri abuziv."
    },
    {
      "q": "De ce verifici rundll32 intr-o alerta endpoint?",
      "a": [
        "Poate rula DLL-uri abuziv.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Poate rula DLL-uri abuziv."
    },
    {
      "q": "In EDR, ce inseamna certutil?",
      "a": [
        "LOLB pentru download/encoding",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Frecvent abuzat pentru descarcari."
    },
    {
      "q": "De ce verifici certutil intr-o alerta endpoint?",
      "a": [
        "Frecvent abuzat pentru descarcari.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Frecvent abuzat pentru descarcari."
    },
    {
      "q": "In EDR, ce inseamna mshta?",
      "a": [
        "LOLB pentru executie HTA",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Folosit in phishing/malware."
    },
    {
      "q": "De ce verifici mshta intr-o alerta endpoint?",
      "a": [
        "Folosit in phishing/malware.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Folosit in phishing/malware."
    },
    {
      "q": "In EDR, ce inseamna bitsadmin?",
      "a": [
        "LOLB pentru transfer fisiere",
        "serviciu AWS",
        "regula inbox",
        "port DNS"
      ],
      "c": 0,
      "e": "Poate descarca payloaduri."
    },
    {
      "q": "De ce verifici bitsadmin intr-o alerta endpoint?",
      "a": [
        "Poate descarca payloaduri.",
        "Pentru ca este mereu benign",
        "Pentru a sterge toate logurile",
        "Pentru a evita documentarea"
      ],
      "c": 0,
      "e": "Poate descarca payloaduri."
    },
    {
      "q": "In Incident Response, ce inseamna Preparation?",
      "a": [
        "pregatire inainte de incidente",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Playbooks, logging, contacte, tooluri."
    },
    {
      "q": "De ce este important Preparation intr-un incident?",
      "a": [
        "Playbooks, logging, contacte, tooluri.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Playbooks, logging, contacte, tooluri."
    },
    {
      "q": "In Incident Response, ce inseamna Detection and Analysis?",
      "a": [
        "detectare si investigare",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Validare, timeline, scope."
    },
    {
      "q": "De ce este important Detection and Analysis intr-un incident?",
      "a": [
        "Validare, timeline, scope.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Validare, timeline, scope."
    },
    {
      "q": "In Incident Response, ce inseamna Containment?",
      "a": [
        "limitarea extinderii incidentului",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Izolare host, blocare IOC, dezactivare cont."
    },
    {
      "q": "De ce este important Containment intr-un incident?",
      "a": [
        "Izolare host, blocare IOC, dezactivare cont.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Izolare host, blocare IOC, dezactivare cont."
    },
    {
      "q": "In Incident Response, ce inseamna Eradication?",
      "a": [
        "eliminarea cauzei si persistentei",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Stergere malware, patching, eliminare conturi."
    },
    {
      "q": "De ce este important Eradication intr-un incident?",
      "a": [
        "Stergere malware, patching, eliminare conturi.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Stergere malware, patching, eliminare conturi."
    },
    {
      "q": "In Incident Response, ce inseamna Recovery?",
      "a": [
        "revenire controlata la normal",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Restaurare si monitorizare."
    },
    {
      "q": "De ce este important Recovery intr-un incident?",
      "a": [
        "Restaurare si monitorizare.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Restaurare si monitorizare."
    },
    {
      "q": "In Incident Response, ce inseamna Post-Incident?",
      "a": [
        "lectii invatate si imbunatatiri",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Raport, reguli noi, hardening."
    },
    {
      "q": "De ce este important Post-Incident intr-un incident?",
      "a": [
        "Raport, reguli noi, hardening.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Raport, reguli noi, hardening."
    },
    {
      "q": "In Incident Response, ce inseamna timeline?",
      "a": [
        "sir cronologic de evenimente",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Coloana vertebrala a raportului."
    },
    {
      "q": "De ce este important timeline intr-un incident?",
      "a": [
        "Coloana vertebrala a raportului.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Coloana vertebrala a raportului."
    },
    {
      "q": "In Incident Response, ce inseamna scope?",
      "a": [
        "sisteme/useri/date afectate",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Determina impactul si prioritatea."
    },
    {
      "q": "De ce este important scope intr-un incident?",
      "a": [
        "Determina impactul si prioritatea.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Determina impactul si prioritatea."
    },
    {
      "q": "In Incident Response, ce inseamna evidence?",
      "a": [
        "dovezi din loguri si tooluri",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Sustine concluzia."
    },
    {
      "q": "De ce este important evidence intr-un incident?",
      "a": [
        "Sustine concluzia.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Sustine concluzia."
    },
    {
      "q": "In Incident Response, ce inseamna recommendations?",
      "a": [
        "masuri pentru reducerea riscului",
        "un port de retea",
        "o cheie registry mereu malitioasa",
        "un hash benign"
      ],
      "c": 0,
      "e": "Partea actionabila pentru client."
    },
    {
      "q": "De ce este important recommendations intr-un incident?",
      "a": [
        "Partea actionabila pentru client.",
        "Nu conteaza in raport",
        "Este doar un termen de marketing",
        "Se foloseste doar in OSINT"
      ],
      "c": 0,
      "e": "Partea actionabila pentru client."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna WHOIS/RDAP?",
      "a": [
        "informatii despre inregistrarea domeniilor",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Ajuta la context pentru domenii."
    },
    {
      "q": "De ce folosesti WHOIS/RDAP in threat intelligence?",
      "a": [
        "Ajuta la context pentru domenii.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Ajuta la context pentru domenii."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna Certificate Transparency?",
      "a": [
        "certificate TLS emise",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Poate descoperi subdomenii."
    },
    {
      "q": "De ce folosesti Certificate Transparency in threat intelligence?",
      "a": [
        "Poate descoperi subdomenii.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Poate descoperi subdomenii."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna URLScan?",
      "a": [
        "analiza pagini si URL-uri",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Util pentru phishing."
    },
    {
      "q": "De ce folosesti URLScan in threat intelligence?",
      "a": [
        "Util pentru phishing.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Util pentru phishing."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna VirusTotal?",
      "a": [
        "reputatie hash/IP/domain",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Trebuie corelat, nu folosit orbeste."
    },
    {
      "q": "De ce folosesti VirusTotal in threat intelligence?",
      "a": [
        "Trebuie corelat, nu folosit orbeste.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Trebuie corelat, nu folosit orbeste."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna Shodan?",
      "a": [
        "cautare servicii expuse",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Ajuta la attack surface."
    },
    {
      "q": "De ce folosesti Shodan in threat intelligence?",
      "a": [
        "Ajuta la attack surface.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Ajuta la attack surface."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna Censys?",
      "a": [
        "inventariere internet si certificate",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Util pentru expuneri externe."
    },
    {
      "q": "De ce folosesti Censys in threat intelligence?",
      "a": [
        "Util pentru expuneri externe.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Util pentru expuneri externe."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna Telegram monitoring?",
      "a": [
        "monitorizare canale relevante",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Necesita limite legale si etice."
    },
    {
      "q": "De ce folosesti Telegram monitoring in threat intelligence?",
      "a": [
        "Necesita limite legale si etice.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Necesita limite legale si etice."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna Dark Web?",
      "a": [
        "surse ascunse pentru leaks/mentions",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Nu interactionezi ilegal cu actori."
    },
    {
      "q": "De ce folosesti Dark Web in threat intelligence?",
      "a": [
        "Nu interactionezi ilegal cu actori.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Nu interactionezi ilegal cu actori."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna confidence level?",
      "a": [
        "nivel de incredere in informatie",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "Threat intel trebuie calificat."
    },
    {
      "q": "De ce folosesti confidence level in threat intelligence?",
      "a": [
        "Threat intel trebuie calificat.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "Threat intel trebuie calificat."
    },
    {
      "q": "In OSINT/Threat Intel, ce inseamna IOC aging?",
      "a": [
        "cat de recent este indicatorul",
        "Windows Event ID",
        "Logon Type",
        "WinRM port"
      ],
      "c": 0,
      "e": "IOC-urile vechi pot deveni zgomot."
    },
    {
      "q": "De ce folosesti IOC aging in threat intelligence?",
      "a": [
        "IOC-urile vechi pot deveni zgomot.",
        "Pentru a evita validarea",
        "Pentru a cumpara date ilegal",
        "Pentru a sterge loguri"
      ],
      "c": 0,
      "e": "IOC-urile vechi pot deveni zgomot."
    },
    {
      "q": "In Google Workspace, ce reprezinta Login audit?",
      "a": [
        "autentificari Google Workspace",
        "CloudTrail event",
        "Sysmon DNS",
        "SMB share"
      ],
      "c": 0,
      "e": "Verifica IP, locatie si succes/esec."
    },
    {
      "q": "De ce verifici Login audit intr-un incident Google Workspace?",
      "a": [
        "Verifica IP, locatie si succes/esec.",
        "Este irelevant pentru conturi",
        "Este doar pentru endpoint Linux",
        "Nu poate indica abuz"
      ],
      "c": 0,
      "e": "Verifica IP, locatie si succes/esec."
    },
    {
      "q": "In Google Workspace, ce reprezinta Admin audit?",
      "a": [
        "actiuni administrative",
        "CloudTrail event",
        "Sysmon DNS",
        "SMB share"
      ],
      "c": 0,
      "e": "Relevant pentru privilege changes."
    },
    {
      "q": "De ce verifici Admin audit intr-un incident Google Workspace?",
      "a": [
        "Relevant pentru privilege changes.",
        "Este irelevant pentru conturi",
        "Este doar pentru endpoint Linux",
        "Nu poate indica abuz"
      ],
      "c": 0,
      "e": "Relevant pentru privilege changes."
    },
    {
      "q": "In Google Workspace, ce reprezinta Drive audit?",
      "a": [
        "share/download fisiere",
        "CloudTrail event",
        "Sysmon DNS",
        "SMB share"
      ],
      "c": 0,
      "e": "Util pentru exfiltrare si sharing extern."
    },
    {
      "q": "De ce verifici Drive audit intr-un incident Google Workspace?",
      "a": [
        "Util pentru exfiltrare si sharing extern.",
        "Este irelevant pentru conturi",
        "Este doar pentru endpoint Linux",
        "Nu poate indica abuz"
      ],
      "c": 0,
      "e": "Util pentru exfiltrare si sharing extern."
    },
    {
      "q": "In Google Workspace, ce reprezinta Gmail forwarding?",
      "a": [
        "redirectionare mesaje",
        "CloudTrail event",
        "Sysmon DNS",
        "SMB share"
      ],
      "c": 0,
      "e": "Indicator de cont compromis."
    },
    {
      "q": "De ce verifici Gmail forwarding intr-un incident Google Workspace?",
      "a": [
        "Indicator de cont compromis.",
        "Este irelevant pentru conturi",
        "Este doar pentru endpoint Linux",
        "Nu poate indica abuz"
      ],
      "c": 0,
      "e": "Indicator de cont compromis."
    },
    {
      "q": "In Google Workspace, ce reprezinta Gmail filters?",
      "a": [
        "reguli pentru mesaje",
        "CloudTrail event",
        "Sysmon DNS",
        "SMB share"
      ],
      "c": 0,
      "e": "Pot ascunde conversatii malitioase."
    },
    {
      "q": "De ce verifici Gmail filters intr-un incident Google Workspace?",
      "a": [
        "Pot ascunde conversatii malitioase.",
        "Este irelevant pentru conturi",
        "Este doar pentru endpoint Linux",
        "Nu poate indica abuz"
      ],
      "c": 0,
      "e": "Pot ascunde conversatii malitioase."
    },
    {
      "q": "In Google Workspace, ce reprezinta 2-Step Verification?",
      "a": [
        "MFA in Google",
        "CloudTrail event",
        "Sysmon DNS",
        "SMB share"
      ],
      "c": 0,
      "e": "Reduce riscul de cont compromis."
    },
    {
      "q": "De ce verifici 2-Step Verification intr-un incident Google Workspace?",
      "a": [
        "Reduce riscul de cont compromis.",
        "Este irelevant pentru conturi",
        "Este doar pentru endpoint Linux",
        "Nu poate indica abuz"
      ],
      "c": 0,
      "e": "Reduce riscul de cont compromis."
    }
  ],
  "flashcards": [
    {
      "front": "4624",
      "back": "Windows successful logon; verifica Logon Type si sursa."
    },
    {
      "front": "4625",
      "back": "Windows failed logon; util pentru brute force/password spraying."
    },
    {
      "front": "4688",
      "back": "Process creation; command line este esentiala."
    },
    {
      "front": "1102",
      "back": "Audit log cleared; high severity."
    },
    {
      "front": "Sysmon 1",
      "back": "Process Create."
    },
    {
      "front": "Sysmon 3",
      "back": "Network Connection."
    },
    {
      "front": "Sysmon 22",
      "back": "DNS Query."
    },
    {
      "front": "BEC",
      "back": "Business Email Compromise; cauta inbox rules, forwarding, OAuth grants."
    },
    {
      "front": "CloudTrail",
      "back": "AWS API audit: cine a facut ce, cand, de unde."
    },
    {
      "front": "Wazuh decoder",
      "back": "Parseaza loguri si extrage campuri."
    },
    {
      "front": "Wazuh rule",
      "back": "Declanseaza alerta pe baza campurilor/conditiilor."
    },
    {
      "front": "T1059",
      "back": "Command and Scripting Interpreter."
    },
    {
      "front": "LOLBins",
      "back": "Utilitare legitime abuzate: certutil, mshta, rundll32."
    },
    {
      "front": "IOC",
      "back": "Indicator of Compromise; necesita validare si corelare."
    }
  ],
  "interviewPrompts": [
    "Ai o alerta: 20 de logon failures 4625 pentru acelasi user, apoi 4624 Type 10 din alta tara. Cum investighezi?",
    "EDR detecteaza powershell.exe -enc lansat de winword.exe. Ce verifici si ce actiuni iei?",
    "Clientul raporteaza emailuri frauduloase trimise din contul CFO. Cum investighezi in M365?",
    "In AWS vezi StopLogging in CloudTrail. Cum clasifici si ce faci imediat?",
    "Wazuh produce multe false positive pe o regula de PowerShell. Cum o tunezi fara sa pierzi detectia?",
    "Pe Linux vezi login SSH reusit dupa multe esecuri si proces in /tmp. Care este planul tau?",
    "Firewall arata conexiuni periodice la fiecare 60 secunde catre un IP necunoscut. Cum confirmi C2?",
    "Cum explici diferenta dintre IOC si TTP unui manager non-tehnic?"
  ],
  "quizQuestionCount": 30
};
