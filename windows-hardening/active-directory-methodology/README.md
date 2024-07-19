# Active Directory Methodology

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, consentendo ai **network administrator** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un numero esteso di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, e una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **relazioni di fiducia**, formando il livello più alto della struttura organizzativa. Specifici **diritti di accesso** e **comunicazione** possono essere designati a ciascuno di questi livelli.

I concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Oggetto** – Denota entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Dominio** – Funziona come contenitore per gli oggetti della directory, con la capacità di più domini di coesistere all'interno di una **foresta**, ciascuno mantenendo la propria raccolta di oggetti.
4. **Albero** – Un raggruppamento di domini che condividono un dominio radice comune.
5. **Foresta** – Il culmine della struttura organizzativa in Active Directory, composta da diversi alberi con **relazioni di fiducia** tra di loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Servizi di Dominio** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, inclusi **funzionalità di autenticazione** e **ricerca**.
2. **Servizi di Certificato** – Supervisiona la creazione, distribuzione e gestione di **certificati digitali** sicuri.
3. **Servizi di Directory Leggeri** – Supporta applicazioni abilitate per directory tramite il **protocollo LDAP**.
4. **Servizi di Federazione della Directory** – Fornisce capacità di **single-sign-on** per autenticare gli utenti attraverso più applicazioni web in una singola sessione.
5. **Gestione dei Diritti** – Aiuta a proteggere il materiale protetto da copyright regolando la sua distribuzione e uso non autorizzati.
6. **Servizio DNS** – Cruciale per la risoluzione dei **nomi di dominio**.

Per una spiegazione più dettagliata, controlla: [**TechTerms - Definizione di Active Directory**](https://techterms.com/definition/active\_directory)

### **Autenticazione Kerberos**

Per imparare a **attaccare un AD** devi **comprendere** molto bene il **processo di autenticazione Kerberos**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi visitare [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una visione rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

## Recon Active Directory (Nessuna credenziale/sessioni)

Se hai solo accesso a un ambiente AD ma non hai credenziali/sessioni, potresti:

* **Pentestare la rete:**
* Scansiona la rete, trova macchine e porte aperte e prova a **sfruttare vulnerabilità** o **estrarre credenziali** da esse (ad esempio, [le stampanti potrebbero essere obiettivi molto interessanti](ad-information-in-printers.md).
* Enumerare il DNS potrebbe fornire informazioni sui server chiave nel dominio come web, stampanti, condivisioni, vpn, media, ecc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Dai un'occhiata alla [**Metodologia di Pentesting Generale**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare ulteriori informazioni su come fare questo.
* **Controlla l'accesso nullo e Guest sui servizi smb** (questo non funzionerà su versioni moderne di Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Enumerare Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Una guida più dettagliata su come enumerare LDAP può essere trovata qui (fai **particolare attenzione all'accesso anonimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Avvelenare la rete**
* Raccogli credenziali [**impersonando servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Accedi all'host [**abusando dell'attacco di relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Raccogli credenziali **esponendo** [**falsi servizi UPnP con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Estrai nomi utenti/nomi da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti di dominio e anche da fonti pubblicamente disponibili.
* Se trovi i nomi completi dei lavoratori dell'azienda, potresti provare diverse **convenzioni di nome utente AD** ([**leggi questo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NomeCognome_, _Nome.Cognome_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _CognomeNome_, _Cognome.Nome_, _CognomeN_, _Cognome.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
* Strumenti:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione utenti

* **Enum SMB/LDAP anonimo:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enum Kerbrute**: Quando viene **richiesto un nome utente non valido**, il server risponderà utilizzando il codice di errore **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, permettendoci di determinare che il nome utente era non valido. **I nomi utente validi** genereranno o il **TGT in una risposta AS-REP** o l'errore _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando che l'utente deve eseguire la pre-autenticazione.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Server OWA (Outlook Web Access)**

Se hai trovato uno di questi server nella rete, puoi anche eseguire **l'enumerazione degli utenti contro di esso**. Ad esempio, potresti utilizzare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Puoi trovare elenchi di nomi utente in [**questo repo github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* e in quest'altro ([**nomi utente statisticamente probabili**](https://github.com/insidetrust/statistically-likely-usernames)).

Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dal passo di ricognizione che avresti dovuto eseguire prima di questo. Con il nome e il cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali nomi utente validi.
{% endhint %}

### Conoscere uno o più nomi utente

Ok, quindi sai di avere già un nome utente valido ma nessuna password... Prova:

* [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT\_REQ\_PREAUTH_ puoi **richiedere un messaggio AS\_REP** per quell'utente che conterrà alcuni dati crittografati da una derivazione della password dell'utente.
* [**Password Spraying**](password-spraying.md): Proviamo le **password più comuni** con ciascuno degli utenti scoperti, magari qualche utente sta usando una password debole (tieni presente la politica delle password!).
* Nota che puoi anche **spray i server OWA** per cercare di accedere ai server di posta degli utenti.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Avvelenamento LLMNR/NBT-NS

Potresti essere in grado di **ottenere** alcuni **hash di sfida** per decifrare **avvelenando** alcuni protocolli della **rete**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relay NTML

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare attacchi [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* per ottenere accesso all'ambiente AD.

### Rubare credenziali NTLM

Se puoi **accedere ad altri PC o condivisioni** con l'**utente null o guest** potresti **posizionare file** (come un file SCF) che, se in qualche modo accessibili, **attiveranno un'autenticazione NTML contro di te** così potrai **rubare** la **sfida NTLM** per decifrarla:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerare Active Directory CON credenziali/sessione

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai alcune credenziali valide o una shell come utente di dominio, **dovresti ricordare che le opzioni fornite prima sono ancora opzioni per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti sapere qual è il **problema del doppio salto Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumerazione

Aver compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché sarai in grado di avviare l'**Enumerazione di Active Directory:**

Per quanto riguarda [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e per quanto riguarda [**Password Spraying**](password-spraying.md) puoi ottenere un **elenco di tutti i nomi utente** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

* Potresti usare il [**CMD per eseguire una ricognizione di base**](../basic-cmd-for-pentesters.md#domain-info)
* Puoi anche usare [**powershell per la ricognizione**](../basic-powershell-for-pentesters/) che sarà più furtivo
* Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
* Un altro strumento fantastico per la ricognizione in un active directory è [**BloodHound**](bloodhound.md). Non è **molto furtivo** (a seconda dei metodi di raccolta che usi), ma **se non ti importa** di questo, dovresti assolutamente provarlo. Scopri dove gli utenti possono RDP, trova percorsi verso altri gruppi, ecc.
* **Altri strumenti automatizzati per l'enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Record DNS dell'AD**](ad-dns-records.md) poiché potrebbero contenere informazioni interessanti.
* Un **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** dal **SysInternal** Suite.
* Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche per _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
* Se stai usando **Linux**, potresti anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* Potresti anche provare strumenti automatizzati come:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Estrazione di tutti gli utenti di dominio**

È molto facile ottenere tutti i nomi utente del dominio da Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di enumerazione sembra piccola, è la parte più importante di tutte. Accedi ai link (principalmente quello di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica finché non ti senti a tuo agio. Durante una valutazione, questo sarà il momento chiave per trovare la tua strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting implica ottenere **ticket TGS** utilizzati dai servizi legati agli account utente e decifrare la loro crittografia—che si basa sulle password degli utenti—**offline**.

Maggiori informazioni su questo in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Connessione remota (RDP, SSH, FTP, Win-RM, ecc)

Una volta ottenute alcune credenziali, potresti controllare se hai accesso a qualche **macchina**. A tal fine, potresti usare **CrackMapExec** per tentare di connetterti a diversi server con diversi protocolli, in base alle tue scansioni delle porte.

### Escalation dei privilegi locali

Se hai compromesso credenziali o una sessione come utente di dominio regolare e hai **accesso** con questo utente a **qualsiasi macchina nel dominio**, dovresti cercare di trovare il modo di **escalare i privilegi localmente e cercare credenziali**. Questo perché solo con privilegi di amministratore locale sarai in grado di **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**escalation dei privilegi locali in Windows**](../windows-local-privilege-escalation/) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket di sessione attuali

È molto **improbabile** che tu trovi **ticket** nell'utente attuale **che ti diano permesso di accedere** a risorse inaspettate, ma potresti controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare gli attacchi [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Cerca Credenziali nelle Condivisioni di Computer**

Ora che hai alcune credenziali di base dovresti controllare se puoi **trovare** file **interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente, ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti che devi controllare).

[**Segui questo link per scoprire gli strumenti che potresti utilizzare.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Rubare Credenziali NTLM

Se puoi **accedere ad altri PC o condivisioni** potresti **posizionare file** (come un file SCF) che, se in qualche modo accessibili, **attiveranno un'autenticazione NTML contro di te** così potrai **rubare** la **sfida NTLM** per decifrarla:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità ha permesso a qualsiasi utente autenticato di **compromettere il controller di dominio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalation dei privilegi su Active Directory CON credenziali/sessioni privilegiate

**Per le seguenti tecniche un normale utente di dominio non è sufficiente, hai bisogno di privilegi/credenziali speciali per eseguire questi attacchi.**

### Estrazione degli Hash

Speriamo che tu sia riuscito a **compromettere qualche account admin locale** utilizzando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inclusi i relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/).\
Poi, è tempo di estrarre tutti gli hash in memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **strumento** che **eseguirà** l'**autenticazione NTLM utilizzando** quell'**hash**, **oppure** potresti creare una nuova **sessionlogon** e **iniettare** quell'**hash** all'interno del **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, quell'**hash verrà utilizzato.** L'ultima opzione è ciò che fa mimikatz.\
[**Leggi questa pagina per ulteriori informazioni.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **utilizzare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Pertanto, questo potrebbe essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attaccanti **rubano il ticket di autenticazione di un utente** invece dei loro valori di password o hash. Questo ticket rubato viene poi utilizzato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Riutilizzo delle Credenziali

Se hai l'**hash** o la **password** di un **amministratore locale** dovresti provare a **accedere localmente** ad altri **PC** con esso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.
{% endhint %}

### Abuso di MSSQL e collegamenti fidati

Se un utente ha privilegi per **accedere alle istanze MSSQL**, potrebbe essere in grado di usarlo per **eseguire comandi** nell'host MSSQL (se in esecuzione come SA), **rubare** l'**hash** NetNTLM o persino eseguire un **attacco di relay**.\
Inoltre, se un'istanza MSSQL è fidata (collegamento al database) da un'altra istanza MSSQL. Se l'utente ha privilegi sul database fidato, sarà in grado di **utilizzare la relazione di fiducia per eseguire query anche nell'altra istanza**. Queste fiducia possono essere concatenate e a un certo punto l'utente potrebbe essere in grado di trovare un database mal configurato dove può eseguire comandi.\
**I collegamenti tra i database funzionano anche attraverso le fiducia tra foreste.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegazione non vincolata

Se trovi un oggetto Computer con l'attributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) e hai privilegi di dominio nel computer, sarai in grado di estrarre i TGT dalla memoria di ogni utente che accede al computer.\
Quindi, se un **Domain Admin accede al computer**, sarai in grado di estrarre il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla delegazione vincolata potresti anche **compromettere automaticamente un Print Server** (speriamo che sia un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegazione vincolata

Se un utente o un computer è autorizzato per la "Delegazione vincolata", sarà in grado di **impersonare qualsiasi utente per accedere a determinati servizi in un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche gli amministratori di dominio) per accedere a determinati servizi.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegazione vincolata basata sulle risorse

Avere il privilegio di **SCRITTURA** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione di codice con **privilegi elevati**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso delle ACL

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su alcuni oggetti di dominio** che potrebbero consentirti di **muoverti** lateralmente/**escalare** privilegi.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso del servizio Printer Spooler

Scoprire un **servizio Spool in ascolto** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abuso delle sessioni di terze parti

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema tramite RDP, quindi ecco come eseguire un paio di attacchi sulle sessioni RDP di terze parti:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'amministratore locale** sui computer uniti al dominio, assicurando che sia **randomizzata**, unica e frequentemente **cambiata**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACL solo per gli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile passare ad altri computer.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Furto di certificati

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per escalare privilegi all'interno dell'ambiente:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso dei modelli di certificato

Se sono configurati **modelli vulnerabili**, è possibile abusarne per escalare privilegi:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-sfruttamento con account ad alto privilegio

### Dumping delle credenziali di dominio

Una volta ottenuti i privilegi di **Domain Admin** o ancora meglio di **Enterprise Admin**, puoi **dumpare** il **database di dominio**: _ntds.dit_.

[**Maggiori informazioni sull'attacco DCSync possono essere trovate qui**](dcsync.md).

[**Maggiori informazioni su come rubare il NTDS.dit possono essere trovate qui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc come persistenza

Alcune delle tecniche discusse in precedenza possono essere utilizzate per la persistenza.\
Ad esempio potresti:

*   Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Concedere privilegi di [**DCSync**](./#dcsync) a un utente

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'**attacco Silver Ticket** crea un **ticket di servizio Ticket Granting Service (TGS)** legittimo per un servizio specifico utilizzando l'**hash NTLM** (ad esempio, l'**hash dell'account PC**). Questo metodo viene impiegato per **accedere ai privilegi di servizio**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Un **attacco Golden Ticket** comporta che un attaccante ottenga accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene utilizzato per firmare tutti i **Ticket Granting Tickets (TGT)**, essenziali per l'autenticazione all'interno della rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGT** per qualsiasi account scelga (attacco Silver Ticket).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Questi sono simili ai golden ticket forgiati in un modo che **bypassa i comuni meccanismi di rilevamento dei golden ticket.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistenza dell'account tramite certificati**

**Avere certificati di un account o essere in grado di richiederli** è un ottimo modo per poter persistere nell'account degli utenti (anche se cambia la password):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistenza del dominio tramite certificati**

**Utilizzare certificati è anche possibile per persistere con privilegi elevati all'interno del dominio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Gruppo AdminSDHolder

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una standard **Access Control List (ACL)** su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per dare accesso completo a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, destinata a proteggere, può quindi ritorcersi contro, consentendo accessi non autorizzati a meno che non venga monitorata da vicino.

[**Maggiori informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenziali DSRM

All'interno di ogni **Domain Controller (DC)**, esiste un account di **amministratore locale**. Ottenendo diritti di amministratore su tale macchina, l'hash dell'amministratore locale può essere estratto utilizzando **mimikatz**. Successivamente, è necessaria una modifica del registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account dell'amministratore locale.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistenza delle ACL

Potresti **dare** alcuni **privilegi speciali** a un **utente** su alcuni oggetti di dominio specifici che consentiranno all'utente di **escalare privilegi in futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descrittori di sicurezza

I **descrittori di sicurezza** vengono utilizzati per **memorizzare** i **privilegi** che un **oggetto** ha **su** un **oggetto**. Se riesci a **fare** un **piccolo cambiamento** nel **descrittore di sicurezza** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account di dominio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP personalizzato

[Scopri cos'è un SSP (Security Support Provider) qui.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **testo chiaro** le **credenziali** utilizzate per accedere alla macchina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per **inviare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** riguardo alle **modifiche**. Hai **bisogno di privilegi DA** e di essere all'interno del **dominio radice**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistenza LAPS

In precedenza abbiamo discusso di come escalare privilegi se hai **sufficienti permessi per leggere le password LAPS**. Tuttavia, queste password possono anche essere utilizzate per **mantenere la persistenza**.\
Controlla:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalation dei privilegi nella foresta - Fiducia tra domini

Microsoft considera la **Foresta** come il confine di sicurezza. Ciò implica che **compromettere un singolo dominio potrebbe potenzialmente portare alla compromissione dell'intera Foresta**.

### Informazioni di base

Una [**fiducia di dominio**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse in un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, consentendo che le verifiche di autenticazione fluiscano senza problemi. Quando i domini stabiliscono una fiducia, scambiano e mantengono specifiche **chiavi** all'interno dei loro **Domain Controllers (DC)**, che sono cruciali per l'integrità della fiducia.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio fidato**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal DC del proprio dominio. Questo TGT è crittografato con una **chiave** condivisa su cui entrambi i domini hanno concordato. L'utente presenta quindi questo TGT al **DC del dominio fidato** per ottenere un ticket di servizio (**TGS**). Dopo la validazione con successo dell'inter-realm TGT da parte del DC del dominio fidato, emette un TGS, concedendo all'utente accesso al servizio.

**Passaggi**:

1. Un **computer client** nel **Dominio 1** avvia il processo utilizzando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** dal proprio **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede quindi un **inter-realm TGT** da DC1, necessario per accedere alle risorse nel **Dominio 2**.
4. L'inter-realm TGT è crittografato con una **chiave di fiducia** condivisa tra DC1 e DC2 come parte della fiducia tra domini bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** del Dominio 2.
6. DC2 verifica l'inter-realm TGT utilizzando la sua chiave di fiducia condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server nel Dominio 2 a cui il client desidera accedere.
7. Infine, il client presenta questo TGS al server, che è crittografato con l'hash dell'account del server, per ottenere accesso al servizio nel Dominio 2.

### Diverse fiducia

È importante notare che **una fiducia può essere unidirezionale o bidirezionale**. Nelle opzioni bidirezionali, entrambi i domini si fideranno l'uno dell'altro, ma nella relazione di fiducia **unidirezionale** uno dei domini sarà il **fidato** e l'altro il **fiducioso**. Nel secondo caso, **sarai in grado di accedere solo alle risorse all'interno del dominio fiducioso dal fidato**.

Se il Dominio A si fida del Dominio B, A è il dominio fiducioso e B è quello fidato. Inoltre, in **Dominio A**, questo sarebbe una **fiducia in uscita**; e in **Dominio B**, questo sarebbe una **fiducia in entrata**.

**Diverse relazioni di fiducia**

* **Fiducia Genitore-Figlio**: Questa è una configurazione comune all'interno della stessa foresta, dove un dominio figlio ha automaticamente una fiducia bidirezionale transitiva con il suo dominio genitore. Essenzialmente, ciò significa che le richieste di autenticazione possono fluire senza problemi tra il genitore e il figlio.
* **Fiducia Cross-link**: Riferita come "fiducia abbreviata", queste vengono stabilite tra domini figli per accelerare i processi di riferimento. In foreste complesse, i riferimenti di autenticazione devono generalmente viaggiare fino alla radice della foresta e poi giù fino al dominio di destinazione. Creando collegamenti incrociati, il viaggio viene accorciato, il che è particolarmente vantaggioso in ambienti geograficamente dispersi.
* **Fiducia Esterna**: Queste vengono impostate tra domini diversi e non correlati e sono di natura non transitiva. Secondo [la documentazione di Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), le fiducia esterne sono utili per accedere a risorse in un dominio al di fuori dell'attuale foresta che non è connesso tramite una fiducia tra foreste. La sicurezza è rafforzata attraverso il filtraggio SID con fiducia esterne.
* **Fiducia Tree-root**: Queste fiducia vengono stabilite automaticamente tra il dominio radice della foresta e un nuovo albero radice aggiunto. Anche se non comunemente incontrate, le fiducia tree-root sono importanti per aggiungere nuovi alberi di dominio a una foresta, consentendo loro di mantenere un nome di dominio unico e garantendo una transitività bidirezionale. Maggiori informazioni possono essere trovate nella [guida di Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Fiducia tra Foreste**: Questo tipo di fiducia è una fiducia bidirezionale transitiva tra due domini radice di foresta, imponendo anche il filtraggio SID per migliorare le misure di sicurezza.
* **Fiducia MIT**: Queste fiducia vengono stabilite con domini Kerberos non Windows, [conformi a RFC4120](https://tools.ietf.org/html/rfc4120). Le fiducia MIT sono un po' più specializzate e si rivolgono a ambienti che richiedono integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Altre differenze nelle **relazioni di fiducia**

* Una relazione di fiducia può anche essere **transitiva** (A si fida di B, B si fida di C, quindi A si fida di C) o **non transitiva**.
* Una relazione di fiducia può essere impostata come **fiducia bidirezionale** (entrambi si fidano l'uno dell'altro) o come **fiducia unidirezionale** (solo uno di loro si fida dell'altro).

### Percorso di attacco

1. **Enumerare** le relazioni di fiducia
2. Controlla se qualche **principale di sicurezza** (utente/gruppo/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite voci ACE o essendo in gruppi dell'altro dominio. Cerca **relazioni tra domini** (la fiducia è stata creata per questo probabilmente).
1. Kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** tra i domini.

Gli attaccanti potrebbero accedere alle risorse in un altro dominio attraverso tre meccanismi principali:

* **Appartenenza a Gruppi Locali**: I principali potrebbero essere aggiunti a gruppi locali su macchine, come il gruppo "Amministratori" su un server, concedendo loro un controllo significativo su quella macchina.
* **Appartenenza a Gruppi di Domini Esterni**: I principali possono anche essere membri di gruppi all'interno del dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura della fiducia e dall'ambito del gruppo.
* **Liste di Controllo di Accesso (ACL)**: I principali potrebbero essere specificati in un **ACL**, in particolare come entità in **ACE** all'interno di un **DACL**, fornendo loro accesso a risorse specifiche. Per coloro che desiderano approfondire la meccanica delle ACL, DACL e ACE, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” è una risorsa preziosa.

### Escalation dei privilegi da figlio a genitore nella foresta
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Ci sono **2 chiavi fidate**, una per _Child --> Parent_ e un'altra per _Parent_ --> _Child_.\
Puoi utilizzare quella usata dal dominio corrente con:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Iniezione di SID-History

Esegui l'escalation come amministratore dell'Enterprise al dominio padre/figlio abusando della fiducia con l'iniezione di SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Sfruttare la Configurazione NC scrivibile

Comprendere come la Configurazione Naming Context (NC) possa essere sfruttata è cruciale. La Configurazione NC funge da repository centrale per i dati di configurazione in ambienti Active Directory (AD). Questi dati vengono replicati a ogni Domain Controller (DC) all'interno della foresta, con DC scrivibili che mantengono una copia scrivibile della Configurazione NC. Per sfruttare questo, è necessario avere **privilegi di SYSTEM su un DC**, preferibilmente un DC figlio.

**Collegare GPO al sito DC radice**

Il contenitore Siti della Configurazione NC include informazioni sui siti di tutti i computer uniti al dominio all'interno della foresta AD. Operando con privilegi di SYSTEM su qualsiasi DC, gli attaccanti possono collegare GPO ai siti DC radice. Questa azione compromette potenzialmente il dominio radice manipolando le politiche applicate a questi siti.

Per informazioni approfondite, si può esplorare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettere qualsiasi gMSA nella foresta**

Un vettore d'attacco coinvolge il targeting di gMSA privilegiati all'interno del dominio. La chiave KDS Root, essenziale per calcolare le password delle gMSA, è memorizzata all'interno della Configurazione NC. Con privilegi di SYSTEM su qualsiasi DC, è possibile accedere alla chiave KDS Root e calcolare le password per qualsiasi gMSA nella foresta.

Un'analisi dettagliata può essere trovata nella discussione su [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Attacco di modifica dello schema**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi di SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Questo potrebbe portare ad accessi non autorizzati e controllo su nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Da DA a EA con ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo sugli oggetti di Public Key Infrastructure (PKI) per creare un modello di certificato che consente l'autenticazione come qualsiasi utente all'interno della foresta. Poiché gli oggetti PKI risiedono nella Configurazione NC, compromettere un DC figlio scrivibile consente l'esecuzione di attacchi ESC5.

Maggiori dettagli su questo possono essere letti in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attaccante ha la capacità di impostare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio Foresta Esterno - Unidirezionale (In entrata) o bidirezionale
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
In questo scenario **il tuo dominio è fidato** da un dominio esterno che ti concede **permessi indeterminati** su di esso. Dovrai scoprire **quali principi del tuo dominio hanno accesso a quale dominio esterno** e poi cercare di sfruttarlo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Dominio Forestale Esterno - Unidirezionale (In uscita)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In questo scenario **il tuo dominio** sta **fidandosi** di alcuni **privilegi** a un principale di **domini diversi**.

Tuttavia, quando un **dominio è fidato** dal dominio fiducioso, il dominio fidato **crea un utente** con un **nome prevedibile** che utilizza come **password la password fidata**. Ciò significa che è possibile **accedere a un utente dal dominio fiducioso per entrare in quello fidato** per enumerarlo e cercare di aumentare ulteriormente i privilegi:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Un altro modo per compromettere il dominio fidato è trovare un [**collegamento SQL fidato**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** della fiducia del dominio (cosa non molto comune).

Un altro modo per compromettere il dominio fidato è aspettare su una macchina a cui un **utente del dominio fidato può accedere** per effettuare il login tramite **RDP**. Poi, l'attaccante potrebbe iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì.\
Inoltre, se la **vittima ha montato il suo disco rigido**, dal processo della **sessione RDP** l'attaccante potrebbe memorizzare **backdoor** nella **cartella di avvio del disco rigido**. Questa tecnica è chiamata **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigazione dell'abuso della fiducia del dominio

### **Filtraggio SID:**

* Il rischio di attacchi che sfruttano l'attributo della cronologia SID attraverso le fiducie tra foreste è mitigato dal Filtraggio SID, che è attivato per impostazione predefinita su tutte le fiducie inter-foresta. Questo è supportato dall'assunzione che le fiducie intra-foresta siano sicure, considerando la foresta, piuttosto che il dominio, come il confine di sicurezza secondo la posizione di Microsoft.
* Tuttavia, c'è un problema: il filtraggio SID potrebbe interrompere le applicazioni e l'accesso degli utenti, portando alla sua disattivazione occasionale.

### **Autenticazione Selettiva:**

* Per le fiducie inter-foresta, l'uso dell'Autenticazione Selettiva garantisce che gli utenti delle due foreste non siano autenticati automaticamente. Invece, sono necessarie autorizzazioni esplicite affinché gli utenti possano accedere ai domini e ai server all'interno del dominio o della foresta fiduciosa.
* È importante notare che queste misure non proteggono contro lo sfruttamento del Contesto di Nominazione di Configurazione (NC) scrivibile o attacchi all'account di fiducia.

[**Ulteriori informazioni sulle fiducie di dominio in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Alcune Difese Generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)\\

### **Misure Difensive per la Protezione delle Credenziali**

* **Restrizioni per gli Amministratori di Dominio**: Si raccomanda che gli Amministratori di Dominio possano accedere solo ai Controller di Dominio, evitando il loro utilizzo su altri host.
* **Privilegi degli Account di Servizio**: I servizi non dovrebbero essere eseguiti con privilegi di Amministratore di Dominio (DA) per mantenere la sicurezza.
* **Limitazione Temporale dei Privilegi**: Per i compiti che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementazione di Tecniche di Inganno**

* Implementare l'inganno implica impostare trappole, come utenti o computer esca, con caratteristiche come password che non scadono o sono contrassegnate come Fidate per Delegazione. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta a gruppi ad alto privilegio.
* Un esempio pratico implica l'uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Maggiori informazioni sull'implementazione di tecniche di inganno possono essere trovate in [Deploy-Deception su GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificazione dell'Inganno**

* **Per Oggetti Utente**: Indicatori sospetti includono ObjectSID atipico, accessi infrequenti, date di creazione e conteggi di password errate bassi.
* **Indicatori Generali**: Confrontare gli attributi di potenziali oggetti esca con quelli genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali inganni.

### **Evitare i Sistemi di Rilevamento**

* **Bypass della Rilevazione Microsoft ATA**:
* **Enumerazione Utente**: Evitare l'enumerazione delle sessioni sui Controller di Dominio per prevenire la rilevazione da parte di ATA.
* **Impersonificazione del Ticket**: Utilizzare chiavi **aes** per la creazione di ticket aiuta a evitare la rilevazione non degradando a NTLM.
* **Attacchi DCSync**: È consigliato eseguire da un non-Controller di Dominio per evitare la rilevazione da parte di ATA, poiché l'esecuzione diretta da un Controller di Dominio attiverà avvisi.

## Riferimenti

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
