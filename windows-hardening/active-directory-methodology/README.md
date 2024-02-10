# Metodologia di Active Directory

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, consentendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un numero esteso di utenti in **gruppi** e **sottogruppi** gestibili, controllando nel contempo i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, e una **foresta** rappresenta la collezione di alberi multipli, interconnessi tramite **relazioni di trust**, formando il livello più alto della struttura organizzativa. Specifici **diritti di accesso** e **comunicazione** possono essere designati a ciascuno di questi livelli.

I concetti chiave all'interno di **Active Directory** includono:

1. **Directory** - Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Oggetto** - Indica le entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Dominio** - Serve come contenitore per gli oggetti della directory, con la capacità per più domini di coesistere all'interno di una **foresta**, ognuno mantenendo la propria raccolta di oggetti.
4. **Albero** - Un raggruppamento di domini che condividono un dominio radice comune.
5. **Foresta** - Il vertice della struttura organizzativa in Active Directory, composta da diversi alberi con **relazioni di trust** tra di loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Servizi di dominio** - Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, inclusi le funzionalità di **autenticazione** e **ricerca**.
2. **Servizi di certificazione** - Sovrintende alla creazione, distribuzione e gestione di **certificati digitali** sicuri.
3. **Servizi di directory leggeri** - Supporta le applicazioni abilitate per la directory tramite il protocollo **LDAP**.
4. **Servizi di federazione della directory** - Fornisce capacità di **accesso singolo** per autenticare gli utenti su più applicazioni web in una singola sessione.
5. **Gestione dei diritti** - Aiuta a proteggere il materiale con copyright regolando la sua distribuzione e utilizzo non autorizzati.
6. **Servizio DNS** - Cruciale per la risoluzione dei **nomi di dominio**.

Per una spiegazione più dettagliata, consulta: [**TechTerms - Definizione di Active Directory**](https://techterms.com/definition/active_directory)


### **Autenticazione Kerberos**

Per imparare come **attaccare un AD** è necessario **comprendere** molto bene il **processo di autenticazione Kerberos**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una rapida panoramica dei comandi che puoi eseguire per enumerare/sfruttare un AD.

## Recon di Active Directory (Senza credenziali/sessioni)

Se hai solo accesso a un ambiente AD ma non hai credenziali/sessioni, puoi:

* **Pentestare la rete:**
* Scansiona la rete, trova macchine e porte aperte e cerca di **sfruttare vulnerabilità** o **estrarre credenziali** da esse (ad esempio, [le stampanti potrebbero essere bersagli molto interessanti](ad-information-in-printers.md)).
* L'enumerazione del DNS potrebbe fornire informazioni su server chiave nel dominio come web, stampanti, condivisioni, VPN, media, ecc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Dai un'occhiata alla [**Metodologia generale di Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare ulteriori informazioni su come fare questo.
* **Verifica l'accesso nullo e ospite sui servizi SMB** (questo non funzionerà su versioni moderne di Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Enumerare Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **particolare attenzione all'accesso anonimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Avvelena la rete**
* Raccogli credenziali [**fingendosi servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Accedi all'host [**abusando dell'attacco di relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Raccogli credenziali **esponendo** [**servizi UPnP falsi con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Estrai nomi utente/nomi da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti di domin
### Enumerazione degli utenti

* **Enum anonima SMB/LDAP**: Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enum Kerbrute**: Quando viene richiesto un **nome utente non valido**, il server risponderà utilizzando il codice di errore **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, consentendoci di determinare che il nome utente era invalido. I **nomi utente validi** produrranno una risposta **TGT in una risposta AS-REP** o l'errore _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando che all'utente è richiesta la pre-autenticazione.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Server OWA (Outlook Web Access)**

Se hai trovato uno di questi server nella rete, puoi anche eseguire **l'enumerazione degli utenti** su di esso. Ad esempio, potresti utilizzare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Puoi trovare elenchi di nomi utente in [**questo repository di GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dalla fase di ricognizione che dovresti aver eseguito prima di questa. Con il nome e il cognome potresti utilizzare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali nomi utente validi.
{% endhint %}

### Conoscere uno o più nomi utente

Ok, quindi sai di avere già un nome utente valido ma nessuna password... Allora prova:

* [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT\_REQ\_PREAUTH_, puoi **richiedere un messaggio AS\_REP** per quell'utente che conterrà alcuni dati crittografati da una derivazione della password dell'utente.
* [**Password Spraying**](password-spraying.md): Prova le **password più comuni** con ciascuno degli utenti scoperti, forse qualche utente sta usando una password debole (tieni presente la politica delle password!).
* Nota che puoi anche **sprayare i server OWA** per cercare di accedere ai server di posta degli utenti.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Avvelenamento LLMNR/NBT-NS

Potresti essere in grado di **ottenere** alcuni **hash di sfida** da craccare **avvelenando** alcuni protocolli della **rete**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Se sei riuscito a enumerare l'active directory, avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare attacchi di **relay NTML** per ottenere accesso all'ambiente AD.

### Rubare le credenziali NTLM

Se puoi **accedere ad altri PC o condivisioni** con l'utente **null** o **guest**, potresti **inserire file** (come un file SCF) che, se accessibili in qualche modo, **provocheranno un'autenticazione NTML** nei tuoi confronti in modo da poter **rubare** la **sfida NTLM** per craccarla:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerazione di Active Directory CON credenziali/sessione

Per questa fase è necessario **compromettere le credenziali o una sessione di un account di dominio valido**. Se hai delle credenziali valide o una shell come utente di dominio, **ricorda che le opzioni fornite in precedenza sono comunque opzioni per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata, dovresti sapere qual è il **problema del doppio hop di Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumerazione

Avere compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché sarai in grado di iniziare l'**enumerazione di Active Directory**:

Riguardo a [**ASREPRoast**](asreproast.md), ora puoi trovare tutti gli utenti vulnerabili possibili, e riguardo a [**Password Spraying**](password-spraying.md) puoi ottenere un **elenco di tutti i nomi utente** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

* Puoi utilizzare il [**CMD per eseguire una ricognizione di base**](../basic-cmd-for-pentesters.md#domain-info)
* Puoi anche utilizzare [**powershell per la ricognizione**](../basic-powershell-for-pentesters/) che sarà più stealth
* Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
* Un altro strumento incredibile per la ricognizione in un active directory è [**BloodHound**](bloodhound.md). Non è molto stealth (a seconda dei metodi di raccolta che usi), ma **se non ti interessa**, dovresti assolutamente provarlo. Trova dove gli utenti possono fare RDP, trova il percorso verso altri gruppi, ecc.
* **Altri strumenti automatizzati di enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Record DNS dell'AD**](ad-dns-records.md) in quanto potrebbero contenere informazioni interessanti.
* Uno **strumento con GUI** che puoi utilizzare per enumerare la directory è **AdExplorer.exe** della suite **SysInternal**.
* Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ e _unixUserPassword_, o anche in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
* Se stai usando **Linux**, puoi anche enumerare il dominio utilizzando [**pywerview**](https://github.com/the-useless-one/pywerview).
* Puoi anche provare strumenti automatizzati come:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Estrazione di tutti gli utenti del dominio**

È molto facile ottenere tutti i nomi utente del dominio da Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumerazione sembra piccola, è la parte più importante di tutte. Accedi ai link (soprattutto quello di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica fino a quando ti sentirai a tuo agio. Durante una valutazione, questo sarà il momento chiave per trovare la tua strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Il Kerberoasting consiste nell'ottenere i **biglietti TGS** utilizzati dai servizi legati agli account utente e craccare la loro crittografia, basata sulle password degli utenti, **offline**.

Maggiori informazioni su questo argomento in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}
### Connessione remota (RDP, SSH, FTP, Win-RM, ecc)

Una volta ottenute delle credenziali, puoi verificare se hai accesso a qualsiasi **macchina**. A tal proposito, puoi utilizzare **CrackMapExec** per tentare di connetterti a diversi server con protocolli diversi, in base alle scansioni delle porte.

### Escalation dei privilegi locali

Se hai credenziali compromesse o una sessione come utente di dominio regolare e hai **accesso** con questo utente a **qualsiasi macchina nel dominio**, dovresti cercare di trovare un modo per **aumentare i privilegi localmente e rubare le credenziali**. Questo perché solo con i privilegi di amministratore locale sarai in grado di **estrarre gli hash di altri utenti** dalla memoria (LSASS) e localmente (SAM).

In questo libro è presente una pagina completa sull'[**escalation dei privilegi locali in Windows**](../windows-local-privilege-escalation/) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di utilizzare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket della sessione corrente

È molto **improbabile** che troverai **ticket** nell'utente corrente che ti danno il permesso di accedere a risorse inaspettate, ma puoi verificare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Se sei riuscito a enumerare l'active directory, avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare attacchi di [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Cerca Credenziali nelle Condivisioni dei Computer**

Ora che hai alcune credenziali di base, dovresti verificare se puoi **trovare** file **interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente, ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Segui questo link per conoscere gli strumenti che potresti utilizzare.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Rubare le Credenziali NTLM

Se puoi **accedere ad altri PC o condivisioni**, potresti **inserire file** (come un file SCF) che, se accessibili in qualche modo, **provocheranno un'autenticazione NTML nei tuoi confronti**, in modo da poter **rubare** la **challenge NTLM** per craccarla:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità consentiva a qualsiasi utente autenticato di **compromettere il domain controller**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalation dei privilegi su Active Directory CON credenziali/sessione privilegiate

**Per le seguenti tecniche, un utente di dominio regolare non è sufficiente, hai bisogno di privilegi/credenziali speciali per eseguire questi attacchi.**

### Estrazione dell'hash

Sperabilmente sei riuscito a **compromettere un account di amministratore locale** utilizzando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) compreso il relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/).\
Quindi, è il momento di estrarre tutti gli hash dalla memoria e localmente.\
[**Leggi questa pagina per conoscere i diversi modi per ottenere gli hash.**](broken-reference/)

### Pass the Hash

Una volta ottenuto l'hash di un utente, puoi usarlo per **impersonarlo**.\
Devi utilizzare uno **strumento** che **eseguirà** l'**autenticazione NTLM utilizzando** quell'**hash**, **oppure** puoi creare una nuova **sessionlogon** e **iniettare** quell'**hash** all'interno di **LSASS**, in modo che quando viene eseguita qualsiasi **autenticazione NTLM**, verrà utilizzato quell'**hash**. L'ultima opzione è ciò che fa mimikatz.\
[**Leggi questa pagina per ulteriori informazioni.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **utilizzare l'hash NTLM dell'utente per richiedere i biglietti Kerberos**, come alternativa al comune Pass The Hash tramite protocollo NTLM. Pertanto, ciò potrebbe essere particolarmente **utile nelle reti in cui il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attaccanti **rubano il ticket di autenticazione di un utente** anziché la loro password o i valori hash. Questo ticket rubato viene quindi utilizzato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Riutilizzo delle credenziali

Se hai l'**hash** o la **password** di un **amministratore locale**, dovresti provare ad **effettuare il login localmente** su altri **PC** con esso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Si noti che questo è abbastanza **rumoroso** e **LAPS** lo **mitigherebbe**.
{% endhint %}

### Abuso di MSSQL e collegamenti fidati

Se un utente ha privilegi per **accedere alle istanze MSSQL**, potrebbe essere in grado di utilizzarle per **eseguire comandi** nell'host MSSQL (se in esecuzione come SA), **rubare** l'hash di NetNTLM o addirittura eseguire un **attacco di relay**.\
Inoltre, se un'istanza MSSQL è fidata (collegamento al database) da un'altra istanza MSSQL. Se l'utente ha privilegi sul database fidato, sarà in grado di **utilizzare la relazione di fiducia per eseguire query anche nell'altra istanza**. Queste fiducie possono essere concatenate e a un certo punto l'utente potrebbe essere in grado di trovare un database mal configurato in cui può eseguire comandi.\
**I collegamenti tra database funzionano anche attraverso le fiducie tra foreste.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delega non vincolata

Se trovi un oggetto Computer con l'attributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) e hai privilegi di dominio nel computer, sarai in grado di estrarre TGT dalla memoria di tutti gli utenti che accedono al computer.\
Quindi, se un **Domain Admin accede al computer**, sarai in grado di estrarre il suo TGT e impersonarlo utilizzando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla delega vincolata, potresti persino **compromettere automaticamente un server di stampa** (speriamo che sia un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delega vincolata

Se a un utente o a un computer è consentita la "Delega vincolata", sarà in grado di **impersonare qualsiasi utente per accedere a determinati servizi in un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer, sarai in grado di **impersonare qualsiasi utente** (anche gli amministratori di dominio) per accedere a determinati servizi.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delega vincolata basata su risorse

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione del codice con **privilegi elevati**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso delle ACL

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su alcuni oggetti di dominio** che potrebbero consentirti di **spostarti** lateralmente/**elevare** i privilegi.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso del servizio Printer Spooler

Scoprire un **servizio Spool in ascolto** nel dominio può essere **abusato** per **acquisire nuove credenziali** ed **elevare i privilegi**.

{% content-ref url="acl-persistence-abuse/" %}
[printers-spooler-service-abuse](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abuso delle sessioni di terze parti

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accederanno al sistema tramite RDP, quindi ecco come eseguire un paio di attacchi sulle sessioni RDP di terze parti:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'amministratore locale** sui computer associati al dominio, garantendo che sia **casuale**, univoca e frequentemente **cambiata**. Queste password vengono archiviate in Active Directory e l'accesso è controllato tramite ACL solo agli utenti autorizzati. Con sufficienti autorizzazioni per accedere a queste password, diventa possibile passare ad altri computer.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Furto di certificati

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per elevare i privilegi all'interno dell'ambiente:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso dei modelli di certificato

Se sono configurati **modelli vulnerabili**, è possibile abusarne per elevare i privilegi:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitation con account ad alto privilegio

### Estrarre le credenziali di dominio

Una volta ottenuti i privilegi di **Domain Admin** o ancora meglio di **Enterprise Admin**, è possibile **estrarre** il **database del dominio**: _ntds.dit_.

[**Ulteriori informazioni sull'attacco DCSync possono essere trovate qui**](dcsync.md).

[**Ulteriori informazioni su come rubare l'NTDS.dit possono essere trovate qui**](broken-reference/)

### Privesc come persistenza

Alcune delle tecniche discusse in precedenza possono essere utilizzate per la persistenza.\
Ad esempio, potresti:

*   Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Concedere privilegi [**DCSync**](./#dcsync) a un utente

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'attacco **Silver Ticket** crea un **legittimo Ticket Granting Service (TGS) ticket** per un servizio specifico utilizzando l'hash NTLM (ad esempio, l'hash dell'account PC). Questo metodo viene utilizzato per **accedere ai privilegi del servizio**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Un attacco **Golden Ticket** coinvolge un attaccante che ottiene l'accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene utilizzato per firmare tutti i **Ticket Granting Tickets (TGT)**, che sono essenziali per l'autenticazione all'interno della rete AD.

Una volta ottenuto questo hash, è possibile creare **TGT** per qualsiasi account si desideri (attacco Silver ticket).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Sono come golden ticket forgiati in modo da **eludere i comuni meccanismi di rilevamento dei golden ticket**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistenza dell'account dei certificati**

**Avere i certificati di un account o essere in grado di richiederli** è un ottimo modo per poter persistere nell'account degli utenti (anche se cambiano la password):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}
### **Persistenza del dominio tramite certificati**

**È possibile utilizzare i certificati per persistere con privilegi elevati all'interno del dominio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Gruppo AdminSDHolder

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una **Access Control List (ACL)** standard a questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per concedere l'accesso completo a un utente normale, tale utente acquisisce un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi avere effetti negativi, consentendo l'accesso non autorizzato a meno che non venga monitorata attentamente.

[**Ulteriori informazioni sul gruppo AdminSDHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenziali DSRM

All'interno di ogni **Domain Controller (DC)**, esiste un account **amministratore locale**. Ottenendo i diritti di amministratore su tale macchina, è possibile estrarre l'hash dell'amministratore locale utilizzando **mimikatz**. Successivamente, è necessaria una modifica del registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Amministratore locale.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistenza ACL

È possibile **concedere** alcuni **permessi speciali** a un **utente** su alcuni oggetti specifici del dominio che consentiranno all'utente di **aumentare i privilegi in futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descrittori di sicurezza

I **descrittori di sicurezza** vengono utilizzati per **memorizzare** i **permessi** che un **oggetto** ha **su** un **oggetto**. Se è possibile apportare una **piccola modifica** al descrittore di sicurezza di un oggetto, è possibile ottenere privilegi molto interessanti su quell'oggetto senza la necessità di essere membri di un gruppo privilegiato.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo l'accesso a tutti gli account del dominio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP personalizzato

[Scopri cos'è un SSP (Security Support Provider) qui.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
È possibile creare il proprio SSP per **catturare** in **testo normale** le **credenziali** utilizzate per accedere alla macchina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per **inserire attributi** (SIDHistory, SPN...) su oggetti specificati **senza** lasciare **registrazioni** relative alle **modifiche**. È necessario avere privilegi DA e trovarsi all'interno del **dominio radice**.\
Si noti che se si utilizzano dati errati, verranno visualizzate registrazioni molto brutte.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistenza LAPS

In precedenza abbiamo discusso su come aumentare i privilegi se si dispone dei **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono anche essere utilizzate per **mantenere la persistenza**.\
Controlla:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalation dei privilegi nel dominio tramite trust dei domini

Microsoft considera il **Forest** come il confine di sicurezza. Ciò implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intero Forest**.

### Informazioni di base

Un [**trust di dominio**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse di un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, consentendo la verifica dell'autenticazione in modo trasparente. Quando i domini stabiliscono un trust, scambiano e conservano specifici **chiavi** all'interno dei loro **Domain Controller (DC)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio fidato**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal proprio DC di dominio. Questo TGT è crittografato con una **chiave condivisa** su cui entrambi i domini hanno concordato. L'utente presenta quindi questo TGT al **DC del dominio fidato** per ottenere un ticket di servizio (**TGS**). Dopo la corretta convalida dell'inter-realm TGT da parte del DC del dominio fidato, viene emesso un TGS, concedendo all'utente l'accesso al servizio.

**Passaggi**:

1. Un **computer client** nel **Dominio 1** avvia il processo utilizzando il suo **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** dal suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato correttamente.
3. Il client richiede quindi un **inter-realm TGT** da DC1, che è necessario per accedere alle risorse nel **Dominio 2**.
4. L'inter-realm TGT è crittografato con una **chiave di trust** condivisa tra DC1 e DC2 come parte del trust bidirezionale tra i domini.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) del Dominio 2**.
6. DC2 verifica l'inter-realm TGT utilizzando la chiave di trust condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server nel Dominio 2 a cui il client desidera accedere.
7. Infine, il client presenta questo TGS al server, che è crittografato con l'hash dell'account del server, per ottenere l'accesso al servizio nel Dominio 2.


### Trust diversi

È importante notare che **un trust può essere unidirezionale o bidirezionale**. Nelle opzioni bidirezionali, entrambi i domini si fidano l'uno dell'altro, ma nella relazione di trust **unidirezionale** uno dei domini sarà il dominio **fidato** e l'altro il dominio **fidante**. In quest'ultimo caso, **sarà possibile accedere solo alle risorse all'interno del dominio fidante dal dominio fidato**.

Se il Dominio A si fida del Dominio B, A è il dominio fidante e B è il dominio fidato. Inoltre, nel **Dominio A**, questo sarebbe un **trust in uscita**; e nel **Dominio B**, questo sarebbe un **trust in ingresso**.

**Diverse relazioni di trust**

* **Trust padre-figlio**: questa è una configurazione comune all'interno dello stesso forest, in cui un dominio figlio ha automaticamente un trust bidirezionale transitivo con il dominio padre. Fondamentalmente, ciò significa che le richieste di autenticazione possono fluire senza problemi tra il padre e il figlio.
* **Trust cross-link**: chiamati anche "trust shortcut", questi vengono stabiliti tra domini figli per accelerare i processi di riferimento. Nei forest complessi, i riferimenti di autenticazione devono di solito viaggiare fino alla radice del forest e poi scendere al dominio di destinazione. Creando collegamenti incrociati, il percorso viene accorciato, il che
#### Altre differenze nelle **relazioni di fiducia**

* Una relazione di fiducia può essere anche **transitiva** (A fiducia B, B fiducia C, quindi A fiducia C) o **non transitiva**.
* Una relazione di fiducia può essere stabilita come **fiducia bidirezionale** (entrambi si fidano l'uno dell'altro) o come **fiducia unidirezionale** (solo uno di loro si fida dell'altro).

### Percorso di attacco

1. **Enumerare** le relazioni di fiducia
2. Verificare se qualche **principale di sicurezza** (utente/gruppo/computer) ha **accesso** alle risorse dell'**altro dominio**, forse tramite voci ACE o facendo parte di gruppi dell'altro dominio. Cercare **relazioni tra domini** (probabilmente la fiducia è stata creata per questo).
1. In questo caso, kerberoast potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivottare** attraverso i domini.

Gli attaccanti possono accedere alle risorse in un altro dominio attraverso tre meccanismi principali:

- **Appartenenza a gruppi locali**: I principali possono essere aggiunti a gruppi locali su macchine, come il gruppo "Amministratori" su un server, concedendo loro un controllo significativo su quella macchina.
- **Appartenenza a gruppi di domini esterni**: I principali possono anche essere membri di gruppi all'interno del dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura della fiducia e dalla portata del gruppo.
- **Liste di controllo degli accessi (ACL)**: I principali possono essere specificati in una **ACL**, in particolare come entità in **ACE** all'interno di una **DACL**, fornendo loro accesso a risorse specifiche. Per coloro che desiderano approfondire la meccanica delle ACL, delle DACL e degli ACE, il documento tecnico intitolato "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" è una risorsa preziosa.

### Escalation dei privilegi dalla foresta figlio al genitore
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
Ci sono **2 chiavi di fiducia**, una per _Figlio --> Genitore_ e un'altra per _Genitore_ --> _Figlio_.\
Puoi trovare quella utilizzata dal dominio corrente con:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Iniezione di SID-History

Elevare i privilegi come amministratore aziendale al dominio figlio/genitore sfruttando la fiducia con l'iniezione di SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Sfruttare la configurazione NC scrivibile

Comprendere come può essere sfruttata la Configurazione Naming Context (NC) è fondamentale. La Configurazione NC funge da repository centrale per i dati di configurazione in un ambiente Active Directory (AD) forestale. Questi dati vengono replicati su ogni Domain Controller (DC) all'interno della foresta, con i DC scrivibili che mantengono una copia scrivibile della Configurazione NC. Per sfruttare ciò, è necessario avere **privilegi di SYSTEM su un DC**, preferibilmente un DC figlio.

**Collegare GPO al sito del DC radice**

Il contenitore dei siti della Configurazione NC include informazioni su tutti i siti dei computer associati al dominio all'interno della foresta AD. Operando con privilegi di SYSTEM su qualsiasi DC, gli attaccanti possono collegare GPO al sito del DC radice. Questa azione compromette potenzialmente il dominio radice manipolando le policy applicate a questi siti.

Per informazioni approfondite, è possibile esplorare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettere qualsiasi gMSA nella foresta**

Un vettore di attacco coinvolge il mirare gMSA privilegiati all'interno del dominio. La chiave KDS Root, essenziale per il calcolo delle password delle gMSA, è memorizzata nella Configurazione NC. Con privilegi di SYSTEM su qualsiasi DC, è possibile accedere alla chiave KDS Root e calcolare le password per qualsiasi gMSA in tutta la foresta.

Un'analisi dettagliata può essere trovata nella discussione su [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Attacco al cambio dello schema**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi di SYSTEM, un attaccante può modificare lo schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe portare ad accessi e controllo non autorizzati su oggetti AD appena creati.

Ulteriori informazioni sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Da DA a EA con ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo sugli oggetti dell'infrastruttura a chiave pubblica (PKI) per creare un modello di certificato che consente l'autenticazione come qualsiasi utente all'interno della foresta. Poiché gli oggetti PKI risiedono nella Configurazione NC, compromettere un DC figlio scrivibile consente l'esecuzione di attacchi ESC5.

Maggiori dettagli su questo argomento possono essere letti in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attaccante ha la capacità di configurare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio forestale esterno - Unidirezionale (in ingresso) o bidirezionale
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
In questo scenario **il tuo dominio è fidato** da un dominio esterno che ti conferisce **permessi indeterminati** su di esso. Dovrai trovare **quali principali del tuo dominio hanno accesso al dominio esterno** e poi cercare di sfruttarlo:

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
In questo scenario, **il tuo dominio** sta **affidando** alcuni **privilegi** a un principale proveniente da un **dominio diverso**.

Tuttavia, quando un **dominio viene affidato** al dominio affidante, il dominio affidato **crea un utente** con un **nome prevedibile** che utilizza come **password la password affidata**. Ciò significa che è possibile **accedere a un utente del dominio affidante per entrare nel dominio affidato** per enumerarlo e cercare di ottenere ulteriori privilegi:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Un altro modo per compromettere il dominio affidato è trovare un [**collegamento di fiducia SQL**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** della fiducia del dominio (cosa non molto comune).

Un altro modo per compromettere il dominio affidato è aspettare in una macchina a cui può accedere un **utente del dominio affidato** per effettuare il login tramite **RDP**. Quindi, l'attaccante potrebbe iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì.\
Inoltre, se la **vittima ha montato il suo disco rigido**, dall'**RDP session** l'attaccante potrebbe memorizzare **backdoor** nella **cartella di avvio del disco rigido**. Questa tecnica è chiamata **RDPInception**.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigazione dell'abuso della fiducia del dominio

### **Filtraggio SID:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso le fiducie tra foreste è mitigato dal Filtraggio SID, che è attivato per impostazione predefinita su tutte le fiducie tra foreste. Questo si basa sull'assunzione che le fiducie all'interno della foresta siano sicure, considerando la foresta, piuttosto che il dominio, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: il filtraggio SID potrebbe interrompere le applicazioni e l'accesso degli utenti, portando alla sua disattivazione occasionale.

### **Autenticazione selettiva:**

- Per le fiducie tra foreste, l'utilizzo dell'Autenticazione selettiva garantisce che gli utenti delle due foreste non vengano autenticati automaticamente. Invece, sono richiesti permessi espliciti per gli utenti per accedere ai domini e ai server all'interno del dominio o della foresta affidante.
- È importante notare che queste misure non proteggono dall'exploit del Configuration Naming Context (NC) scrivibile o dagli attacchi all'account di fiducia.

[**Ulteriori informazioni sulle fiducie di dominio in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Alcune difese generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)\

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni degli amministratori di dominio**: Si consiglia di consentire agli amministratori di dominio di effettuare il login solo sui controller di dominio, evitando il loro utilizzo su altri host.
- **Privilegi degli account di servizio**: I servizi non dovrebbero essere eseguiti con privilegi di amministratore di dominio (DA) per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: Per le attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Ciò può essere ottenuto tramite: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementazione di tecniche di inganno**

- L'implementazione dell'inganno comporta la creazione di trappole, come utenti o computer fittizi, con caratteristiche come password che non scadono o sono contrassegnate come Affidabili per la Delega. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta di utenti a gruppi ad alto privilegio.
- Un esempio pratico prevede l'utilizzo di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sull'implementazione delle tecniche di inganno possono essere trovate su [Deploy-Deception su GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificazione dell'inganno**

- **Per gli oggetti utente**: Gli indicatori sospetti includono ObjectSID atipici, accessi rari, date di creazione e bassi conteggi di password errate.
- **Indicatori generali**: Confrontare gli attributi degli oggetti di potenziale inganno con quelli degli oggetti genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare nell'identificazione di tali inganni.

### **Eludere i sistemi di rilevamento**

- **Elusione del rilevamento di Microsoft ATA**:
- **Enumerazione degli utenti**: Evitare l'enumerazione delle sessioni sui controller di dominio per evitare il rilevamento di ATA.
- **Impersonazione del ticket**: Utilizzare chiavi **aes** per la creazione del ticket aiuta a eludere il rilevamento evitando il degrado a NTLM.
- **Attacchi DCSync**: Si consiglia di eseguire l'attacco da un non-Controller di dominio per evitare il rilevamento di ATA, poiché l'esecuzione diretta da un Controller di dominio attiverà gli allarmi.


## Riferimenti

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di GitHub.**

</details>
