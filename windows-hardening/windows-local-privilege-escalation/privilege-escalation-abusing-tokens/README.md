# Abuso di Token

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Token

Se **non sai cosa sono i Token di Accesso di Windows**, leggi questa pagina prima di continuare:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Potresti essere in grado di ottenere privilegi elevati abusando dei token che hai già**

### SeImpersonatePrivilege

Questo è un privilegio detenuto da qualsiasi processo che consente l'impersonificazione (ma non la creazione) di qualsiasi token, a condizione che sia possibile ottenere un handle ad esso. Un token privilegiato può essere acquisito da un servizio Windows (DCOM) inducendolo a eseguire l'autenticazione NTLM contro un exploit, consentendo successivamente l'esecuzione di un processo con privilegi di sistema. Questa vulnerabilità può essere sfruttata utilizzando vari strumenti, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede la disabilitazione di winrm), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

È molto simile a **SeImpersonatePrivilege**, utilizzerà il **metodo stesso** per ottenere un token privilegiato.\
Quindi, questo privilegio consente di **assegnare un token primario** a un processo nuovo/sospeso. Con il token di impersonificazione privilegiato è possibile derivare un token primario (DuplicateTokenEx).\
Con il token, è possibile creare un **nuovo processo** con 'CreateProcessAsUser' o creare un processo sospeso e **impostare il token** (in generale, non è possibile modificare il token primario di un processo in esecuzione).

### SeTcbPrivilege

Se hai abilitato questo token, puoi utilizzare **KERB\_S4U\_LOGON** per ottenere un **token di impersonificazione** per qualsiasi altro utente senza conoscere le credenziali, **aggiungere un gruppo arbitrario** (amministratori) al token, impostare il **livello di integrità** del token su "**medio**" e assegnare questo token al **thread corrente** (SetThreadToken).

### SeBackupPrivilege

Il sistema è portato a **concedere tutti i diritti di accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura) con questo privilegio. Viene utilizzato per **leggere gli hash delle password degli account Amministratori locali** dal registro, a seguito del quale, possono essere utilizzati strumenti come "**psexec**" o "**wmicexec**" con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica fallisce in due condizioni: quando l'account Amministratore locale è disabilitato o quando è in atto una policy che rimuove i diritti amministrativi dagli Amministratori locali che si connettono in remoto.\
Puoi **abusare di questo privilegio** con:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* seguendo **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* O come spiegato nella sezione **escalation dei privilegi con gli operatori di backup** di:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Questo privilegio fornisce il permesso di **accesso in scrittura** a qualsiasi file di sistema, indipendentemente dalla lista di controllo degli accessi (ACL) del file. Apre numerose possibilità per l'escalation, inclusa la possibilità di **modificare i servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options, tra le varie altre tecniche.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un permesso potente, particolarmente utile quando un utente possiede la capacità di impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità si basa sulla possibilità di impersonare un token che rappresenta lo stesso utente e il cui livello di integrità non supera quello del processo corrente.

**Punti chiave:**
- **Impersonificazione senza SeImpersonatePrivilege:** È possibile sfruttare SeCreateTokenPrivilege per EoP impersonando token in determinate condizioni.
- **Condizioni per l'impersonificazione del token:** L'impersonificazione riuscita richiede che il token di destinazione appartenga allo stesso utente e abbia un livello di integrità inferiore o uguale al livello di integrità del processo che tenta l'impersonificazione.
- **Creazione e modifica di token di impersonificazione:** Gli utenti possono creare un token di impersonificazione e migliorarlo aggiungendo l'ID di sicurezza (SID) di un gruppo privilegiato.


### SeLoadDriverPrivilege

Questo privilegio consente di **caricare e scaricare i driver dei dispositivi** con la creazione di una voce di registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso diretto in scrittura a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, è necessario utilizzare `HKCU` (HKEY_CURRENT_USER) al suo posto. Tuttavia, per rendere `HKCU` riconoscibile al kernel per la configurazione del driver, è necessario seguire un percorso specifico.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è l'Identificatore Relativo dell'utente corrente. All'interno di `HKCU`, è necessario creare l'intero percorso e impostare due valori:
- `ImagePath`, che è il percorso dell'eseguibile da eseguire
- `Type`, con un valore di `SERVICE_KERNEL_DRIVER` (`0
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Altri modi per sfruttare questo privilegio sono disponibili su [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Questo è simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito di accesso discrezionale esplicito attraverso la fornitura dei diritti di accesso WRITE_OWNER. Il processo prevede di acquisire inizialmente la proprietà della chiave di registro desiderata per scopi di scrittura, per poi modificare il DACL per abilitare le operazioni di scrittura.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Questo privilegio consente di **eseguire il debug di altri processi**, inclusa la lettura e la scrittura nella memoria. Con questo privilegio è possibile utilizzare varie strategie di iniezione di memoria, in grado di eludere la maggior parte degli antivirus e delle soluzioni di prevenzione delle intrusioni dell'host.

#### Dump della memoria

È possibile utilizzare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **acquisire la memoria di un processo**. In particolare, questo può essere applicato al processo **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, che è responsabile per la memorizzazione delle credenziali degli utenti una volta che un utente ha effettuato correttamente l'accesso a un sistema.

Successivamente, è possibile caricare questo dump in mimikatz per ottenere le password:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se vuoi ottenere una shell `NT SYSTEM`, puoi utilizzare:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Verifica dei privilegi

To check the privileges of a user, you can use the following methods:

Per verificare i privilegi di un utente, puoi utilizzare i seguenti metodi:

### 1. Whoami

```plaintext
whoami
```

The `whoami` command displays the current user and group information.

Il comando `whoami` visualizza le informazioni sull'utente e sul gruppo correnti.

### 2. Net user

```plaintext
net user <username>
```

The `net user` command displays detailed information about a specific user, including their group memberships and privileges.

Il comando `net user` visualizza informazioni dettagliate su un utente specifico, inclusi i gruppi di appartenenza e i privilegi.

### 3. Systeminfo

```plaintext
systeminfo
```

The `systeminfo` command displays detailed information about the system, including the current user's privileges.

Il comando `systeminfo` visualizza informazioni dettagliate sul sistema, inclusi i privilegi dell'utente corrente.

### 4. PowerShell

```plaintext
(Get-WmiObject -Class Win32_UserAccount -Filter "Name='<username>'").Caption
```

The PowerShell command above retrieves the username and displays it.

Il comando PowerShell sopra riportato recupera il nome utente e lo visualizza.

### 5. Task Manager

You can also check the privileges of a user using the Task Manager:

Puoi anche verificare i privilegi di un utente utilizzando il Task Manager:

1. Press `Ctrl + Shift + Esc` to open the Task Manager.

2. Go to the "Processes" or "Details" tab.

3. Right-click on a process and select "Go to details" or "Open file location".

4. Right-click on the process again and select "Properties".

5. In the "Properties" window, go to the "Security" tab.

6. The "Group or user names" section displays the user's privileges.

1. Premi `Ctrl + Shift + Esc` per aprire il Task Manager.

2. Vai alla scheda "Processi" o "Dettagli".

3. Fai clic con il pulsante destro del mouse su un processo e seleziona "Vai ai dettagli" o "Apri percorso file".

4. Fai nuovamente clic con il pulsante destro del mouse sul processo e seleziona "Proprietà".

5. Nella finestra "Proprietà", vai alla scheda "Sicurezza".

6. La sezione "Nomi gruppo o utente" visualizza i privilegi dell'utente.
```
whoami /priv
```
I **token che appaiono come Disabilitati** possono essere abilitati, e in realtà è possibile abusare dei token _Abilitati_ e _Disabilitati_.

### Abilita tutti i token

Se hai dei token disabilitati, puoi utilizzare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Cheat sheet completo dei privilegi del token su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), di seguito verranno elencati solo i modi diretti per sfruttare il privilegio per ottenere una sessione di amministratore o leggere file sensibili.

| Privilegio                 | Impatto     | Strumento               | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                            | Osservazioni                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Strumento di terze parti | _"Consentirebbe a un utente di impersonare token e ottenere privilegi di sistema nt utilizzando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                     | Grazie [Aurélien Chalot](https://twitter.com/Defte\_) per l'aggiornamento. Cercherò di riformularlo in qualcosa di più simile a una ricetta al più presto.                                                                                                                                                                      |
| **`SeBackup`**             | **Minaccia** | _**Comandi integrati**_ | Leggere file sensibili con `robocopy /b`                                                                                                                                                                                                                                                                                                          | <p>- Potrebbe essere più interessante se è possibile leggere %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) non è utile quando si tratta di aprire file.<br><br>- Robocopy richiede sia SeBackup che SeRestore per funzionare con il parametro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Strumento di terze parti | Creare token arbitrari, inclusi i diritti di amministratore locale, con `NtCreateToken`.                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicare il token di `lsass.exe`.                                                                                                                                                                                                                                                                                                                | Script da trovare su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Strumento di terze parti | <p>1. Caricare un driver di kernel difettoso come <code>szkg64.sys</code><br>2. Sfruttare la vulnerabilità del driver<br><br>In alternativa, il privilegio può essere utilizzato per scaricare driver correlati alla sicurezza con il comando integrato <code>ftlMC</code>. ad esempio: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilità <code>szkg64</code> è elencata come <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Il codice di exploit <code>szkg64</code> è stato creato da <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco potrebbe essere rilevato da alcuni software antivirus.</p><p>Un metodo alternativo si basa sulla sostituzione dei file binari di servizio memorizzati in "Program Files" utilizzando lo stesso privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                       | <p>L'attacco potrebbe essere rilevato da alcuni software antivirus.</p><p>Un metodo alternativo si basa sulla sostituzione dei file binari di servizio memorizzati in "Program Files" utilizzando lo stesso privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Strumento di terze parti | <p>Manipolare i token per includere i diritti di amministratore locale. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                |

## Riferimento

* Dai un'occhiata a questa tabella che definisce i token di Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Dai un'occhiata a [**questo documento**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) su privesc con i token.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in un'azienda di **sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
