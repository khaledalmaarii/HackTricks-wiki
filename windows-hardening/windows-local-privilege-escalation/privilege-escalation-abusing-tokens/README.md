# Abuso dei Token

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Token

Se **non sai cos'è un Token di Accesso Windows**, leggi questa pagina prima di continuare:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Potresti essere in grado di elevare i privilegi abusando dei token che possiedi già**

### SeImpersonatePrivilege

Questo è un privilegio detenuto da qualsiasi processo che consente l'impersonificazione (ma non la creazione) di qualsiasi token, a condizione che se ne possa ottenere un handle. Un token privilegiato può essere acquisito da un servizio Windows (DCOM) inducendolo a eseguire l'autenticazione NTLM contro un exploit, consentendo successivamente l'esecuzione di un processo con privilegi di **SYSTEM**. Questa vulnerabilità può essere sfruttata utilizzando vari strumenti, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede la disabilitazione di winrm), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

È molto simile a **SeImpersonatePrivilege**, utilizzerà lo **stesso metodo** per ottenere un token privilegiato.\
Quindi, questo privilegio consente di **assegnare un token primario** a un processo nuovo/in sospensione. Con il token di impersonificazione privilegiato è possibile derivare un token primario (DuplicateTokenEx).\
Con il token, è possibile creare un **nuovo processo** con 'CreateProcessAsUser' o creare un processo sospeso e **impostare il token** (in generale, non è possibile modificare il token primario di un processo in esecuzione).

### SeTcbPrivilege

Se hai abilitato questo token, puoi utilizzare **KERB\_S4U\_LOGON** per ottenere un **token di impersonificazione** per qualsiasi altro utente senza conoscere le credenziali, **aggiungere un gruppo arbitrario** (amministratori) al token, impostare il **livello di integrità** del token a "**medio**" e assegnare questo token al **thread corrente** (SetThreadToken).

### SeBackupPrivilege

Il sistema è portato a **concedere tutti i diritti di accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura) con questo privilegio. Viene utilizzato per **leggere gli hash delle password degli account Amministratori locali** dal registro, a seguito del quale, strumenti come "**psexec**" o "**wmicexec**" possono essere utilizzati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica fallisce in due condizioni: quando l'account Amministratore locale è disabilitato, o quando è in atto una policy che rimuove i diritti amministrativi dagli Amministratori locali che si connettono in remoto.\
Puoi **abusare di questo privilegio** con:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* seguendo **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* O come spiegato nella sezione **elevare i privilegi con gli Operatori di Backup** di:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Il permesso di **accesso in scrittura** a qualsiasi file di sistema, indipendentemente dalla lista di controllo degli accessi (ACL) del file, è fornito da questo privilegio. Apre numerose possibilità di escalation, inclusa la capacità di **modificare servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options tra varie altre tecniche.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un permesso potente, particolarmente utile quando un utente possiede la capacità di impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità si basa sulla possibilità di impersonare un token che rappresenta lo stesso utente e il cui livello di integrità non supera quello del processo corrente.

**Punti Chiave:**
- **Impersonificazione senza SeImpersonatePrivilege:** È possibile sfruttare SeCreateTokenPrivilege per l'EoP impersonando token in condizioni specifiche.
- **Condizioni per l'Impersonificazione del Token:** L'impersonificazione riuscita richiede che il token di destinazione appartenga allo stesso utente e abbia un livello di integrità inferiore o uguale a quello del processo che tenta l'impersonificazione.
- **Creazione e Modifica di Token di Impersonificazione:** Gli utenti possono creare un token di impersonificazione e potenziarlo aggiungendo l'SID (Identificatore di Sicurezza) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio consente di **caricare e scaricare i driver dei dispositivi** con la creazione di una voce di registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso in scrittura diretta a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, è necessario utilizzare `HKCU` (HKEY_CURRENT_USER) al suo posto. Tuttavia, per rendere `HKCU` riconoscibile al kernel per la configurazione del driver, è necessario seguire un percorso specifico.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è l'Identificatore Relativo dell'utente corrente. All'interno di `HKCU`, è necessario creare l'intero percorso e impostare due valori:
- `ImagePath`, che è il percorso del binario da eseguire
- `Type`, con un valore di `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passaggi da Seguire:**
1. Accedere a `HKCU` anziché a `HKLM` a causa dell'accesso in scrittura limitato.
2. Creare il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` all'interno di `HKCU`, dove `<RID>` rappresenta l'Identificatore Relativo dell'utente corrente.
3. Impostare `ImagePath` sul percorso di esecuzione del binario.
4. Assegnare il `Type` come `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Altri modi per abusare di questo privilegio sono disponibili in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Questo è simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito di accesso discrezionale esplicito attraverso la fornitura dei diritti di accesso WRITE_OWNER. Il processo prevede prima di tutto di garantire la proprietà della chiave di registro prevista per scopi di scrittura, per poi modificare il DACL per abilitare le operazioni di scrittura.
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

Questo privilegio permette di **debuggare altri processi**, inclusa la lettura e scrittura in memoria. Diverse strategie di iniezione di memoria, capaci di eludere la maggior parte degli antivirus e delle soluzioni di prevenzione delle intrusioni degli host, possono essere utilizzate con questo privilegio.

#### Dump della memoria

Potresti utilizzare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **catturare la memoria di un processo**. In particolare, questo può essere applicato al processo **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, che è responsabile di memorizzare le credenziali degli utenti una volta che un utente ha effettuato correttamente l'accesso a un sistema.

Successivamente puoi caricare questo dump in mimikatz per ottenere le password:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se desideri ottenere una shell `NT SYSTEM` potresti utilizzare:

- ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
- ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1 (Script Powershell)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Verifica dei privilegi
```
whoami /priv
```
I **token che appaiono come Disabilitati** possono essere abilitati, è possibile abusare dei token _Abilitati_ e _Disabilitati_.

### Abilita tutti i token

Se hai token disabilitati, puoi utilizzare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Elenco completo dei privilegi del token su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), di seguito verranno elencati solo i modi diretti per sfruttare il privilegio per ottenere una sessione di amministratore o leggere file sensibili.

| Privilegio                 | Impatto      | Strumento               | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                            | Osservazioni                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Strumento di terze parti | _"Consentirebbe a un utente di impersonare token e ottenere privilegi di sistema nt utilizzando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Grazie a [Aurélien Chalot](https://twitter.com/Defte\_) per l'aggiornamento. Cercherò di riformularlo in qualcosa di più simile a una ricetta presto.                                                                                                                                                                                        |
| **`SeBackup`**             | **Minaccia**  | _**Comandi integrati**_ | Leggere file sensibili con `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Potrebbe essere più interessante se si possono leggere %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) non è utile quando si tratta di file aperti.<br><br>- Robocopy richiede sia SeBackup che SeRestore per funzionare con il parametro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Strumento di terze parti | Creare token arbitrari inclusi i diritti di amministratore locale con `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicare il token di `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script da trovare su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Strumento di terze parti | <p>1. Caricare un driver kernel difettoso come <code>szkg64.sys</code><br>2. Sfruttare la vulnerabilità del driver<br><br>In alternativa, il privilegio può essere utilizzato per scaricare driver correlati alla sicurezza con il comando integrato <code>ftlMC</code>. ad es.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilità di <code>szkg64</code> è elencata come <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Il codice di exploit di <code>szkg64</code> è stato creato da <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco potrebbe essere rilevato da alcuni software AV.</p><p>Il metodo alternativo si basa sulla sostituzione dei binari di servizio memorizzati in "Program Files" utilizzando lo stesso privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                       | <p>L'attacco potrebbe essere rilevato da alcuni software AV.</p><p>Il metodo alternativo si basa sulla sostituzione dei binari di servizio memorizzati in "Program Files" utilizzando lo stesso privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Strumento di terze parti | <p>Manipolare i token per includere i diritti di amministratore locale. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Riferimenti

* Dai un'occhiata a questa tabella che definisce i token di Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Dai un'occhiata a [**questo documento**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sull'elevazione dei privilegi con i token.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
