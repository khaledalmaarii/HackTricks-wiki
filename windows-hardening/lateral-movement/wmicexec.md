# WmicExec

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Come funziona spiegato

I processi possono essere aperti su host in cui sono noti il nome utente e la password o l'hash tramite l'uso di WMI. I comandi vengono eseguiti utilizzando WMI tramite Wmiexec, fornendo un'esperienza di shell semi-interattiva.

**dcomexec.py:** Utilizzando diversi endpoint DCOM, questo script offre una shell semi-interattiva simile a wmiexec.py, sfruttando specificamente l'oggetto DCOM ShellBrowserWindow. Attualmente supporta MMC20. Applicazione, finestre della shell e oggetti della finestra del browser. (fonte: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Fondamenti di WMI

### Namespace

Strutturato gerarchicamente come una directory, il contenitore di primo livello di WMI è \root, sotto il quale sono organizzate ulteriori directory, chiamate namespace.
Comandi per elencare i namespace:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Le classi all'interno di uno spazio dei nomi possono essere elencate utilizzando:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classi**

Conoscere il nome di una classe WMI, come win32\_process, e il namespace in cui risiede è fondamentale per qualsiasi operazione WMI.
Comandi per elencare le classi che iniziano con `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocazione di una classe:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metodi

I metodi, che sono una o più funzioni eseguibili delle classi WMI, possono essere eseguiti.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumerazione WMI

### Stato del servizio WMI

Comandi per verificare se il servizio WMI è operativo:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informazioni di sistema e processo

Raccolta di informazioni di sistema e processo tramite WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Per gli attaccanti, WMI è uno strumento potente per enumerare dati sensibili sui sistemi o sui domini.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Interrogazione manuale remota di WMI**

L'identificazione stealthy degli amministratori locali su una macchina remota e degli utenti connessi può essere ottenuta attraverso specifiche interrogazioni di WMI. `wmic` supporta anche la lettura da un file di testo per eseguire comandi su più nodi contemporaneamente.

Per eseguire in remoto un processo tramite WMI, come ad esempio il deploy di un agente Empire, viene utilizzata la seguente struttura di comando, con l'esecuzione riuscita indicata da un valore di ritorno "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Questo processo illustra la capacità di esecuzione remota e di enumerazione del sistema di WMI, evidenziando la sua utilità sia per l'amministrazione di sistema che per il penetration testing.


## Riferimenti
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Strumenti Automatici

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
