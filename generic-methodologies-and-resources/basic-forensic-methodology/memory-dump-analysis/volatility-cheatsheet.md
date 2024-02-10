# Volatility - CheatSheet

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

Se vuoi qualcosa di **veloce e pazzo** che lancerà diversi plugin di Volatility in parallelo, puoi utilizzare: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Installazione

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
#### Metodo1

```
volatility2 -f memory_dump.vmem imageinfo
```

Questo comando restituisce informazioni sull'immagine del dump di memoria, come l'architettura, il sistema operativo e la versione del kernel.

{% endtab %}
{% tab title="Method2" %}

#### Metodo2

```
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 pslist
```

Questo comando elenca tutti i processi attivi nel dump di memoria.

{% endtab %}
{% tab title="Method3" %}

#### Metodo3

```
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 pstree
```

Questo comando visualizza la struttura ad albero dei processi nel dump di memoria.

{% endtab %}
{% tab title="Method4" %}

#### Metodo4

```
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 cmdline
```

Questo comando mostra gli argomenti della riga di comando per ogni processo nel dump di memoria.

{% endtab %}
{% tab title="Method5" %}

#### Metodo5

```
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 dlllist
```

Questo comando elenca tutte le DLL caricate per ogni processo nel dump di memoria.

{% endtab %}
{% endtabs %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% tab title="Metodo 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Comandi di Volatility

Accedi al documento ufficiale in [Riferimento dei comandi di Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Una nota su plugin "list" vs "scan"

Volatility ha due approcci principali ai plugin, che a volte si riflettono nei loro nomi. I plugin "list" cercheranno di navigare attraverso le strutture del kernel di Windows per recuperare informazioni come i processi (individuare e scorrere la lista collegata delle strutture `_EPROCESS` in memoria), le handle del sistema operativo (individuare e elencare la tabella delle handle, dereferenziare eventuali puntatori trovati, ecc). Più o meno si comportano come farebbe l'API di Windows se richiesto, ad esempio, di elencare i processi.

Ciò rende i plugin "list" abbastanza veloci, ma altrettanto vulnerabili all'API di Windows alla manipolazione da parte di malware. Ad esempio, se il malware utilizza DKOM per scollegare un processo dalla lista collegata `_EPROCESS`, non apparirà nel Task Manager e nemmeno nella pslist.

I plugin "scan", d'altra parte, adotteranno un approccio simile a quello di estrarre la memoria per le cose che potrebbero avere senso quando dereferenziate come strutture specifiche. Ad esempio, `psscan` leggerà la memoria e cercherà di creare oggetti `_EPROCESS` da essa (utilizza la scansione del pool-tag, che cerca stringhe di 4 byte che indicano la presenza di una struttura di interesse). Il vantaggio è che può individuare processi che sono usciti e anche se il malware manomette la lista collegata `_EPROCESS`, il plugin troverà comunque la struttura che giace in memoria (poiché deve ancora esistere per far funzionare il processo). Lo svantaggio è che i plugin "scan" sono un po' più lenti dei plugin "list" e talvolta possono produrre falsi positivi (un processo che è uscito troppo tempo fa e ha avuto parti della sua struttura sovrascritte da altre operazioni).

Da: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profili di sistema operativo

### Volatility3

Come spiegato nel file readme, è necessario inserire la **tabella dei simboli del sistema operativo** che si desidera supportare all'interno di _volatility3/volatility/symbols_.\
I pacchetti delle tabelle dei simboli per i vari sistemi operativi sono disponibili per **scaricare** su:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profilo esterno

È possibile ottenere l'elenco dei profili supportati eseguendo:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Se vuoi utilizzare un **nuovo profilo che hai scaricato** (ad esempio uno per Linux), devi creare la seguente struttura di cartelle: _plugins/overlays/linux_ e mettere all'interno di questa cartella il file zip contenente il profilo. Successivamente, ottieni il numero dei profili utilizzando:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Puoi **scaricare i profili di Linux e Mac** da [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Nel frammento precedente puoi vedere che il profilo si chiama `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, e puoi usarlo per eseguire qualcosa come:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Scoprire il Profilo

```bash
volatility -f <dumpfile> imageinfo
```

Questo comando restituisce informazioni di base sul dump di memoria, come l'architettura, il sistema operativo e la versione del kernel. Queste informazioni sono utili per selezionare il profilo corretto per l'analisi successiva.

#### Analisi dei Processi

```bash
volatility -f <dumpfile> --profile=<profile> pslist
```

Questo comando elenca tutti i processi presenti nel dump di memoria, fornendo informazioni come il PID (Process ID), il nome del processo e il PID del processo padre. Queste informazioni possono essere utili per identificare processi sospetti o potenzialmente dannosi.

#### Analisi delle Connessioni di Rete

```bash
volatility -f <dumpfile> --profile=<profile> netscan
```

Questo comando elenca tutte le connessioni di rete attive nel dump di memoria, fornendo informazioni come gli indirizzi IP e le porte associate. Queste informazioni possono essere utili per individuare attività di rete sospette o potenzialmente dannose.

#### Analisi delle DLL Caricate

```bash
volatility -f <dumpfile> --profile=<profile> dlllist
```

Questo comando elenca tutte le DLL (Dynamic Link Libraries) caricate nei processi presenti nel dump di memoria. Queste informazioni possono essere utili per individuare DLL sospette o potenzialmente dannose.

#### Analisi delle Connessioni di Rete

```bash
volatility -f <dumpfile> --profile=<profile> connscan
```

Questo comando elenca tutte le connessioni di rete attive nel dump di memoria, fornendo informazioni come gli indirizzi IP e le porte associate. Queste informazioni possono essere utili per individuare attività di rete sospette o potenzialmente dannose.

#### Analisi delle Attività di Registrazione

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K "ControlSet001\Control\Windows"
```

Questo comando visualizza le informazioni relative alle attività di registrazione nel dump di memoria, come la data e l'ora dell'ultima accensione del sistema. Queste informazioni possono essere utili per determinare il periodo di attività del sistema.

#### Analisi delle Attività di Esecuzione

```bash
volatility -f <dumpfile> --profile=<profile> cmdline
```

Questo comando elenca tutti i comandi eseguiti nel dump di memoria, fornendo informazioni come il PID del processo e il comando eseguito. Queste informazioni possono essere utili per individuare attività sospette o potenzialmente dannose.

#### Analisi dei File Aperti

```bash
volatility -f <dumpfile> --profile=<profile> handles
```

Questo comando elenca tutti i file aperti nel dump di memoria, fornendo informazioni come il PID del processo, il nome del file e il tipo di accesso. Queste informazioni possono essere utili per individuare file sospetti o potenzialmente dannosi.

#### Analisi delle Attività di Registrazione

```bash
volatility -f <dumpfile> --profile=<profile> printkey -K "ControlSet001\Control\Windows"
```

Questo comando visualizza le informazioni relative alle attività di registrazione nel dump di memoria, come la data e l'ora dell'ultima accensione del sistema. Queste informazioni possono essere utili per determinare il periodo di attività del sistema.

#### Analisi delle Attività di Esecuzione

```bash
volatility -f <dumpfile> --profile=<profile> cmdline
```

Questo comando elenca tutti i comandi eseguiti nel dump di memoria, fornendo informazioni come il PID del processo e il comando eseguito. Queste informazioni possono essere utili per individuare attività sospette o potenzialmente dannose.

#### Analisi dei File Aperti

```bash
volatility -f <dumpfile> --profile=<profile> handles
```

Questo comando elenca tutti i file aperti nel dump di memoria, fornendo informazioni come il PID del processo, il nome del file e il tipo di accesso. Queste informazioni possono essere utili per individuare file sospetti o potenzialmente dannosi.
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Differenze tra imageinfo e kdbgscan**

[**Da qui**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): A differenza di imageinfo che fornisce solo suggerimenti di profilo, **kdbgscan** è progettato per identificare positivamente il profilo corretto e l'indirizzo KDBG corretto (se ce ne sono più di uno). Questo plugin scansiona le firme di KDBGHeader collegate ai profili di Volatility e applica controlli di coerenza per ridurre i falsi positivi. La verbosità dell'output e il numero di controlli di coerenza che possono essere eseguiti dipendono dal fatto che Volatility possa trovare un DTB, quindi se conosci già il profilo corretto (o se hai un suggerimento di profilo da imageinfo), assicurati di utilizzarlo.

Fai sempre attenzione al **numero di processi che kdbgscan ha trovato**. A volte imageinfo e kdbgscan possono trovare **più di un** profilo **adatto**, ma solo quello **valido avrà qualche processo correlato** (Questo perché per estrarre i processi è necessario l'indirizzo KDBG corretto).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

Il **blocco del debugger del kernel**, chiamato **KDBG** da Volatility, è fondamentale per le attività forensi eseguite da Volatility e vari debugger. Identificato come `KdDebuggerDataBlock` e di tipo `_KDDEBUGGER_DATA64`, contiene riferimenti essenziali come `PsActiveProcessHead`. Questo riferimento specifico punta all'inizio della lista dei processi, consentendo l'elenco di tutti i processi, il che è fondamentale per un'analisi approfondita della memoria.

## Informazioni sul sistema operativo
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Il plugin `banners.Banners` può essere utilizzato in **vol3 per cercare i banner di Linux** nel dump.

## Hash/Password

Estrai gli hash SAM, le [credenziali memorizzate nella cache del dominio](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) e i [segnreti lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo -p <pid>`: This command displays information about the virtual address space for a specific process.
- `volatility -f <memory_dump> vadtree -p <pid>`: This command displays the virtual address space tree for a specific process.
- `volatility -f <memory_dump> memdump -p <pid> -D <output_directory>`: This command dumps the memory of a specific process to a file.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the contents of a specific registry key in the memory dump.
- `volatility -f <memory_dump> dumpregistry -D <output_directory>`: This command dumps the entire registry from the memory dump to a file.

## Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, simply specify it with the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [plugin_options]
```

Some popular Volatility plugins include:

- `malfind`: Scans the memory dump for potentially malicious code.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Extracts files from the memory dump.
- `hivelist`: Lists the registry hives in the memory dump.
- `printkey`: Displays the contents of a specific registry key in the memory dump.

## Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can extract valuable information from memory dumps and perform in-depth forensic analysis.
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Dump di memoria

Il dump di memoria di un processo estrarrà **tutto** lo stato attuale del processo. Il modulo **procdump** estrarrà solo il **codice**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Processi

### Elencare i processi

Cerca processi **sospetti** (per nome) o **inesperati** (ad esempio un cmd.exe come figlio di iexplorer.exe).\
Potrebbe essere interessante **confrontare** il risultato di pslist con quello di psscan per identificare processi nascosti.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### Dump proc

{% tabs %}
{% tab title="vol3" %}Volatility è uno strumento potente per l'analisi di dump di memoria. Può essere utilizzato per estrarre informazioni preziose dai dump di memoria, come processi in esecuzione, connessioni di rete, registri di sistema e altro ancora. Di seguito sono riportati alcuni comandi di Volatility comuni per l'analisi dei dump di memoria:

- `imageinfo`: restituisce informazioni sull'immagine del dump di memoria, come l'architettura, il sistema operativo e la versione.
- `pslist`: elenca tutti i processi in esecuzione nel dump di memoria.
- `pstree`: visualizza una rappresentazione ad albero dei processi nel dump di memoria.
- `dlllist`: elenca tutte le DLL caricate dai processi nel dump di memoria.
- `handles`: elenca tutti i gestori di oggetti aperti dai processi nel dump di memoria.
- `filescan`: esegue una scansione dei file nel dump di memoria.
- `netscan`: esegue una scansione delle connessioni di rete nel dump di memoria.
- `cmdline`: visualizza gli argomenti della riga di comando per i processi nel dump di memoria.
- `malfind`: cerca indicatori di malware nel dump di memoria.
- `apihooks`: elenca tutte le funzioni API modificate dai processi nel dump di memoria.

Questi sono solo alcuni dei comandi disponibili in Volatility. Puoi consultare la documentazione ufficiale di Volatility per ulteriori informazioni su come utilizzare questi comandi e altri strumenti disponibili.
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Riga di comando

È stato eseguito qualcosa di sospetto?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo -p <pid>`: This command displays information about the virtual address space for a specific process.
- `volatility -f <memory_dump> vadtree -p <pid>`: This command displays the virtual address space tree for a specific process.
- `volatility -f <memory_dump> memdump -p <pid> -D <output_directory>`: This command dumps the memory of a specific process to a file.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the contents of a specific registry key in the memory dump.
- `volatility -f <memory_dump> dumpregistry -D <output_directory>`: This command dumps the entire registry from the memory dump to a file.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.

To use a plugin, simply append the plugin name to the Volatility command. For example:

`volatility -f <memory_dump> timeliner`

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

I comandi eseguiti in `cmd.exe` sono gestiti da **`conhost.exe`** (o `csrss.exe` nei sistemi precedenti a Windows 7). Ciò significa che se **`cmd.exe`** viene terminato da un attaccante prima di ottenere un dump di memoria, è comunque possibile recuperare la cronologia dei comandi della sessione dalla memoria di **`conhost.exe`**. Per fare ciò, se viene rilevata un'attività insolita nei moduli della console, dovrebbe essere effettuato un dump della memoria del processo **`conhost.exe`** associato. Successivamente, cercando **stringhe** all'interno di questo dump, è possibile estrarre potenzialmente le righe di comando utilizzate nella sessione.

### Ambiente

Ottieni le variabili di ambiente di ogni processo in esecuzione. Potrebbero esserci alcuni valori interessanti.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### Privilegi del token

Controlla i token dei privilegi nei servizi inaspettati.\
Potrebbe essere interessante elencare i processi che utilizzano un token privilegiato.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Controlla ogni SSID posseduto da un processo.\
Potrebbe essere interessante elencare i processi che utilizzano un SID con privilegi (e i processi che utilizzano un SID di servizio).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo -p <pid>`: This command displays information about the virtual address space for a specific process.
- `volatility -f <memory_dump> vadtree -p <pid>`: This command displays the virtual address space tree for a specific process.
- `volatility -f <memory_dump> memdump -p <pid> -D <output_directory>`: This command dumps the memory of a specific process to a file.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the contents of a specific registry key in the memory dump.
- `volatility -f <memory_dump> dumpregistry -D <output_directory>`: This command dumps the entire registry from the memory dump to a file.

## Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, simply specify it with the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [plugin_options]
```

Some popular Volatility plugins include:

- `malfind`: Scans the memory dump for potentially malicious code.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Extracts files from the memory dump.
- `hivelist`: Lists the registry hives in the memory dump.
- `printkey`: Displays the contents of a specific registry key in the memory dump.

## Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can gain valuable insights into the memory dump and uncover potential security issues. Remember to always use Volatility responsibly and ethically.
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Gestori

Utile sapere a quali altri file, chiavi, thread, processi... un **processo ha un gestore** (ha aperto)

{% tabs %}
{% tab title="vol3" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo -p <pid>`: This command displays information about the virtual address space for a specific process.
- `volatility -f <memory_dump> vadtree -p <pid>`: This command displays the virtual address space tree for a specific process.
- `volatility -f <memory_dump> memdump -p <pid> -D <output_directory>`: This command dumps the memory of a specific process to a file.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the contents of a specific registry key in the memory dump.
- `volatility -f <memory_dump> dumpregistry -D <output_directory>`: This command dumps the entire registry from the memory dump to a file.

## Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, simply specify it with the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [plugin_options]
```

Some popular Volatility plugins include:

- `malfind`: Scans the memory dump for potentially malicious code.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Extracts files from the memory dump.
- `hivelist`: Lists the registry hives in the memory dump.
- `printkey`: Displays the contents of a specific registry key in the memory dump.

## Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can extract valuable information from memory dumps and perform in-depth forensic analysis.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}

#### List loaded DLLs

```bash
volatility -f <memory_dump> --profile=<profile> dlllist
```

#### Dump DLL

```bash
volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory> -b <base_address>
```

#### Find DLL by name

```bash
volatility -f <memory_dump> --profile=<profile> dlllist | grep <dll_name>
```

#### Find DLL by process

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>
```

#### Find DLL by module

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <module_name>
```

#### Find DLL by base address

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <base_address>
```

#### Find DLL by size

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <size>
```

#### Find DLL by path

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <path>
```

#### Find DLL by timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -t <timestamp>
```

#### Find DLL by checksum

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <checksum>
```

#### Find DLL by description

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <description>
```

#### Find DLL by company

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <company>
```

#### Find DLL by product

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <product>
```

#### Find DLL by version

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -v <version>
```

#### Find DLL by language

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <language>
```

#### Find DLL by original filename

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <original_filename>
```

#### Find DLL by internal name

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <internal_name>
```

#### Find DLL by legal copyright

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <legal_copyright>
```

#### Find DLL by legal trademark

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <legal_trademark>
```

#### Find DLL by product version

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <product_version>
```

#### Find DLL by file description

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -y <file_description>
```

#### Find DLL by file version

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -z <file_version>
```

#### Find DLL by comments

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <comments>
```

#### Find DLL by private build

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -u <private_build>
```

#### Find DLL by special build

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -w <special_build>
```

#### Find DLL by product name

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <product_name>
```

#### Find DLL by file size

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_size>
```

#### Find DLL by file path

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_path>
```

#### Find DLL by file extension

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_extension>
```

#### Find DLL by file attributes

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_attributes>
```

#### Find DLL by file creation time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <file_creation_time>
```

#### Find DLL by file modification time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_modification_time>
```

#### Find DLL by file access time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_access_time>
```

#### Find DLL by file change time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_change_time>
```

#### Find DLL by file attributes change time

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_attributes_change_time>
```

#### Find DLL by file creation timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <file_creation_timestamp>
```

#### Find DLL by file modification timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -t <file_modification_timestamp>
```

#### Find DLL by file access timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <file_access_timestamp>
```

#### Find DLL by file change timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_change_timestamp>
```

#### Find DLL by file attributes change timestamp

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_attributes_change_timestamp>
```

#### Find DLL by file creation date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_creation_date>
```

#### Find DLL by file modification date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_modification_date>
```

#### Find DLL by file access date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_access_date>
```

#### Find DLL by file change date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_change_date>
```

#### Find DLL by file attributes change date

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_attributes_change_date>
```

#### Find DLL by file creation datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_creation_datetime>
```

#### Find DLL by file modification datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_modification_datetime>
```

#### Find DLL by file access datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_access_datetime>
```

#### Find DLL by file change datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <file_change_datetime>
```

#### Find DLL by file attributes change datetime

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <file_attributes_change_datetime>
```

#### Find DLL by file creation year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_creation_year>
```

#### Find DLL by file modification year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <file_modification_year>
```

#### Find DLL by file access year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_access_year>
```

#### Find DLL by file change year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_change_year>
```

#### Find DLL by file attributes change year

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_attributes_change_year>
```

#### Find DLL by file creation month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_creation_month>
```

#### Find DLL by file modification month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_modification_month>
```

#### Find DLL by file access month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_access_month>
```

#### Find DLL by file change month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_change_month>
```

#### Find DLL by file attributes change month

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_attributes_change_month>
```

#### Find DLL by file creation day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_creation_day>
```

#### Find DLL by file modification day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_modification_day>
```

#### Find DLL by file access day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_access_day>
```

#### Find DLL by file change day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <file_change_day>
```

#### Find DLL by file attributes change day

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <file_attributes_change_day>
```

#### Find DLL by file creation hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_creation_hour>
```

#### Find DLL by file modification hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -t <file_modification_hour>
```

#### Find DLL by file access hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -u <file_access_hour>
```

#### Find DLL by file change hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -v <file_change_hour>
```

#### Find DLL by file attributes change hour

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -w <file_attributes_change_hour>
```

#### Find DLL by file creation minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_creation_minute>
```

#### Find DLL by file modification minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -y <file_modification_minute>
```

#### Find DLL by file access minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -z <file_access_minute>
```

#### Find DLL by file change minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_change_minute>
```

#### Find DLL by file attributes change minute

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <file_attributes_change_minute>
```

#### Find DLL by file creation second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <file_creation_second>
```

#### Find DLL by file modification second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_modification_second>
```

#### Find DLL by file access second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <file_access_second>
```

#### Find DLL by file change second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_change_second>
```

#### Find DLL by file attributes change second

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_attributes_change_second>
```

#### Find DLL by file creation millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_creation_millisecond>
```

#### Find DLL by file modification millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_modification_millisecond>
```

#### Find DLL by file access millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_access_millisecond>
```

#### Find DLL by file change millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_change_millisecond>
```

#### Find DLL by file attributes change millisecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -l <file_attributes_change_millisecond>
```

#### Find DLL by file creation microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -m <file_creation_microsecond>
```

#### Find DLL by file modification microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -n <file_modification_microsecond>
```

#### Find DLL by file access microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -o <file_access_microsecond>
```

#### Find DLL by file change microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -p <file_change_microsecond>
```

#### Find DLL by file attributes change microsecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -q <file_attributes_change_microsecond>
```

#### Find DLL by file creation nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -r <file_creation_nanosecond>
```

#### Find DLL by file modification nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -s <file_modification_nanosecond>
```

#### Find DLL by file access nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -t <file_access_nanosecond>
```

#### Find DLL by file change nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -u <file_change_nanosecond>
```

#### Find DLL by file attributes change nanosecond

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -v <file_attributes_change_nanosecond>
```

#### Find DLL by file creation timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -w <file_creation_timezone>
```

#### Find DLL by file modification timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -x <file_modification_timezone>
```

#### Find DLL by file access timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -y <file_access_timezone>
```

#### Find DLL by file change timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -z <file_change_timezone>
```

#### Find DLL by file attributes change timezone

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -a <file_attributes_change_timezone>
```

#### Find DLL by file creation offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -b <file_creation_offset>
```

#### Find DLL by file modification offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -c <file_modification_offset>
```

#### Find DLL by file access offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -d <file_access_offset>
```

#### Find DLL by file change offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -e <file_change_offset>
```

#### Find DLL by file attributes change offset

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -f <file_attributes_change_offset>
```

#### Find DLL by file creation offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -g <file_creation_offset_hours>
```

#### Find DLL by file modification offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -h <file_modification_offset_hours>
```

#### Find DLL by file access offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -i <file_access_offset_hours>
```

#### Find DLL by file change offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -j <file_change_offset_hours>
```

#### Find DLL by file attributes change offset hours

```bash
volatility -f <memory_dump> --profile=<profile> dlllist -k <file_attributes_change_offset_hours>
```

#### Find DLL by file creation offset minutes

```bash
volatility
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo -p <pid>`: This command displays information about the virtual address space for a specific process.
- `volatility -f <memory_dump> vadtree -p <pid>`: This command displays the virtual address space tree for a specific process.
- `volatility -f <memory_dump> memdump -p <pid> -D <output_directory>`: This command dumps the memory of a specific process to a file.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the contents of a specific registry key in the memory dump.
- `volatility -f <memory_dump> dumpregistry -D <output_directory>`: This command dumps the registry hives in the memory dump to files.

### Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, simply specify it with the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [plugin_options]
```

Some popular Volatility plugins include:

- `malfind`: Scans the memory dump for potentially malicious code.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Dumps files from the memory dump.
- `hivelist`: Lists the registry hives in the memory dump.
- `printkey`: Displays the contents of a specific registry key in the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can extract valuable information from memory dumps and perform in-depth forensic analysis.
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Stringhe per processi

Volatility ci permette di verificare a quale processo appartiene una stringa.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Inoltre, consente di cercare stringhe all'interno di un processo utilizzando il modulo yarascan:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the following command to install Volatility:

```bash
python setup.py install
```

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility imageinfo`: This command displays information about the memory image, such as the operating system version, architecture, and profile.
- `volatility pslist`: This command lists all running processes in the memory image.
- `volatility psscan`: This command scans for processes in the memory image.
- `volatility pstree`: This command displays the process tree in the memory image.
- `volatility dlllist`: This command lists all loaded DLLs in the memory image.
- `volatility handles`: This command lists all open handles in the memory image.
- `volatility filescan`: This command scans for file objects in the memory image.
- `volatility cmdline`: This command displays the command-line arguments of processes in the memory image.
- `volatility netscan`: This command scans for network connections in the memory image.
- `volatility connections`: This command displays information about network connections in the memory image.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility malfind`: This command scans for injected code and malicious processes in the memory image.
- `volatility apihooks`: This command displays information about API hooks in the memory image.
- `volatility callbacks`: This command displays information about callback functions in the memory image.
- `volatility modscan`: This command scans for kernel modules in the memory image.
- `volatility svcscan`: This command scans for Windows services in the memory image.
- `volatility driverirp`: This command displays information about driver IRPs in the memory image.
- `volatility printkey`: This command displays the contents of a registry key in the memory image.
- `volatility hivelist`: This command lists all registry hives in the memory image.
- `volatility hashdump`: This command dumps the password hashes from the memory image.

## Memory Analysis Tips

Here are some tips for conducting memory analysis using Volatility:

- Always use the correct profile for the memory image. The profile specifies the operating system version and architecture.
- Use multiple plugins to gather as much information as possible. Different plugins provide different insights into the memory image.
- Compare the output of different plugins to cross-reference information and identify anomalies.
- Use the `--output-file` option to save the output of a command to a file for further analysis.
- Use the `--profile` option to specify the profile for a specific command, if different from the default profile.

## Additional Resources

Here are some additional resources for learning more about memory analysis and using Volatility:

- Volatility official documentation: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)
- Volatility cheat sheet: [https://github.com/sans-dfir/sift-cheatsheet/blob/master/cheatsheets/volatility-cheatsheet.pdf](https://github.com/sans-dfir/sift-cheatsheet/blob/master/cheatsheets/volatility-cheatsheet.pdf)
- Volatility plugins repository: [https://github.com/volatilityfoundation/community](https://github.com/volatilityfoundation/community)

Happy memory analysis with Volatility!
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** tiene traccia dei programmi che esegui utilizzando una funzionalità nel registro chiamata **chiavi UserAssist**. Queste chiavi registrano quante volte ogni programma viene eseguito e quando è stato eseguito l'ultima volta.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for injected code or malware.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the values and subkeys of a specific registry key.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> hashdump -s <system_hive> -y <sam_hive>`: This command dumps the password hashes from the SAM database.

### Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, you can use the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [options]
```

Some popular Volatility plugins include:

- `malfind`: Scans the memory dump for injected code or malware.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Dumps files from the memory dump.
- `yarascan`: Scans the memory dump using YARA rules.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs) in the memory dump.

### Volatility Profiles

Volatility uses profiles to determine the operating system and architecture of the memory dump. You can specify a profile using the `-p` option followed by the profile name. For example:

```
volatility -f <memory_dump> -p <profile_name> [command]
```

Some common Volatility profiles include:

- `WinXPSP2x86`: Windows XP SP2 (32-bit)
- `Win7SP1x64`: Windows 7 SP1 (64-bit)
- `Win10x64`: Windows 10 (64-bit)

### Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can extract valuable information from memory dumps and perform in-depth forensic analysis.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Servizi

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository.
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python vol.py` to verify that Volatility is installed correctly.

### Basic Volatility Commands

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `cmdline`: Displays command line arguments.
- `filescan`: Scans for file objects in memory.
- `netscan`: Scans for network connections.
- `connections`: Lists open network connections.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Dumps files from memory.
- `dumpregistry`: Dumps registry hives.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.
- `privs`: Lists process privileges.
- `svcscan`: Scans for Windows services.
- `modscan`: Scans for loaded kernel modules.
- `ssdt`: Displays the System Service Descriptor Table.
- `driverirp`: Lists IRP handlers for drivers.
- `idt`: Displays the Interrupt Descriptor Table.
- `gdt`: Displays the Global Descriptor Table.
- `callbacks`: Lists registered callbacks.
- `ssdt`: Displays the System Service Descriptor Table.
- `driverirp`: Lists IRP handlers for drivers.
- `idt`: Displays the Interrupt Descriptor Table.
- `gdt`: Displays the Global Descriptor Table.
- `callbacks`: Lists registered callbacks.

### Memory Analysis Techniques

- **Process Analysis**: Analyzing running processes to identify malicious activity or suspicious behavior.
- **DLL Analysis**: Analyzing loaded DLLs to identify malicious or suspicious code.
- **Network Analysis**: Analyzing network connections and traffic to identify malicious or suspicious activity.
- **File Analysis**: Analyzing files in memory to identify malicious or suspicious files.
- **Registry Analysis**: Analyzing registry hives to identify malicious or suspicious entries.
- **Malware Analysis**: Analyzing malware artifacts in memory to understand their behavior and capabilities.

### Memory Analysis Frameworks

- **Volatility**: A popular open-source memory forensics framework.
- **Rekall**: Another open-source memory forensics framework.
- **Mandiant Redline**: A commercial memory forensics tool.
- **WinDbg**: A Windows kernel debugger that can be used for memory analysis.
- **GDB**: A GNU Project debugger that can be used for memory analysis on Linux systems.

### Memory Analysis Tips

- Always work on a copy of the memory image to avoid accidental modifications.
- Use multiple memory analysis tools to cross-validate your findings.
- Document your analysis process and findings to maintain a clear record.
- Stay up-to-date with the latest memory analysis techniques and tools.
- Join online communities and forums to learn from and collaborate with other memory analysts.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Rekall Documentation](https://www.rekall-forensic.com/docs/)
- [Mandiant Redline](https://www.fireeye.com/services/freeware/redline.html)
- [WinDbg Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
- [GDB Documentation](https://www.gnu.org/software/gdb/documentation/)

### References

- [Volatility Cheat Sheet](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage)
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Rete

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python vol.py` to verify that Volatility is installed correctly.

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `imageinfo`: This command displays information about the memory image, such as the operating system version and architecture.
- `pslist`: This command lists all running processes in the memory image.
- `pstree`: This command displays the process tree, showing the parent-child relationships between processes.
- `dlllist`: This command lists all loaded DLLs in the memory image.
- `handles`: This command lists all open handles in the memory image.
- `filescan`: This command scans the memory image for file artifacts, such as file headers and file names.
- `dumpfiles`: This command extracts files from the memory image.
- `malfind`: This command scans the memory image for common malware indicators.
- `cmdscan`: This command scans the memory image for command-line artifacts, such as executed commands.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `mbrparser`: This command parses the Master Boot Record (MBR) from the memory image.
- `ssdt`: This command displays the System Service Descriptor Table (SSDT) from the memory image.
- `driverscan`: This command scans the memory image for loaded drivers.
- `modscan`: This command scans the memory image for loaded kernel modules.
- `vadinfo`: This command displays information about the Virtual Address Descriptors (VADs) in the memory image.
- `vaddump`: This command dumps the memory contents of a specific VAD.
- `vadtree`: This command displays the VAD tree, showing the hierarchical relationships between VADs.
- `vadwalk`: This command walks the VAD tree and displays the memory regions mapped by each VAD.
- `memmap`: This command displays the memory map of the memory image.

## Volatility Plugins

Volatility also supports plugins, which provide additional functionality for memory analysis. Some popular plugins include:

- `malfind`: This plugin scans the memory image for common malware indicators.
- `timeliner`: This plugin creates a timeline of events based on timestamps found in the memory image.
- `apihooks`: This plugin displays information about API hooks in the memory image.
- `svcscan`: This plugin scans the memory image for Windows services.
- `netscan`: This plugin scans the memory image for network connections.
- `psxview`: This plugin displays information about hidden processes in the memory image.

To use a plugin, simply run the command `python vol.py -f <memory_image> --profile=<profile> <plugin_name>`. Replace `<memory_image>` with the path to your memory image file, `<profile>` with the appropriate profile for your memory image, and `<plugin_name>` with the name of the plugin you want to use.

## Conclusion

Volatility is a powerful tool for memory analysis, allowing you to extract valuable information from memory images. By using the basic and advanced commands, as well as the available plugins, you can perform in-depth analysis and gain insights into the activities and artifacts present in a memory image.

Happy analyzing!
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## Registro dell'alveare

### Stampa alveari disponibili

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Ottenere un valore

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the following command to install Volatility:

```bash
python setup.py install
```

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility imageinfo`: This command displays information about the memory image, such as the operating system version, architecture, and profile.
- `volatility pslist`: This command lists all running processes in the memory image.
- `volatility psscan`: This command scans for processes in the memory image.
- `volatility pstree`: This command displays the process tree in the memory image.
- `volatility dlllist`: This command lists all loaded DLLs in the memory image.
- `volatility handles`: This command lists all open handles in the memory image.
- `volatility filescan`: This command scans for file objects in the memory image.
- `volatility cmdline`: This command displays the command-line arguments of processes in the memory image.
- `volatility netscan`: This command scans for network connections in the memory image.
- `volatility connections`: This command displays information about network connections in the memory image.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility malfind`: This command scans for injected code and malicious processes in the memory image.
- `volatility apihooks`: This command displays information about API hooks in the memory image.
- `volatility callbacks`: This command displays information about callback functions in the memory image.
- `volatility modscan`: This command scans for kernel modules in the memory image.
- `volatility svcscan`: This command scans for Windows services in the memory image.
- `volatility driverirp`: This command displays information about driver IRPs in the memory image.
- `volatility printkey`: This command displays the contents of a registry key in the memory image.
- `volatility hivelist`: This command lists all registry hives in the memory image.
- `volatility hashdump`: This command dumps the password hashes from the memory image.

## Memory Analysis Plugins

Volatility also provides a wide range of plugins for specific memory analysis tasks. Some popular plugins include:

- `volatility timeliner`: This plugin creates a timeline of events based on timestamps in the memory image.
- `volatility dumpfiles`: This plugin extracts files from the memory image.
- `volatility screenshot`: This plugin captures screenshots from the memory image.
- `volatility vadinfo`: This plugin displays information about Virtual Address Descriptors (VADs) in the memory image.
- `volatility memdump`: This plugin dumps the memory of a specific process in the memory image.

To use a plugin, simply run the following command:

```bash
volatility [plugin_name] -f [memory_image]
```

Replace `[plugin_name]` with the name of the plugin you want to use and `[memory_image]` with the path to the memory image file.

## Conclusion

Volatility is a powerful tool for memory analysis in forensic investigations. By using the various commands and plugins provided by Volatility, you can extract valuable information from memory images and gain insights into the activities and artifacts left behind by malicious actors.
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Dump
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Filesystem

### Montaggio

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Scansione/dump

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### Tabella dei file principali

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo`: This command displays information about the Virtual Address Descriptors (VADs) in the memory dump.
- `volatility -f <memory_dump> vadtree`: This command displays the VAD tree in the memory dump.
- `volatility -f <memory_dump> vadwalk -p <pid>`: This command walks the VAD tree for a specific process.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> dumpfiles -Q <pid>`: This plugin extracts files from the memory dump for a specific process.
- `volatility -f <memory_dump> screenshot`: This plugin captures screenshots of the desktop from the memory dump.
- `volatility -f <memory_dump> hivelist`: This plugin lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <key_path>`: This plugin displays the values of a specific registry key in the memory dump.
- `volatility -f <memory_dump> hashdump`: This plugin dumps the password hashes from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and gain insights into the system's state at the time of the memory dump.
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

Il sistema di file **NTFS** utilizza un componente critico noto come _master file table_ (MFT). Questa tabella include almeno una voce per ogni file su un volume, coprendo anche l'MFT stesso. I dettagli vitali su ogni file, come **dimensione, timestamp, autorizzazioni e dati effettivi**, sono racchiusi nelle voci dell'MFT o in aree esterne all'MFT ma referenziate da queste voci. Ulteriori dettagli possono essere trovati nella [documentazione ufficiale](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Chiavi/Certificati SSL

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository.
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python vol.py` to verify that Volatility is installed correctly.

### Basic Volatility Commands

- `imageinfo`: Displays information about the memory image.
- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `cmdline`: Displays command line arguments.
- `filescan`: Scans for file objects in memory.
- `netscan`: Scans for network connections.
- `connections`: Lists open network connections.
- `malfind`: Finds hidden or injected code.
- `dumpfiles`: Dumps files from memory.
- `dumpregistry`: Dumps registry hives.
- `hivelist`: Lists registry hives.
- `hashdump`: Dumps password hashes.
- `privs`: Lists process privileges.
- `svcscan`: Scans for Windows services.
- `modscan`: Scans for loaded kernel modules.
- `ssdt`: Displays the System Service Descriptor Table.
- `driverirp`: Lists IRP handlers for drivers.
- `idt`: Displays the Interrupt Descriptor Table.
- `gdt`: Displays the Global Descriptor Table.
- `callbacks`: Lists registered callbacks.
- `ssdt`: Displays the System Service Descriptor Table.
- `driverirp`: Lists IRP handlers for drivers.
- `idt`: Displays the Interrupt Descriptor Table.
- `gdt`: Displays the Global Descriptor Table.
- `callbacks`: Lists registered callbacks.

### Memory Analysis Techniques

- **Process Analysis**: Analyzing running processes to identify malicious activity or suspicious behavior.
- **DLL Analysis**: Analyzing loaded DLLs to identify malicious or suspicious code.
- **Network Analysis**: Analyzing network connections and traffic to identify malicious or suspicious activity.
- **File Analysis**: Analyzing files in memory to identify malicious or suspicious files.
- **Registry Analysis**: Analyzing registry hives to identify malicious or suspicious entries.
- **Malware Analysis**: Analyzing malware artifacts in memory to understand their behavior and capabilities.

### Memory Analysis Frameworks

- **Volatility**: A popular open-source memory forensics framework.
- **Rekall**: Another open-source memory forensics framework.
- **Mandiant Redline**: A commercial memory forensics tool.
- **WinDbg**: A Windows kernel debugger that can be used for memory analysis.
- **GDB**: A GNU Project debugger that can be used for memory analysis on Linux systems.

### Memory Analysis Tips

- Always work on a copy of the memory image to avoid accidental modifications.
- Use multiple memory analysis tools to cross-validate your findings.
- Document your analysis process and findings to maintain a clear record.
- Stay up-to-date with the latest memory analysis techniques and tools.
- Join online communities and forums to learn from and collaborate with other memory analysts.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Rekall Documentation](https://www.rekall-forensic.com/docs/)
- [Mandiant Redline](https://www.fireeye.com/services/freeware/redline.html)
- [WinDbg Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
- [GDB Documentation](https://www.gnu.org/software/gdb/documentation/)

### References

- [Volatility Cheat Sheet](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage)
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the following command to install Volatility:

```bash
python setup.py install
```

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility imageinfo`: This command displays information about the memory image, such as the operating system version, architecture, and profile.
- `volatility pslist`: This command lists all running processes in the memory image.
- `volatility psscan`: This command scans for processes in the memory image.
- `volatility pstree`: This command displays the process tree in the memory image.
- `volatility dlllist`: This command lists all loaded DLLs in the memory image.
- `volatility handles`: This command lists all open handles in the memory image.
- `volatility filescan`: This command scans for file objects in the memory image.
- `volatility cmdline`: This command displays the command-line arguments of processes in the memory image.
- `volatility netscan`: This command scans for network connections in the memory image.
- `volatility connections`: This command displays information about network connections in the memory image.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility malfind`: This command scans for injected code and malicious processes in the memory image.
- `volatility apihooks`: This command displays information about API hooks in the memory image.
- `volatility callbacks`: This command displays information about callback functions in the memory image.
- `volatility modscan`: This command scans for kernel modules in the memory image.
- `volatility svcscan`: This command scans for Windows services in the memory image.
- `volatility driverirp`: This command displays information about driver IRPs in the memory image.
- `volatility printkey`: This command displays the contents of a registry key in the memory image.
- `volatility hivelist`: This command lists all registry hives in the memory image.
- `volatility hashdump`: This command dumps the password hashes from the memory image.

## Memory Analysis Plugins

Volatility also provides a wide range of plugins for specific memory analysis tasks. Some popular plugins include:

- `volatility timeliner`: This plugin creates a timeline of events based on timestamps in the memory image.
- `volatility dumpfiles`: This plugin extracts files from the memory image.
- `volatility screenshot`: This plugin captures screenshots from the memory image.
- `volatility vadinfo`: This plugin displays information about Virtual Address Descriptors (VADs) in the memory image.
- `volatility memdump`: This plugin dumps the memory of a specific process in the memory image.

To use a plugin, simply run the following command:

```bash
volatility [plugin_name] -f [memory_image]
```

Replace `[plugin_name]` with the name of the plugin you want to use and `[memory_image]` with the path to the memory image file.

## Conclusion

Volatility is a powerful tool for memory analysis in forensic investigations. By using the various commands and plugins provided by Volatility, you can extract valuable information from memory images and gain insights into the activities and artifacts left behind by malicious actors.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### Scansione con yara

Utilizza questo script per scaricare e unire tutte le regole di malware yara da github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Crea la directory _**rules**_ ed esegui lo script. Questo creerà un file chiamato _**malware\_rules.yar**_ che contiene tutte le regole yara per il malware.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### Plugin esterni

Se desideri utilizzare plugin esterni, assicurati che le cartelle relative ai plugin siano il primo parametro utilizzato.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> driverirp`: This command displays the IRP hooks in the memory dump.
- `volatility -f <memory_dump> ssdt`: This command displays the System Service Descriptor Table (SSDT) hooks in the memory dump.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <hive>`: This command displays the contents of a specific registry key.
- `volatility -f <memory_dump> dumpregistry -K <hive> -D <output_directory>`: This command dumps the contents of a specific registry hive to a directory.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> mftparser`: This plugin parses the Master File Table (MFT) in the memory dump.
- `volatility -f <memory_dump> shimcache`: This plugin extracts information from the Application Compatibility Cache (ShimCache) in the memory dump.
- `volatility -f <memory_dump> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory dumps. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Scaricalo da [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutex

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for potentially malicious code.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> vadinfo -p <pid>`: This command displays information about the virtual address space for a specific process.
- `volatility -f <memory_dump> vadtree -p <pid>`: This command displays the virtual address space tree for a specific process.
- `volatility -f <memory_dump> memdump -p <pid> -D <output_directory>`: This command dumps the memory of a specific process to a file.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the contents of a specific registry key in the memory dump.
- `volatility -f <memory_dump> dumpregistry -D <output_directory>`: This command dumps the entire registry from the memory dump to a file.

## Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, simply specify it with the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [plugin_options]
```

Some popular Volatility plugins include:

- `malfind`: Scans the memory dump for potentially malicious code.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Extracts files from the memory dump.
- `hivelist`: Lists the registry hives in the memory dump.
- `printkey`: Displays the contents of a specific registry key in the memory dump.

## Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can extract valuable information from memory dumps and perform in-depth forensic analysis.
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Collegamenti simbolici

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the following command to install Volatility:

```bash
python setup.py install
```

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility imageinfo`: This command displays information about the memory image, such as the operating system version, architecture, and profile.
- `volatility pslist`: This command lists all running processes in the memory image.
- `volatility psscan`: This command scans for processes in the memory image.
- `volatility pstree`: This command displays the process tree in the memory image.
- `volatility dlllist`: This command lists all loaded DLLs in the memory image.
- `volatility handles`: This command lists all open handles in the memory image.
- `volatility filescan`: This command scans for file objects in the memory image.
- `volatility cmdline`: This command displays the command-line arguments of processes in the memory image.
- `volatility netscan`: This command scans for network connections in the memory image.
- `volatility connections`: This command displays information about network connections in the memory image.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility malfind`: This command scans for injected code and malicious processes in the memory image.
- `volatility apihooks`: This command displays information about API hooks in the memory image.
- `volatility callbacks`: This command displays information about callback functions in the memory image.
- `volatility modscan`: This command scans for kernel modules in the memory image.
- `volatility svcscan`: This command scans for Windows services in the memory image.
- `volatility driverirp`: This command displays information about driver IRPs in the memory image.
- `volatility printkey`: This command displays the contents of a registry key in the memory image.
- `volatility hivelist`: This command lists all registry hives in the memory image.
- `volatility hashdump`: This command dumps the password hashes from the memory image.

## Volatility Profiles

Volatility requires a profile to analyze a memory image. A profile defines the operating system and architecture of the memory image. You can find pre-built profiles for various operating systems in the `volatility/plugins/overlays` directory.

To specify a profile, use the `-p` or `--profile` option followed by the profile name. For example:

```bash
volatility -f memory.dmp --profile=Win7SP1x64 imageinfo
```

## Volatility Plugins

Volatility has a wide range of plugins that provide additional functionality for memory analysis. You can find a list of available plugins in the `volatility/plugins` directory.

To use a plugin, specify the plugin name with the `-f` or `--plugin` option. For example:

```bash
volatility -f memory.dmp --profile=Win7SP1x64 pslist
```

## Conclusion

Volatility is a powerful tool for memory analysis. By using the various commands and plugins available, you can extract valuable information from memory images and perform forensic analysis on compromised systems.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

È possibile **leggere dalla memoria la cronologia di bash**. È anche possibile eseguire il dump del file _.bash\_history_, ma se è stato disabilitato, sarai felice di poter utilizzare questo modulo di volatilità.
```
./vol.py -f file.dmp linux.bash.Bash
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the following command to install Volatility:

```bash
python setup.py install
```

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility imageinfo`: This command displays information about the memory image, such as the operating system version, architecture, and profile.
- `volatility pslist`: This command lists all running processes in the memory image.
- `volatility psscan`: This command scans for processes in the memory image.
- `volatility pstree`: This command displays the process tree in the memory image.
- `volatility dlllist`: This command lists all loaded DLLs in the memory image.
- `volatility handles`: This command lists all open handles in the memory image.
- `volatility filescan`: This command scans for file objects in the memory image.
- `volatility cmdline`: This command displays the command-line arguments of processes in the memory image.
- `volatility netscan`: This command scans for network connections in the memory image.
- `volatility connections`: This command displays information about network connections in the memory image.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility malfind`: This command scans for injected code and malicious processes in the memory image.
- `volatility apihooks`: This command displays information about API hooks in the memory image.
- `volatility callbacks`: This command displays information about callback functions in the memory image.
- `volatility modscan`: This command scans for kernel modules in the memory image.
- `volatility svcscan`: This command scans for Windows services in the memory image.
- `volatility driverirp`: This command displays information about driver IRPs in the memory image.
- `volatility printkey`: This command displays the contents of a registry key in the memory image.
- `volatility hivelist`: This command lists all registry hives in the memory image.
- `volatility hashdump`: This command dumps the password hashes from the memory image.

## Memory Analysis Plugins

Volatility also provides a wide range of plugins for specific memory analysis tasks. Some popular plugins include:

- `volatility timeliner`: This plugin creates a timeline of events based on timestamps in the memory image.
- `volatility dumpfiles`: This plugin extracts files from the memory image.
- `volatility screenshot`: This plugin captures screenshots from the memory image.
- `volatility vadinfo`: This plugin displays information about Virtual Address Descriptors (VADs) in the memory image.
- `volatility memdump`: This plugin dumps the memory of a specific process in the memory image.

To use a plugin, simply run the following command:

```bash
volatility [plugin_name] -f [memory_image]
```

Replace `[plugin_name]` with the name of the plugin you want to use and `[memory_image]` with the path to the memory image file.

## Conclusion

Volatility is a powerful tool for memory analysis and forensic investigations. By using the commands and plugins provided by Volatility, you can extract valuable information from memory images and gain insights into the activities and behavior of a system.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Linea temporale

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> psscan`: This command scans the memory dump for processes.
- `volatility -f <memory_dump> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump> handles -p <pid>`: This command lists the open handles for a specific process.
- `volatility -f <memory_dump> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump> connections`: This command displays the network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> malfind`: This command scans the memory dump for injected code or malware.
- `volatility -f <memory_dump> apihooks`: This command displays the API hooks in the memory dump.
- `volatility -f <memory_dump> modscan`: This command scans the memory dump for loaded kernel modules.
- `volatility -f <memory_dump> svcscan`: This command scans the memory dump for Windows services.
- `volatility -f <memory_dump> printkey -K <registry_key>`: This command displays the values and subkeys of a specific registry key.
- `volatility -f <memory_dump> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump> hashdump -s <system_hive> -y <sam_hive>`: This command dumps the password hashes from the SAM database.

### Volatility Plugins

Volatility also supports plugins that provide additional functionality. To use a plugin, you can use the `-p` option followed by the plugin name. For example:

```
volatility -f <memory_dump> -p <plugin_name> [options]
```

Here are some useful Volatility plugins:

- `malfind`: Scans the memory dump for injected code or malware.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpfiles`: Dumps files from the memory dump.
- `cmdscan`: Scans the memory dump for command history.
- `consoles`: Lists console history from the memory dump.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs) in the memory dump.

### Conclusion

Volatility is a powerful tool for memory analysis. By using the commands and plugins provided by Volatility, you can extract valuable information from memory dumps and perform forensic analysis on compromised systems.
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Driver

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
# Volatility Cheat Sheet

## Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python vol.py` to verify that Volatility is installed correctly.

## Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `imageinfo`: This command displays information about the memory image, such as the operating system version and architecture.
- `pslist`: This command lists all running processes in the memory image.
- `pstree`: This command displays the process tree, showing the parent-child relationships between processes.
- `dlllist`: This command lists all loaded DLLs in the memory image.
- `handles`: This command lists all open handles in the memory image.
- `filescan`: This command scans the memory image for file artifacts, such as file headers and file names.
- `dumpfiles`: This command extracts files from the memory image.
- `malfind`: This command searches for malware in the memory image.
- `cmdscan`: This command scans the memory image for command-line artifacts, such as executed commands.

## Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `mbrparser`: This command parses the Master Boot Record (MBR) in the memory image.
- `ssdt`: This command displays the System Service Descriptor Table (SSDT) in the memory image.
- `driverscan`: This command scans the memory image for loaded drivers.
- `modscan`: This command scans the memory image for loaded kernel modules.
- `ssdt`: This command displays the System Service Descriptor Table (SSDT) in the memory image.
- `vadinfo`: This command displays information about the Virtual Address Descriptors (VADs) in the memory image.
- `vaddump`: This command dumps the memory contents of a specific VAD.
- `vadtree`: This command displays the VAD tree in the memory image.

## Memory Analysis Plugins

Volatility also supports various plugins that can be used for specific memory analysis tasks. Some popular plugins include:

- `malfind`: This plugin searches for malware in the memory image.
- `timeliner`: This plugin creates a timeline of events based on timestamps in the memory image.
- `dumpregistry`: This plugin extracts the Windows registry from the memory image.
- `hivelist`: This plugin lists the registry hives in the memory image.
- `hashdump`: This plugin extracts password hashes from the memory image.
- `netscan`: This plugin scans the memory image for network artifacts, such as open ports and network connections.

To use a plugin, simply run the command `python vol.py -f <memory_image> --profile=<profile> <plugin_name>`. Replace `<memory_image>` with the path to the memory image file, `<profile>` with the appropriate profile for the memory image, and `<plugin_name>` with the name of the plugin you want to use.

## Conclusion

Volatility is a powerful tool for memory analysis and can be used to extract valuable information from memory images. By using the various commands and plugins available in Volatility, you can perform in-depth analysis and investigation of memory artifacts.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Ottenere la clipboard
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Ottenere la cronologia di Internet Explorer

```
volatility -f <memory_dump> --profile=<profile> iehistory
```

Questo comando consente di estrarre la cronologia di Internet Explorer da un dump di memoria utilizzando Volatility. Sostituisci `<memory_dump>` con il percorso del dump di memoria e `<profile>` con il profilo Volatility corretto per l'immagine di memoria.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Ottenere il testo di Notepad

```
$ volatility -f memory_dump.vmem --profile=Win7SP1x64 notepad
```

Questo comando utilizza Volatility per estrarre il testo dal processo Notepad all'interno del dump di memoria "memory_dump.vmem" utilizzando il profilo "Win7SP1x64".
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Screenshot
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)

Il Master Boot Record (MBR) è la prima sezione di un disco rigido o di un dispositivo di archiviazione che contiene le informazioni di avvio del sistema operativo. Questa area è critica per l'avvio del computer e contiene il codice di avvio e la tabella delle partizioni.

#### Analisi del MBR con Volatility

Volatility fornisce diversi plugin per l'analisi del MBR. Di seguito sono riportati alcuni dei plugin più comuni utilizzati per l'analisi del MBR:

- `mbrparser`: analizza il MBR e restituisce informazioni come la tabella delle partizioni, il codice di avvio e le firme.
- `mbrscan`: esegue una scansione del MBR per rilevare eventuali modifiche o infezioni.
- `mbrparser2`: analizza il MBR e restituisce informazioni dettagliate sulle partizioni, inclusi i tipi di file system e gli indirizzi di avvio.

#### Esempio di utilizzo di `mbrparser`

```
$ volatility -f memory_dump.mem mbrparser
```

Questo comando analizza il MBR nel file di dump di memoria `memory_dump.mem` utilizzando il plugin `mbrparser`.

#### Esempio di utilizzo di `mbrscan`

```
$ volatility -f memory_dump.mem mbrscan
```

Questo comando esegue una scansione del MBR nel file di dump di memoria `memory_dump.mem` utilizzando il plugin `mbrscan`.

#### Esempio di utilizzo di `mbrparser2`

```
$ volatility -f memory_dump.mem mbrparser2
```

Questo comando analizza il MBR nel file di dump di memoria `memory_dump.mem` utilizzando il plugin `mbrparser2`.
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Il **Master Boot Record (MBR)** svolge un ruolo cruciale nella gestione delle partizioni logiche di un supporto di archiviazione, strutturate con diversi [sistemi di file](https://it.wikipedia.org/wiki/File_system). Non solo contiene informazioni sulla disposizione delle partizioni, ma contiene anche codice eseguibile che funge da caricatore di avvio. Questo caricatore di avvio avvia direttamente il processo di caricamento del secondo stadio del sistema operativo (vedi [second-stage boot loader](https://it.wikipedia.org/wiki/Second-stage_boot_loader)) o funziona in armonia con il [volume boot record](https://it.wikipedia.org/wiki/Volume_boot_record) (VBR) di ogni partizione. Per una conoscenza approfondita, consulta la [pagina Wikipedia del MBR](https://it.wikipedia.org/wiki/Master_boot_record).

## Riferimenti
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
