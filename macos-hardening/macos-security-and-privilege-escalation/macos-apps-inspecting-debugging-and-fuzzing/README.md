# App macOS - Ispezione, debug e Fuzzing

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware stealer**.

Il loro obiettivo principale di WhiteIntel è combattere i sequestri di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

## Analisi Statica

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% codice overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
### jtool2

Lo strumento può essere utilizzato come **sostituto** di **codesign**, **otool** e **objdump**, e fornisce alcune funzionalità aggiuntive. [**Scaricalo qui**](http://www.newosxbook.com/tools/jtool.html) o installalo con `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** può essere trovato in **macOS** mentre **`ldid`** può essere trovato in **iOS**
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) è uno strumento utile per ispezionare i file **.pkg** (installatori) e vedere cosa c'è dentro prima di installarli.\
Questi installatori contengono script bash `preinstall` e `postinstall` che gli autori di malware di solito sfruttano per **persistere** il **malware**.

### hdiutil

Questo strumento consente di **montare** le immagini disco Apple (**.dmg**) per ispezionarle prima di eseguire qualsiasi operazione:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Sarà montato in `/Volumes`

### Objective-C

#### Metadati

{% hint style="danger" %}
Si noti che i programmi scritti in Objective-C **mantengono** le loro dichiarazioni di classe **quando** **compilati** in [binari Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tali dichiarazioni di classe **includono** il nome e il tipo di:
{% endhint %}

* La classe
* I metodi della classe
* Le variabili di istanza della classe

È possibile ottenere queste informazioni utilizzando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Chiamata di funzione

Quando una funzione viene chiamata in un binario che utilizza Objective-C, il codice compilato invece di chiamare direttamente quella funzione, chiamerà **`objc_msgSend`**. Questo a sua volta chiamerà la funzione finale:

![](<../../../.gitbook/assets/image (302).png>)

I parametri che questa funzione si aspetta sono:

- Il primo parametro (**self**) è "un puntatore che punta all'**istanza della classe che deve ricevere il messaggio**". O più semplicemente, è l'oggetto su cui il metodo viene invocato. Se il metodo è un metodo di classe, questo sarà un'istanza dell'oggetto della classe (nel suo complesso), mentre per un metodo di istanza, self punterà a un'istanza istanziata della classe come oggetto.
- Il secondo parametro, (**op**), è "il selettore del metodo che gestisce il messaggio". Ancora più semplicemente, questo è solo il **nome del metodo**.
- I parametri rimanenti sono eventuali **valori richiesti dal metodo** (op).

Guarda come **ottenere facilmente queste informazioni con `lldb` in ARM64** in questa pagina:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argomento**     | **Registro**                                                   | **(per) objc\_msgSend**                               |
| ----------------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| **1° argomento**  | **rdi**                                                        | **self: oggetto su cui il metodo viene invocato**     |
| **2° argomento**  | **rsi**                                                        | **op: nome del metodo**                              |
| **3° argomento**  | **rdx**                                                        | **1° argomento per il metodo**                       |
| **4° argomento**  | **rcx**                                                        | **2° argomento per il metodo**                       |
| **5° argomento**  | **r8**                                                         | **3° argomento per il metodo**                       |
| **6° argomento**  | **r9**                                                         | **4° argomento per il metodo**                       |
| **7°+ argomento** | <p><strong>rsp+</strong><br><strong>(nello stack)</strong></p> | **5°+ argomento per il metodo**                      |

### Swift

Con i binari Swift, poiché c'è compatibilità con Objective-C, a volte è possibile estrarre le dichiarazioni utilizzando [class-dump](https://github.com/nygard/class-dump/) ma non sempre.

Con i comandi **`jtool -l`** o **`otool -l`** è possibile trovare diverse sezioni che iniziano con il prefisso **`__swift5`**:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Puoi trovare ulteriori informazioni sull'**informazione memorizzata in questa sezione in questo post del blog**.

Inoltre, **i binari Swift potrebbero avere simboli** (ad esempio le librerie devono memorizzare i simboli in modo che le sue funzioni possano essere chiamate). I **simboli di solito contengono le informazioni sul nome della funzione** e sugli attributi in modo poco chiaro, quindi sono molto utili e ci sono "**demanglers"** che possono ottenere il nome originale:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Binari compressi

* Controllare l'alta entropia
* Controllare le stringhe (se non ci sono stringhe comprensibili, il binario potrebbe essere compresso)
* Il pacchetto UPX per MacOS genera una sezione chiamata "\_\_XHDR"

## Analisi dinamica

{% hint style="warning" %}
Nota che per poter eseguire il debug dei binari, **SIP deve essere disabilitato** (`csrutil disable` o `csrutil enable --without debug`) oppure è possibile copiare i binari in una cartella temporanea e **rimuovere la firma** con `codesign --remove-signature <percorso-binario>` o consentire il debug del binario (puoi utilizzare [questo script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Nota che per **strumentalizzare i binari di sistema** (come `cloudconfigurationd`) su macOS, **SIP deve essere disabilitato** (semplicemente rimuovere la firma non funzionerà).
{% endhint %}

### Log unificati

MacOS genera molti log che possono essere molto utili durante l'esecuzione di un'applicazione per capire **cosa sta facendo**.

Inoltre, ci sono alcuni log che conterranno il tag `<private>` per **nascondere** alcune informazioni **identificabili dall'utente** o dal computer. Tuttavia, è possibile **installare un certificato per divulgare queste informazioni**. Segui le spiegazioni da [**qui**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Pannello sinistro

Nel pannello sinistro di Hopper è possibile vedere i simboli (**Etichette**) del binario, l'elenco delle procedure e delle funzioni (**Proc**) e le stringhe (**Str**). Queste non sono tutte le stringhe ma quelle definite in diverse parti del file Mac-O (come _cstring o_ `objc_methname`).

#### Pannello centrale

Nel pannello centrale è possibile vedere il **codice disassemblato**. E puoi vederlo come disassemblaggio **grezzo**, come **grafico**, come **decompilato** e come **binario** cliccando sull'icona rispettiva:

<figure><img src="../../../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

Facendo clic destro su un oggetto di codice è possibile vedere i **riferimenti da/a quell'oggetto** o persino cambiarne il nome (questo non funziona nel pseudocodice decompilato):

<figure><img src="../../../.gitbook/assets/image (1114).png" alt=""><figcaption></figcaption></figure>

Inoltre, nella **parte inferiore centrale è possibile scrivere comandi python**.

#### Pannello destro

Nel pannello destro è possibile vedere informazioni interessanti come la **cronologia di navigazione** (così sai come sei arrivato alla situazione attuale), il **grafo delle chiamate** dove puoi vedere tutte le **funzioni che chiamano questa funzione** e tutte le funzioni che **questa funzione chiama**, e le informazioni sulle **variabili locali**.

### dtrace

Consente agli utenti di accedere alle applicazioni a un livello estremamente **basso** e fornisce un modo per gli utenti di **tracciare** i **programmi** e persino modificare il loro flusso di esecuzione. Dtrace utilizza **sonde** che sono **posizionate in tutto il kernel** e si trovano in posizioni come l'inizio e la fine delle chiamate di sistema.

DTrace utilizza la funzione **`dtrace_probe_create`** per creare una sonda per ogni chiamata di sistema. Queste sonde possono essere attivate nel **punto di ingresso e di uscita di ogni chiamata di sistema**. L'interazione con DTrace avviene tramite /dev/dtrace che è disponibile solo per l'utente root.

{% hint style="success" %}
Per abilitare Dtrace senza disabilitare completamente la protezione SIP, è possibile eseguire in modalità di ripristino: `csrutil enable --without dtrace`

È anche possibile **`dtrace`** o **`dtruss`** i binari che **hai compilato**.
{% endhint %}

Le sonde disponibili di dtrace possono essere ottenute con:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Il nome della sonda è composto da quattro parti: il provider, il modulo, la funzione e il nome (`fbt:mach_kernel:ptrace:entry`). Se non si specifica una parte del nome, Dtrace applicherà quella parte come un carattere jolly.

Per configurare DTrace per attivare le sonde e specificare quali azioni eseguire quando vengono attivate, dovremo utilizzare il linguaggio D.

È possibile trovare una spiegazione più dettagliata e ulteriori esempi su [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Esempi

Eseguire `man -k dtrace` per elencare gli **script DTrace disponibili**. Esempio: `sudo dtruss -n binary`

* In linea
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* script
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Puoi utilizzare questo anche con **SIP attivato**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) è uno strumento molto utile per controllare le azioni correlate ai processi che un processo sta eseguendo (ad esempio, monitorare quali nuovi processi un processo sta creando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) è uno strumento che stampa le relazioni tra i processi.\
È necessario monitorare il tuo Mac con un comando come **`sudo eslogger fork exec rename create > cap.json`** (il terminale che lo avvia richiede FDA). E poi puoi caricare il json in questo strumento per visualizzare tutte le relazioni:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) consente di monitorare gli eventi dei file (come creazione, modifiche ed eliminazioni) fornendo informazioni dettagliate su tali eventi.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) è uno strumento GUI con l'aspetto e la sensazione che gli utenti di Windows potrebbero conoscere da _Procmon_ di Microsoft Sysinternal. Questo strumento consente di avviare e interrompere la registrazione di vari tipi di eventi, consente di filtrare questi eventi per categorie come file, processo, rete, ecc., e fornisce la funzionalità per salvare gli eventi registrati in un formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fanno parte degli strumenti per sviluppatori di Xcode, utilizzati per monitorare le prestazioni dell'applicazione, identificare perdite di memoria e tracciare l'attività del filesystem.

![](<../../../.gitbook/assets/image (1135).png>)

### fs\_usage

Consente di seguire le azioni eseguite dai processi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) è utile per vedere le **librerie** utilizzate da un binario, i **file** che sta utilizzando e le **connessioni di rete**.\
Controlla anche i processi binari su **virustotal** e mostra informazioni sul binario.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

In [**questo post sul blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puoi trovare un esempio su come **debuggare un demone in esecuzione** che utilizza **`PT_DENY_ATTACH`** per impedire il debug anche se SIP era disabilitato.

### lldb

**lldb** è lo strumento di **debugging** binario **de facto** per **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puoi impostare il flavor di intel quando usi lldb creando un file chiamato **`.lldbinit`** nella tua cartella home con la seguente riga:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
All'interno di lldb, eseguire il dump di un processo con `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descrizione</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Avvia l'esecuzione, che continuerà senza interruzioni fino a quando non viene raggiunto un punto di interruzione o il processo termina.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continua l'esecuzione del processo in debug.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Esegue l'istruzione successiva. Questo comando salterà le chiamate alle funzioni.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Esegue l'istruzione successiva. A differenza del comando nexti, questo comando entrerà nelle chiamate alle funzioni.</td></tr><tr><td><strong>finish (f)</strong></td><td>Esegue il resto delle istruzioni nella funzione corrente ("frame") e si ferma.</td></tr><tr><td><strong>control + c</strong></td><td>Sospende l'esecuzione. Se il processo è stato avviato (r) o continuato (c), questo causerà l'arresto del processo ...dove si trova attualmente in esecuzione.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Qualsiasi funzione chiamata main</p><p>b <binname>`main #Funzione principale del binario</p><p>b set -n main --shlib <lib_name> #Funzione principale del binario indicato</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Elenco dei punti di interruzione</p><p>br e/dis <num> #Abilita/Disabilita il punto di interruzione</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Ottieni aiuto sul comando breakpoint</p><p>help memory write #Ottieni aiuto per scrivere nella memoria</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <a href="https://lldb.llvm.org/use/variable.html#type-format">format</a></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <indirizzo reg/memory></strong></td><td>Visualizza la memoria come stringa terminata da null.</td></tr><tr><td><strong>x/i <indirizzo reg/memory></strong></td><td>Visualizza la memoria come istruzione assembly.</td></tr><tr><td><strong>x/b <indirizzo reg/memory></strong></td><td>Visualizza la memoria come byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Stamperà l'oggetto referenziato dal parametro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Nota che la maggior parte delle API o metodi Objective-C di Apple restituiscono oggetti e quindi dovrebbero essere visualizzati tramite il comando "print object" (po). Se po non produce un output significativo, utilizzare <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Scrivi AAAA in quell'indirizzo<br>memory write -f s $rip+0x11f+7 "AAAA" #Scrivi AAAA nell'indirizzo</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disassembla la funzione corrente</p><p>dis -n <nome_funzione> #Disassembla la funzione</p><p>dis -n <nome_funzione> -b <basename> #Disassembla la funzione<br>dis -c 6 #Disassembla 6 linee<br>dis -c 0x100003764 -e 0x100003768 # Da un indirizzo all'altro<br>dis -p -c 4 # Inizia a disassemblare dall'indirizzo corrente</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Controlla l'array di 3 componenti nel registro x1</td></tr></tbody></table>

{% hint style="info" %}
Quando si chiama la funzione **`objc_sendMsg`**, il registro **rsi** contiene il **nome del metodo** come stringa terminata da null ("C"). Per stampare il nome tramite lldb fare:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Analisi Anti-Dinamica

#### Rilevamento di VM

* Il comando **`sysctl hw.model`** restituisce "Mac" quando l'**host è un MacOS** ma qualcosa di diverso quando si tratta di una VM.
* Giocando con i valori di **`hw.logicalcpu`** e **`hw.physicalcpu`** alcuni malware cercano di rilevare se si tratta di una VM.
* Alcuni malware possono anche **rilevare** se la macchina è basata su **VMware** in base all'indirizzo MAC (00:50:56).
* È anche possibile scoprire se un processo è in fase di debug con un codice semplice come:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processo in fase di debug }`
* È anche possibile invocare la chiamata di sistema **`ptrace`** con il flag **`PT_DENY_ATTACH`**. Questo **impedisce** a un deb**u**gger di collegarsi e tracciare.
* È possibile verificare se la funzione **`sysctl`** o **`ptrace`** viene **importata** (ma il malware potrebbe importarla dinamicamente)
* Come indicato in questo articolo, “[Sconfiggere le tecniche anti-debug: varianti di ptrace su macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Il messaggio Processo # è uscito con **status = 45 (0x0000002d)** è di solito un chiaro segno che il target di debug sta utilizzando **PT\_DENY\_ATTACH**_”
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizza i processi che si bloccano e salva un rapporto di blocco su disco**. Un rapporto di blocco contiene informazioni che possono **aiutare uno sviluppatore a diagnosticare** la causa di un blocco.\
Per le applicazioni e altri processi **che si eseguono nel contesto di avvio per utente singolo**, ReportCrash viene eseguito come LaunchAgent e salva i rapporti di blocco nella cartella `~/Library/Logs/DiagnosticReports/` dell'utente.\
Per i daemon, altri processi **che si eseguono nel contesto di avvio di sistema** e altri processi privilegiati, ReportCrash viene eseguito come LaunchDaemon e salva i rapporti di blocco nella cartella `/Library/Logs/DiagnosticReports` del sistema.

Se ti preoccupano i rapporti di blocco **che vengono inviati ad Apple**, puoi disabilitarli. In caso contrario, i rapporti di blocco possono essere utili per **capire come si è bloccato un server**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sonno

Durante il fuzzing in un MacOS è importante non permettere al Mac di andare in modalità di sospensione:

* systemsetup -setsleep Never
* pmset, Preferenze di Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Disconnessione SSH

Se stai facendo fuzzing tramite una connessione SSH è importante assicurarsi che la sessione non vada inattiva. Modifica quindi il file sshd\_config con:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Gestori Interni

**Controlla la seguente pagina** per scoprire come puoi individuare quale app è responsabile del **gestire lo schema o protocollo specificato:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerazione dei Processi di Rete
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Oppure utilizza `netstat` o `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funziona per strumenti CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Funziona con gli strumenti GUI di macOS. Nota che alcune app macOS hanno requisiti specifici come nomi file unici, l'estensione corretta, la necessità di leggere i file dalla sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Alcuni esempi:

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Ulteriori informazioni sul fuzzing di MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Riferimenti

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
