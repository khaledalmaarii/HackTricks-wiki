# Abuso dei Processi su macOS

{% hint style="success" %}
Impara e pratica l'Hacking su AWS: [**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)\
Impara e pratica l'Hacking su GCP: [**HackTricks Training GCP Red Team Expert (GRTE)**](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

- Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
- **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live).
- **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Informazioni di Base sui Processi

Un processo è un'istanza di un eseguibile in esecuzione, tuttavia i processi non eseguono codice, sono i thread a farlo. Quindi **i processi sono solo contenitori per l'esecuzione dei thread** fornendo la memoria, i descrittori, le porte, le autorizzazioni...

Tradizionalmente, i processi venivano avviati all'interno di altri processi (tranne il PID 1) chiamando **`fork`** che creava una copia esatta del processo corrente e poi il **processo figlio** generalmente chiamava **`execve`** per caricare il nuovo eseguibile ed eseguirlo. Successivamente è stato introdotto **`vfork`** per rendere questo processo più veloce senza alcuna copia di memoria.\
Successivamente è stata introdotta **`posix_spawn`** che combina **`vfork`** e **`execve`** in una sola chiamata e accetta flag:

- `POSIX_SPAWN_RESETIDS`: Reimposta gli id effettivi agli id reali
- `POSIX_SPAWN_SETPGROUP`: Imposta l'affiliazione al gruppo di processo
- `POSUX_SPAWN_SETSIGDEF`: Imposta il comportamento predefinito del segnale
- `POSIX_SPAWN_SETSIGMASK`: Imposta la maschera del segnale
- `POSIX_SPAWN_SETEXEC`: Esegue nello stesso processo (come `execve` con più opzioni)
- `POSIX_SPAWN_START_SUSPENDED`: Avvia sospeso
- `_POSIX_SPAWN_DISABLE_ASLR`: Avvia senza ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Utilizza l'allocatore Nano di libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Consente `rwx` sui segmenti di dati
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Chiude tutte le descrizioni dei file su exec(2) per impostazione predefinita
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizza i bit alti dello slide ASLR

Inoltre, `posix_spawn` consente di specificare un array di **`posix_spawnattr`** che controlla alcuni aspetti del processo generato e **`posix_spawn_file_actions`** per modificare lo stato dei descrittori.

Quando un processo muore invia il **codice di ritorno al processo genitore** (se il genitore è morto, il nuovo genitore è il PID 1) con il segnale `SIGCHLD`. Il genitore deve ottenere questo valore chiamando `wait4()` o `waitid()` e finché ciò non avviene, il figlio rimane in uno stato zombie in cui è ancora elencato ma non consuma risorse.

### PID

I PID, identificatori di processo, identificano un processo univoco. In XNU i **PID** sono su **64 bit** che aumentano in modo monotonico e **non si avvolgono mai** (per evitare abusi).

### Gruppi di Processi, Sessioni e Coalizioni

I **processi** possono essere inseriti in **gruppi** per renderne più facile la gestione. Ad esempio, i comandi in uno script shell saranno nello stesso gruppo di processi, quindi è possibile **segnalarli insieme** utilizzando ad esempio kill.\
È anche possibile **raggruppare i processi in sessioni**. Quando un processo avvia una sessione (`setsid(2)`), i processi figli vengono inseriti nella sessione, a meno che non avviino la propria sessione.

La coalizione è un altro modo per raggruppare i processi in Darwin. Un processo che si unisce a una coalizione consente di accedere alle risorse del pool, condividendo un registro o affrontando Jetsam. Le coalizioni hanno ruoli diversi: Leader, servizio XPC, Estensione.

### Credenziali e Personaggi

Ogni processo detiene **credenziali** che **identificano i suoi privilegi** nel sistema. Ogni processo avrà un `uid` primario e un `gid` primario (anche se potrebbe appartenere a diversi gruppi).\
È anche possibile cambiare l'ID utente e di gruppo se l'eseguibile ha il bit `setuid/setgid`.\
Ci sono diverse funzioni per **impostare nuovi uid/gid**.

La syscall **`persona`** fornisce un **insieme alternativo** di **credenziali**. L'adozione di una persona assume il suo uid, gid e l'appartenenza ai gruppi **in una volta sola**. Nel [**codice sorgente**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) è possibile trovare la struttura:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Informazioni di base sui Thread

1. **Thread POSIX (pthreads):** macOS supporta i thread POSIX (`pthreads`), che fanno parte di un'API standard per il threading in C/C++. L'implementazione di pthreads in macOS si trova in `/usr/lib/system/libsystem_pthread.dylib`, che proviene dal progetto `libpthread` disponibile pubblicamente. Questa libreria fornisce le funzioni necessarie per creare e gestire i thread.
2. **Creazione dei Thread:** La funzione `pthread_create()` viene utilizzata per creare nuovi thread. Internamente, questa funzione chiama `bsdthread_create()`, che è una chiamata di sistema di livello inferiore specifica al kernel XNU (il kernel su cui si basa macOS). Questa chiamata di sistema prende vari flag derivati da `pthread_attr` (attributi) che specificano il comportamento del thread, inclusi le politiche di scheduling e la dimensione dello stack.
* **Dimensione predefinita dello Stack:** La dimensione predefinita dello stack per i nuovi thread è di 512 KB, che è sufficiente per le operazioni tipiche ma può essere regolata tramite attributi del thread se è necessario più o meno spazio.
3. **Inizializzazione del Thread:** La funzione `__pthread_init()` è cruciale durante la configurazione del thread, utilizzando l'argomento `env[]` per analizzare le variabili d'ambiente che possono includere dettagli sulla posizione e dimensione dello stack.

#### Terminazione del Thread in macOS

1. **Uscita dei Thread:** I thread vengono tipicamente terminati chiamando `pthread_exit()`. Questa funzione consente a un thread di uscire pulitamente, eseguendo la pulizia necessaria e consentendo al thread di inviare un valore di ritorno a eventuali joiner.
2. **Pulizia del Thread:** Al chiamare `pthread_exit()`, viene invocata la funzione `pthread_terminate()`, che gestisce la rimozione di tutte le strutture del thread associate. Dealloca le porte del thread Mach (Mach è il sottosistema di comunicazione nel kernel XNU) e chiama `bsdthread_terminate`, una syscall che rimuove le strutture a livello kernel associate al thread.

#### Meccanismi di Sincronizzazione

Per gestire l'accesso alle risorse condivise ed evitare le race condition, macOS fornisce diversi primitivi di sincronizzazione. Questi sono fondamentali negli ambienti multithreading per garantire l'integrità dei dati e la stabilità del sistema:

1. **Mutex:**
* **Mutex Regolare (Firma: 0x4D555458):** Mutex standard con una dimensione di memoria di 60 byte (56 byte per il mutex e 4 byte per la firma).
* **Mutex Veloce (Firma: 0x4d55545A):** Simile a un mutex regolare ma ottimizzato per operazioni più veloci, anch'esso di dimensioni 60 byte.
2. **Variabili di Condizione:**
* Utilizzate per attendere che si verifichino determinate condizioni, con una dimensione di 44 byte (40 byte più una firma di 4 byte).
* **Attributi delle Variabili di Condizione (Firma: 0x434e4441):** Attributi di configurazione per le variabili di condizione, di dimensioni 12 byte.
3. **Variabile Once (Firma: 0x4f4e4345):**
* Garantisce che un pezzo di codice di inizializzazione venga eseguito solo una volta. La sua dimensione è di 12 byte.
4. **Blocco di Lettura-Scrittura:**
* Consente a più lettori o a un solo scrittore alla volta, facilitando l'accesso efficiente ai dati condivisi.
* **Blocco di Lettura-Scrittura (Firma: 0x52574c4b):** Di dimensioni 196 byte.
* **Attributi del Blocco di Lettura-Scrittura (Firma: 0x52574c41):** Attributi per i blocchi di lettura-scrittura, di dimensioni 20 byte.

{% hint style="success" %}
Gli ultimi 4 byte di questi oggetti vengono utilizzati per rilevare gli overflow.
{% endhint %}

### Variabili Locali del Thread (TLV)

Le **Variabili Locali del Thread (TLV)** nel contesto dei file Mach-O (il formato per gli eseguibili in macOS) vengono utilizzate per dichiarare variabili specifiche per **ogni thread** in un'applicazione multithread. Ciò garantisce che ogni thread abbia la propria istanza separata di una variabile, fornendo un modo per evitare conflitti e mantenere l'integrità dei dati senza necessità di meccanismi di sincronizzazione espliciti come i mutex.

In C e nei linguaggi correlati, è possibile dichiarare una variabile locale del thread utilizzando la parola chiave **`__thread`**. Ecco come funziona nell'esempio:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Questo frammento definisce `tlv_var` come una variabile locale al thread. Ogni thread che esegue questo codice avrà la propria `tlv_var`, e le modifiche che un thread apporta a `tlv_var` non influenzeranno `tlv_var` in un altro thread.

Nel binario Mach-O, i dati relativi alle variabili locali al thread sono organizzati in sezioni specifiche:

* **`__DATA.__thread_vars`**: Questa sezione contiene i metadati sulle variabili locali al thread, come i loro tipi e lo stato di inizializzazione.
* **`__DATA.__thread_bss`**: Questa sezione è utilizzata per le variabili locali al thread che non sono esplicitamente inizializzate. Fa parte della memoria riservata per i dati inizializzati a zero.

Mach-O fornisce anche una specifica API chiamata **`tlv_atexit`** per gestire le variabili locali al thread quando un thread termina. Questa API consente di **registrare distruttori** - funzioni speciali che puliscono i dati locali al thread quando un thread termina.

### Priorità dei Thread

Comprendere le priorità dei thread implica guardare a come il sistema operativo decide quali thread eseguire e quando. Questa decisione è influenzata dal livello di priorità assegnato a ciascun thread. In macOS e nei sistemi simili a Unix, ciò è gestito utilizzando concetti come `nice`, `renice` e classi di Qualità del Servizio (QoS).

#### Nice e Renice

1. **Nice:**
* Il valore `nice` di un processo è un numero che influenza la sua priorità. Ogni processo ha un valore `nice` che va da -20 (la priorità più alta) a 19 (la priorità più bassa). Il valore `nice` predefinito quando un processo viene creato è tipicamente 0.
* Un valore `nice` più basso (più vicino a -20) rende un processo più "egoista", dandogli più tempo CPU rispetto ad altri processi con valori `nice` più alti.
2. **Renice:**
* `renice` è un comando utilizzato per cambiare il valore `nice` di un processo già in esecuzione. Questo può essere utilizzato per regolare dinamicamente la priorità dei processi, aumentando o diminuendo la loro allocazione di tempo CPU in base ai nuovi valori `nice`.
* Ad esempio, se un processo ha bisogno di più risorse CPU temporaneamente, potresti abbassare il suo valore `nice` usando `renice`.

#### Classi di Qualità del Servizio (QoS)

Le classi di QoS sono un approccio più moderno per gestire le priorità dei thread, in particolare nei sistemi come macOS che supportano **Grand Central Dispatch (GCD)**. Le classi di QoS consentono agli sviluppatori di **categorizzare** il lavoro in diversi livelli in base all'importanza o all'urgenza. macOS gestisce automaticamente la prioritizzazione dei thread in base a queste classi di QoS:

1. **Interattivo Utente:**
* Questa classe è per attività che interagiscono attualmente con l'utente o richiedono risultati immediati per fornire un'esperienza utente ottimale. Queste attività hanno la priorità più alta per mantenere l'interfaccia reattiva (ad esempio, animazioni o gestione eventi).
2. **Iniziativa Utente:**
* Attività che l'utente avvia e si aspetta risultati immediati, come aprire un documento o fare clic su un pulsante che richiede calcoli. Queste attività hanno una priorità elevata ma inferiore a quella interattiva utente.
3. **Utilità:**
* Queste attività sono a lungo termine e mostrano tipicamente un indicatore di avanzamento (ad esempio, scaricare file, importare dati). Hanno una priorità inferiore rispetto alle attività avviate dall'utente e non devono essere completate immediatamente.
4. **Background:**
* Questa classe è per attività che operano in background e non sono visibili all'utente. Possono essere attività come indicizzazione, sincronizzazione o backup. Hanno la priorità più bassa e un impatto minimo sulle prestazioni del sistema.

Utilizzando le classi di QoS, gli sviluppatori non devono gestire i numeri di priorità esatti, ma piuttosto concentrarsi sulla natura del compito e il sistema ottimizza di conseguenza le risorse CPU.

Inoltre, ci sono diverse **politiche di pianificazione dei thread** che consentono di specificare un insieme di parametri di pianificazione che lo scheduler terrà in considerazione. Questo può essere fatto utilizzando `thread_policy_[set/get]`. Questo potrebbe essere utile negli attacchi di condizione di gara.

## Abuso dei Processi su MacOS

MacOS, come qualsiasi altro sistema operativo, fornisce una varietà di metodi e meccanismi per **processi per interagire, comunicare e condividere dati**. Sebbene queste tecniche siano essenziali per il corretto funzionamento del sistema, possono anche essere abusate da attori minacciosi per **eseguire attività dannose**.

### Iniezione di Libreria

L'iniezione di libreria è una tecnica in cui un attaccante **costringe un processo a caricare una libreria dannosa**. Una volta iniettata, la libreria viene eseguita nel contesto del processo target, fornendo all'attaccante gli stessi permessi e accessi del processo.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection/]
{% endcontent-ref %}

### Hooking di Funzioni

Il Hooking di Funzioni coinvolge **intercettare chiamate di funzioni** o messaggi all'interno di un codice software. Mediante l'hacking delle funzioni, un attaccante può **modificare il comportamento** di un processo, osservare dati sensibili o addirittura ottenere il controllo sul flusso di esecuzione.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md]
{% endcontent-ref %}

### Comunicazione tra Processi

La Comunicazione tra Processi (IPC) si riferisce a diversi metodi con cui processi separati **condividono e scambiano dati**. Sebbene l'IPC sia fondamentale per molte applicazioni legittime, può anche essere abusato per eludere l'isolamento dei processi, divulgare informazioni sensibili o eseguire azioni non autorizzate.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication]
{% endcontent-ref %}

### Iniezione di Applicazioni Electron

Le applicazioni Electron eseguite con specifiche variabili d'ambiente potrebbero essere vulnerabili all'iniezione di processi:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md]
{% endcontent-ref %}

### Iniezione di Chromium

È possibile utilizzare i flag `--load-extension` e `--use-fake-ui-for-media-stream` per eseguire un **attacco man in the browser** che consente di rubare tasti premuti, traffico, cookie, iniettare script nelle pagine...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md]
{% endcontent-ref %}

### NIB Sporco

I file NIB **definiscono elementi dell'interfaccia utente (UI)** e le loro interazioni all'interno di un'applicazione. Tuttavia, possono **eseguire comandi arbitrari** e **Gatekeeper non impedisce** l'esecuzione di un'applicazione già eseguita se un **file NIB è modificato**. Pertanto, potrebbero essere utilizzati per far eseguire programmi arbitrari comandi arbitrari:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md]
{% endcontent-ref %}

### Iniezione di Applicazioni Java

È possibile abusare di determinate capacità di Java (come la variabile d'ambiente **`_JAVA_OPTS`**) per fare in modo che un'applicazione Java esegua **codice/comandi arbitrari**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md]
{% endcontent-ref %}

### Iniezione di Applicazioni .Net

È possibile iniettare codice nelle applicazioni .Net **abusando della funzionalità di debug di .Net** (non protetta dalle protezioni macOS come il rafforzamento in fase di esecuzione).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md]
{% endcontent-ref %}

### Iniezione di Perl

Controlla diverse opzioni per fare in modo che uno script Perl esegua codice arbitrario in:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md]
{% endcontent-ref %}

### Iniezione di Ruby

È anche possibile abusare delle variabili d'ambiente di Ruby per fare in modo che script arbitrari eseguano codice arbitrario:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md]
{% endcontent-ref %}
### Iniezione di Python

Se la variabile di ambiente **`PYTHONINSPECT`** è impostata, il processo python passerà a una CLI python una volta terminato. È anche possibile utilizzare **`PYTHONSTARTUP`** per indicare uno script python da eseguire all'inizio di una sessione interattiva.\
Tuttavia, nota che lo script **`PYTHONSTARTUP`** non verrà eseguito quando **`PYTHONINSPECT`** crea la sessione interattiva.

Altre variabili di ambiente come **`PYTHONPATH`** e **`PYTHONHOME`** potrebbero essere utili per eseguire codice arbitrario con un comando python.

Tieni presente che gli eseguibili compilati con **`pyinstaller`** non utilizzeranno queste variabili di ambiente anche se vengono eseguiti utilizzando un python integrato.

{% hint style="danger" %}
Nel complesso, non sono riuscito a trovare un modo per far eseguire a python codice arbitrario abusando delle variabili di ambiente.\
Tuttavia, la maggior parte delle persone installa python utilizzando **Hombrew**, che installerà python in una **posizione scrivibile** per l'utente amministratore predefinito. Puoi dirottarlo con qualcosa del genere:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Persino **root** eseguirà questo codice quando si esegue python.
{% endhint %}

## Rilevamento

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) è un'applicazione open source che può **rilevare e bloccare azioni di iniezione di processo**:

* Utilizzando le **Variabili Ambientali**: Monitorerà la presenza di una qualsiasi delle seguenti variabili ambientali: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
* Utilizzando chiamate a **`task_for_pid`**: Per individuare quando un processo vuole ottenere la **porta del task di un altro** che consente di iniettare codice nel processo.
* **Parametri delle app Electron**: Qualcuno può utilizzare gli argomenti della riga di comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** per avviare un'app Electron in modalità di debug, e quindi iniettare codice in essa.
* Utilizzando **symlink** o **hardlink**: Tipicamente l'abuso più comune è **collocare un link con i privilegi del nostro utente**, e **farlo puntare a una posizione con privilegi superiori**. Il rilevamento è molto semplice sia per i symlink che per gli hardlink. Se il processo che crea il link ha un **livello di privilegio diverso** rispetto al file di destinazione, creiamo un **avviso**. Purtroppo nel caso dei symlink non è possibile bloccare, poiché non abbiamo informazioni sulla destinazione del link prima della creazione. Questa è una limitazione del framework EndpointSecuriy di Apple.

### Chiamate effettuate da altri processi

In [**questo post sul blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) puoi trovare come è possibile utilizzare la funzione **`task_name_for_pid`** per ottenere informazioni su altri **processi che iniettano codice in un processo** e quindi ottenere informazioni su quell'altro processo.

Nota che per chiamare quella funzione devi essere **lo stesso uid** di chi esegue il processo o **root** (e restituisce informazioni sul processo, non un modo per iniettare codice).

## Riferimenti

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
