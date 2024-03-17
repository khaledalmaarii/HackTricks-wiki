# Analisi Forense di Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Raccolta Informazioni Iniziale

### Informazioni di Base

Prima di tutto, è consigliabile avere una **USB** con **binari e librerie noti e validi** (puoi semplicemente prendere Ubuntu e copiare le cartelle _/bin_, _/sbin_, _/lib_ e _/lib64_), quindi montare la USB e modificare le variabili d'ambiente per utilizzare quei binari:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una volta configurato il sistema per utilizzare binari buoni e noti, puoi iniziare **a estrarre alcune informazioni di base**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Informazioni sospette

Durante l'ottenimento delle informazioni di base dovresti controllare cose strane come:

- I **processi root** di solito vengono eseguiti con PIDS bassi, quindi se trovi un processo root con un PID elevato potresti sospettare
- Controlla i **login registrati** degli utenti senza una shell all'interno di `/etc/passwd`
- Controlla gli **hash delle password** all'interno di `/etc/shadow` per gli utenti senza una shell

### Dump della memoria

Per ottenere la memoria del sistema in esecuzione, è consigliabile utilizzare [**LiME**](https://github.com/504ensicsLabs/LiME).\
Per **compilarlo**, è necessario utilizzare lo **stesso kernel** che sta utilizzando la macchina vittima.

{% hint style="info" %}
Ricorda che **non puoi installare LiME o qualsiasi altra cosa** nella macchina vittima in quanto apporterà diverse modifiche ad essa
{% endhint %}

Quindi, se hai una versione identica di Ubuntu puoi utilizzare `apt-get install lime-forensics-dkms`\
In altri casi, è necessario scaricare [**LiME**](https://github.com/504ensicsLabs/LiME) da github e compilarlo con gli header del kernel corretti. Per **ottenere gli header del kernel esatti** della macchina vittima, puoi semplicemente **copiare la directory** `/lib/modules/<versione del kernel>` sulla tua macchina, e poi **compilare** LiME utilizzandoli:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supporta 3 **formati**:

* Raw (ogni segmento concatenato insieme)
* Padded (come raw, ma con zeri negli ultimi bit)
* Lime (formato consigliato con metadati)

LiME può anche essere utilizzato per **inviare il dump tramite rete** anziché memorizzarlo sul sistema utilizzando qualcosa come: `path=tcp:4444`

### Imaging del disco

#### Spegnimento

Innanzitutto, sarà necessario **spegnere il sistema**. Questo non è sempre un'opzione poiché a volte il sistema sarà un server di produzione che l'azienda non può permettersi di spegnere.\
Ci sono **2 modi** per spegnere il sistema, uno **spegnimento normale** e uno **spegnimento improvviso**. Il primo permetterà ai **processi di terminare come al solito** e al **filesystem** di essere **sincronizzato**, ma permetterà anche al possibile **malware** di **distruggere le prove**. L'approccio "stacca la spina" potrebbe comportare **una certa perdita di informazioni** (non molte informazioni andranno perse poiché abbiamo già preso un'immagine della memoria) e il **malware non avrà alcuna opportunità** di fare qualcosa al riguardo. Pertanto, se **sospetti** che ci possa essere un **malware**, esegui semplicemente il **comando `sync`** sul sistema e stacca la spina.

#### Fare un'immagine del disco

È importante notare che **prima di collegare il tuo computer a qualcosa relativo al caso**, devi essere sicuro che verrà **montato in sola lettura** per evitare di modificare qualsiasi informazione.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Analisi preliminare dell'immagine del disco

Immaginare un'immagine del disco senza ulteriori dati.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ricerca di Malware conosciuti

### File di Sistema Modificati

Linux offre strumenti per garantire l'integrità dei componenti di sistema, fondamentali per individuare file potenzialmente problematici.

* **Sistemi basati su RedHat**: Utilizza `rpm -Va` per un controllo completo.
* **Sistemi basati su Debian**: `dpkg --verify` per la verifica iniziale, seguito da `debsums | grep -v "OK$"` (dopo aver installato `debsums` con `apt-get install debsums`) per identificare eventuali problemi.

### Rilevatori di Malware/Rootkit

Leggi la seguente pagina per scoprire gli strumenti che possono essere utili per trovare malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Ricerca dei programmi installati

Per cercare efficacemente i programmi installati su sistemi Debian e RedHat, considera di sfruttare i log di sistema e i database insieme a controlli manuali nelle directory comuni.

* Per Debian, ispeziona _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ per ottenere dettagli sull'installazione dei pacchetti, utilizzando `grep` per filtrare informazioni specifiche.
* Gli utenti RedHat possono interrogare il database RPM con `rpm -qa --root=/mntpath/var/lib/rpm` per elencare i pacchetti installati.

Per scoprire software installati manualmente o al di fuori di questi gestori di pacchetti, esplora directory come _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, e _**`/sbin`**_. Combina l'elenco delle directory con comandi specifici del sistema per identificare eseguibili non associati a pacchetti conosciuti, migliorando la tua ricerca di tutti i programmi installati.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per creare facilmente e **automatizzare flussi di lavoro** supportati dagli strumenti della community **più avanzati al mondo**.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recupero dei binari in esecuzione eliminati

Immagina un processo eseguito da /tmp/exec e eliminato. È possibile estrarlo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Ispezionare le posizioni di avvio automatico

### Compiti pianificati
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Servizi

Percorsi in cui un malware potrebbe essere installato come servizio:

- **/etc/inittab**: Chiama gli script di inizializzazione come rc.sysinit, indirizzando ulteriormente agli script di avvio.
- **/etc/rc.d/** e **/etc/rc.boot/**: Contengono script per l'avvio dei servizi, quest'ultimo trovato nelle versioni più vecchie di Linux.
- **/etc/init.d/**: Usato in certe versioni di Linux come Debian per memorizzare gli script di avvio.
- I servizi possono anche essere attivati tramite **/etc/inetd.conf** o **/etc/xinetd/**, a seconda della variante di Linux.
- **/etc/systemd/system**: Una directory per gli script del sistema e del gestore dei servizi.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene collegamenti ai servizi che dovrebbero essere avviati in un runlevel multiutente.
- **/usr/local/etc/rc.d/**: Per servizi personalizzati o di terze parti.
- **\~/.config/autostart/**: Per applicazioni di avvio automatico specifiche dell'utente, che possono essere un nascondiglio per malware mirati agli utenti.
- **/lib/systemd/system/**: File di unità predefiniti a livello di sistema forniti dai pacchetti installati.

### Moduli del Kernel

I moduli del kernel Linux, spesso utilizzati dai malware come componenti rootkit, vengono caricati all'avvio del sistema. Le directory e i file critici per questi moduli includono:

- **/lib/modules/$(uname -r)**: Contiene i moduli per la versione del kernel in esecuzione.
- **/etc/modprobe.d**: Contiene file di configurazione per controllare il caricamento dei moduli.
- **/etc/modprobe** e **/etc/modprobe.conf**: File per impostazioni globali dei moduli.

### Altre Posizioni di Avvio Automatico

Linux utilizza vari file per eseguire automaticamente programmi al login dell'utente, potenzialmente ospitando malware:

- **/etc/profile.d/**\*, **/etc/profile**, e **/etc/bash.bashrc**: Eseguiti per qualsiasi login utente.
- **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, e **\~/.config/autostart**: File specifici dell'utente che vengono eseguiti al loro login.
- **/etc/rc.local**: Eseguito dopo che tutti i servizi di sistema sono stati avviati, segnando la fine della transizione a un ambiente multiutente.

## Esaminare i Log

I sistemi Linux tengono traccia delle attività degli utenti e degli eventi di sistema attraverso vari file di log. Questi log sono fondamentali per identificare accessi non autorizzati, infezioni da malware e altri incidenti di sicurezza. I file di log chiave includono:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Catturano messaggi e attività a livello di sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registrano tentativi di autenticazione, accessi riusciti e falliti.
- Usare `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` per filtrare eventi di autenticazione rilevanti.
- **/var/log/boot.log**: Contiene messaggi di avvio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registri delle attività del server di posta elettronica, utili per tracciare servizi correlati alla posta elettronica.
- **/var/log/kern.log**: Memorizza messaggi del kernel, inclusi errori e avvisi.
- **/var/log/dmesg**: Contiene messaggi dei driver di dispositivo.
- **/var/log/faillog**: Registra tentativi di accesso falliti, aiutando nelle indagini sulle violazioni di sicurezza.
- **/var/log/cron**: Registra l'esecuzione dei job cron.
- **/var/log/daemon.log**: Traccia le attività dei servizi in background.
- **/var/log/btmp**: Documenta tentativi di accesso falliti.
- **/var/log/httpd/**: Contiene log degli errori e degli accessi di Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registri delle attività del database MySQL.
- **/var/log/xferlog**: Registra trasferimenti di file FTP.
- **/var/log/**: Controllare sempre i log inaspettati qui.

{% hint style="info" %}
I log di sistema e i sottosistemi di audit di Linux possono essere disabilitati o eliminati in caso di intrusione o incidente di malware. Poiché i log nei sistemi Linux generalmente contengono alcune delle informazioni più utili sulle attività dannose, gli intrusi li eliminano regolarmente. Pertanto, quando si esaminano i file di log disponibili, è importante cercare lacune o voci fuori ordine che potrebbero essere un'indicazione di eliminazione o manomissione.
{% endhint %}

**Linux mantiene un registro dei comandi per ogni utente**, memorizzato in:

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

Inoltre, il comando `last -Faiwx` fornisce un elenco dei login degli utenti. Controllalo per login sconosciuti o inaspettati.

Controllare i file che possono concedere privilegi aggiuntivi:

- Esaminare `/etc/sudoers` per privilegi utente non anticipati che potrebbero essere stati concessi.
- Esaminare `/etc/sudoers.d/` per privilegi utente non anticipati che potrebbero essere stati concessi.
- Esaminare `/etc/groups` per identificare eventuali appartenenze o autorizzazioni di gruppo insolite.
- Esaminare `/etc/passwd` per identificare eventuali appartenenze o autorizzazioni di gruppo insolite.

Alcune app generano anche i propri log:

- **SSH**: Esaminare _\~/.ssh/authorized\_keys_ e _\~/.ssh/known\_hosts_ per connessioni remote non autorizzate.
- **Desktop Gnome**: Controllare _\~/.recently-used.xbel_ per i file recentemente accessati tramite le applicazioni Gnome.
- **Firefox/Chrome**: Controllare la cronologia del browser e i download in _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ per attività sospette.
- **VIM**: Esaminare _\~/.viminfo_ per dettagli sull'uso, come percorsi dei file accessati e cronologia delle ricerche.
- **Open Office**: Verificare gli accessi ai documenti recenti che potrebbero indicare file compromessi.
- **FTP/SFTP**: Esaminare i log in _\~/.ftp\_history_ o _\~/.sftp\_history_ per trasferimenti di file che potrebbero essere non autorizzati.
- **MySQL**: Investigare _\~/.mysql\_history_ per le query MySQL eseguite, rivelando potenzialmente attività non autorizzate sul database.
- **Less**: Analizzare _\~/.lesshst_ per la cronologia dell'uso, inclusi file visualizzati e comandi eseguiti.
- **Git**: Esaminare _\~/.gitconfig_ e il progetto _.git/logs_ per modifiche ai repository.

### Log USB

[**usbrip**](https://github.com/snovvcrash/usbrip) è un piccolo software scritto in Python 3 puro che analizza i file di log di Linux (`/var/log/syslog*` o `/var/log/messages*` a seconda della distribuzione) per costruire tabelle storiche degli eventi USB.

È interessante **conoscere tutti gli USB che sono stati utilizzati** e sarà più utile se si dispone di un elenco autorizzato di USB per trovare "eventi di violazione" (l'uso di USB che non sono all'interno di quell'elenco).

### Installazione
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Esempi
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
## Revisione degli Account Utente e delle Attività di Accesso

Esamina i file _**/etc/passwd**_, _**/etc/shadow**_ e i **log di sicurezza** per individuare nomi o account insoliti creati e/o utilizzati in prossimità di eventi non autorizzati noti. Controlla anche possibili attacchi di forza bruta sudo.\
Inoltre, controlla file come _**/etc/sudoers**_ e _**/etc/groups**_ per verificare privilegi inaspettati assegnati agli utenti.\
Infine, cerca account senza **password** o con password **facilmente indovinabili**.

## Esamina il File System

### Analisi delle Strutture del File System nelle Indagini sui Malware

Nelle indagini sugli incidenti di malware, la struttura del file system è una fonte cruciale di informazioni, rivelando sia la sequenza degli eventi che il contenuto del malware. Tuttavia, gli autori di malware stanno sviluppando tecniche per ostacolare questa analisi, come la modifica dei timestamp dei file o l'evitare il file system per lo storage dei dati.

Per contrastare questi metodi anti-forensi, è essenziale:

* **Condurre un'analisi dettagliata della timeline** utilizzando strumenti come **Autopsy** per visualizzare le timeline degli eventi o `mactime` di **Sleuth Kit** per dati dettagliati sulla timeline.
* **Investigare script inaspettati** nel $PATH del sistema, che potrebbero includere script shell o PHP utilizzati dagli attaccanti.
* **Esaminare `/dev` per file atipici**, poiché tradizionalmente contiene file speciali, ma potrebbe contenere file correlati al malware.
* **Cercare file o directory nascosti** con nomi come ".. " (punto punto spazio) o "..^G" (punto punto control-G), che potrebbero nascondere contenuti dannosi.
* **Identificare file setuid root** utilizzando il comando: `find / -user root -perm -04000 -print` Questo trova file con permessi elevati, che potrebbero essere sfruttati dagli attaccanti.
* **Esaminare i timestamp di cancellazione** nelle tabelle degli inode per individuare cancellazioni di file di massa, indicando potenzialmente la presenza di rootkit o trojan.
* **Ispezionare gli inode consecutivi** per individuare file dannosi vicini dopo averne identificato uno, poiché potrebbero essere stati posizionati insieme.
* **Controllare le directory binarie comuni** (_/bin_, _/sbin_) per file modificati di recente, poiché potrebbero essere stati alterati dal malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Si noti che un **attaccante** può **modificare** l'**orario** per far apparire i **file legittimi**, ma non può modificare l'**inode**. Se si scopre che un **file** indica che è stato creato e modificato allo stesso **orario** degli altri file nella stessa cartella, ma l'**inode** è **inesperatamente più grande**, allora i **timestamp di quel file sono stati modificati**.
{% endhint %}

## Confrontare file di diverse versioni del filesystem

### Riepilogo del Confronto tra Versioni del Filesystem

Per confrontare le versioni del filesystem e individuare le modifiche, utilizziamo comandi semplificati `git diff`:

* **Per trovare nuovi file**, confronta due directory:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Per contenuti modificati**, elenca le modifiche ignorando le linee specifiche:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Per rilevare i file eliminati**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Opzioni di filtro** (`--diff-filter`) aiutano a restringere le modifiche a file specifici come aggiunti (`A`), eliminati (`D`), o modificati (`M`).
* `A`: File aggiunti
* `C`: File copiati
* `D`: File eliminati
* `M`: File modificati
* `R`: File rinominati
* `T`: Cambiamenti di tipo (ad esempio, file a symlink)
* `U`: File non uniti
* `X`: File sconosciuti
* `B`: File corrotti

## Riferimenti

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Libro: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!

* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFTs**](https://opensea.io/collection/the-peass-family) esclusivi
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per costruire e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti comunitari più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
