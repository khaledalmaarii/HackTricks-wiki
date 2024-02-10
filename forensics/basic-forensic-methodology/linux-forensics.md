# Forense Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Raccolta Informazioni Iniziale

### Informazioni di base

Innanzitutto, è consigliabile avere una **USB** con **binari e librerie ben noti** (puoi semplicemente prendere Ubuntu e copiare le cartelle _/bin_, _/sbin_, _/lib_ e _/lib64_), quindi montare l'USB e modificare le variabili di ambiente per utilizzare quei binari:
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

Durante l'ottenimento delle informazioni di base, è necessario controllare eventuali cose strane come:

* I **processi di root** di solito vengono eseguiti con PID bassi, quindi se trovi un processo di root con un PID elevato potresti sospettare
* Controlla i **login registrati** degli utenti senza una shell all'interno di `/etc/passwd`
* Controlla gli **hash delle password** all'interno di `/etc/shadow` per gli utenti senza una shell

### Dump della memoria

Per ottenere la memoria del sistema in esecuzione, è consigliabile utilizzare [**LiME**](https://github.com/504ensicsLabs/LiME).\
Per **compilarlo**, è necessario utilizzare lo **stesso kernel** che la macchina vittima sta utilizzando.

{% hint style="info" %}
Ricorda che **non puoi installare LiME o qualsiasi altra cosa** nella macchina vittima in quanto apporterà diverse modifiche ad essa.
{% endhint %}

Quindi, se hai una versione identica di Ubuntu, puoi utilizzare `apt-get install lime-forensics-dkms`\
In altri casi, è necessario scaricare [**LiME**](https://github.com/504ensicsLabs/LiME) da github e compilarlo con le intestazioni del kernel corrette. Per **ottenere le intestazioni esatte del kernel** della macchina vittima, puoi semplicemente **copiare la directory** `/lib/modules/<versione del kernel>` sulla tua macchina e quindi **compilare** LiME utilizzandole:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supporta 3 **formati**:

* Raw (ogni segmento concatenato insieme)
* Padded (come raw, ma con zeri nei bit a destra)
* Lime (formato consigliato con metadati)

LiME può anche essere utilizzato per **inviare il dump tramite rete** invece di memorizzarlo nel sistema utilizzando qualcosa come: `path=tcp:4444`

### Imaging del disco

#### Spegnimento

Prima di tutto, sarà necessario **spegnere il sistema**. Questo non è sempre un'opzione poiché a volte il sistema sarà un server di produzione che l'azienda non può permettersi di spegnere.\
Ci sono **2 modi** per spegnere il sistema, uno **spegnimento normale** e uno **spegnimento improvviso**. Il primo permetterà ai **processi di terminare come al solito** e al **filesystem** di essere **sincronizzato**, ma permetterà anche al possibile **malware** di **distruggere le prove**. L'approccio "spegnimento improvviso" può comportare **una certa perdita di informazioni** (non molte informazioni andranno perse poiché abbiamo già preso un'immagine della memoria) e il **malware non avrà alcuna opportunità** di fare qualcosa al riguardo. Pertanto, se **sospetti** che ci possa essere un **malware**, esegui semplicemente il comando **`sync`** sul sistema e stacca la spina.

#### Creazione di un'immagine del disco

È importante notare che **prima di collegare il tuo computer a qualsiasi cosa relativa al caso**, devi essere sicuro che verrà **montato in sola lettura** per evitare di modificare qualsiasi informazione.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pre-analisi dell'immagine del disco

Creazione di un'immagine del disco senza ulteriori dati.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ricerca di malware noti

### File di sistema modificati

Linux offre strumenti per garantire l'integrità dei componenti di sistema, fondamentali per individuare file potenzialmente problematici.

- **Sistemi basati su RedHat**: Utilizza `rpm -Va` per una verifica completa.
- **Sistemi basati su Debian**: `dpkg --verify` per una verifica iniziale, seguita da `debsums | grep -v "OK$"` (dopo aver installato `debsums` con `apt-get install debsums`) per identificare eventuali problemi.

### Rilevatori di malware/rootkit

Leggi la seguente pagina per conoscere gli strumenti che possono essere utili per trovare malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Ricerca dei programmi installati

Per cercare efficacemente i programmi installati sia su sistemi Debian che RedHat, considera di sfruttare i log di sistema e i database insieme a controlli manuali nelle directory comuni.

- Per Debian, ispeziona **_`/var/lib/dpkg/status`_** e **_`/var/log/dpkg.log`_** per ottenere dettagli sulle installazioni dei pacchetti, utilizzando `grep` per filtrare le informazioni specifiche.

- Gli utenti di RedHat possono interrogare il database RPM con `rpm -qa --root=/mntpath/var/lib/rpm` per elencare i pacchetti installati.

Per scoprire il software installato manualmente o al di fuori di questi gestori di pacchetti, esplora le directory come **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, e **_`/sbin`_**. Combina l'elenco delle directory con comandi specifici del sistema per identificare eseguibili non associati a pacchetti noti, migliorando la ricerca di tutti i programmi installati.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recupero dei binari in esecuzione eliminati

Immagina un processo eseguito da /tmp/exec e successivamente eliminato. È possibile estrarlo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Ispeziona le posizioni di avvio automatico

### Attività pianificate

Le attività pianificate sono un metodo comune utilizzato da Linux per avviare automaticamente i processi in determinati momenti. Puoi ispezionare le attività pianificate per individuare eventuali programmi sospetti o non autorizzati che potrebbero essere in esecuzione sul sistema.

Per visualizzare le attività pianificate, puoi utilizzare il comando `crontab -l` per elencare le attività pianificate per l'utente corrente. Puoi anche controllare i file nella directory `/etc/cron.d/` per le attività pianificate di sistema.

Se trovi un'attività sospetta o non riconosciuta, puoi esaminare il contenuto del file per determinare cosa fa e se è legittimo o meno. Puoi anche cercare informazioni online sul nome dell'attività o del file per ottenere ulteriori dettagli.

Se necessario, puoi disabilitare o rimuovere un'attività pianificata utilizzando il comando `crontab -e` per modificare il file delle attività pianificate dell'utente corrente o rimuovendo il file corrispondente nella directory `/etc/cron.d/`.

Ricorda di fare attenzione quando modifichi o rimuovi le attività pianificate, in quanto potresti influire sul normale funzionamento del sistema.
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
- **/etc/init.d/**: Utilizzato in alcune versioni di Linux come Debian per memorizzare gli script di avvio.
- I servizi possono anche essere attivati tramite **/etc/inetd.conf** o **/etc/xinetd/**, a seconda della variante di Linux.
- **/etc/systemd/system**: Una directory per gli script di sistema e di gestione dei servizi.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene collegamenti ai servizi che devono essere avviati in un runlevel multiutente.
- **/usr/local/etc/rc.d/**: Per servizi personalizzati o di terze parti.
- **~/.config/autostart/**: Per applicazioni di avvio automatico specifiche dell'utente, che possono essere un nascondiglio per malware mirati agli utenti.
- **/lib/systemd/system/**: File di unità predefiniti a livello di sistema forniti dai pacchetti installati.


### Moduli del kernel

I moduli del kernel di Linux, spesso utilizzati dai malware come componenti rootkit, vengono caricati all'avvio del sistema. Le directory e i file critici per questi moduli includono:

- **/lib/modules/$(uname -r)**: Contiene i moduli per la versione del kernel in esecuzione.
- **/etc/modprobe.d**: Contiene file di configurazione per controllare il caricamento dei moduli.
- **/etc/modprobe** e **/etc/modprobe.conf**: File per le impostazioni globali dei moduli.

### Altre posizioni di avvio automatico

Linux utilizza vari file per eseguire automaticamente programmi all'accesso dell'utente, potenzialmente ospitando malware:

- **/etc/profile.d/***, **/etc/profile** e **/etc/bash.bashrc**: Eseguiti per qualsiasi accesso dell'utente.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** e **~/.config/autostart**: File specifici dell'utente che vengono eseguiti al loro accesso.
- **/etc/rc.local**: Eseguito dopo che tutti i servizi di sistema sono stati avviati, segnando la fine della transizione verso un ambiente multiutente.

## Esaminare i log

I sistemi Linux tengono traccia delle attività degli utenti e degli eventi di sistema attraverso vari file di log. Questi log sono fondamentali per identificare accessi non autorizzati, infezioni da malware e altri incidenti di sicurezza. I principali file di log includono:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Registrano i messaggi e le attività di tutto il sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registrano i tentativi di autenticazione, i login riusciti e falliti.
- Utilizzare `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` per filtrare gli eventi di autenticazione rilevanti.
- **/var/log/boot.log**: Contiene i messaggi di avvio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registrazione delle attività del server di posta, utile per tracciare i servizi correlati alla posta elettronica.
- **/var/log/kern.log**: Archivia i messaggi del kernel, inclusi errori e avvisi.
- **/var/log/dmesg**: Contiene i messaggi del driver del dispositivo.
- **/var/log/faillog**: Registra i tentativi di accesso falliti, aiutando nelle indagini sulle violazioni di sicurezza.
- **/var/log/cron**: Registra l'esecuzione dei lavori cron.
- **/var/log/daemon.log**: Monitora le attività dei servizi in background.
- **/var/log/btmp**: Documenta i tentativi di accesso falliti.
- **/var/log/httpd/**: Contiene i log degli errori e degli accessi di Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registra le attività del database MySQL.
- **/var/log/xferlog**: Registra i trasferimenti di file FTP.
- **/var/log/**: Controllare sempre la presenza di log inaspettati qui.

{% hint style="info" %}
I log di sistema e i sottosistemi di audit di Linux possono essere disabilitati o eliminati in caso di intrusioni o incidenti di malware. Poiché i log sui sistemi Linux generalmente contengono alcune delle informazioni più utili sulle attività maligne, gli intrusi li eliminano regolarmente. Pertanto, quando si esaminano i file di log disponibili, è importante cercare lacune o voci fuori ordine che potrebbero indicare eliminazione o manomissione.
{% endhint %}

**Linux mantiene una cronologia dei comandi per ogni utente**, memorizzata in:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Inoltre, il comando `last -Faiwx` fornisce un elenco dei login degli utenti. Controllalo per verificare la presenza di accessi sconosciuti o inaspettati.

Controlla i file che possono concedere privilegi aggiuntivi:

- Verifica `/etc/sudoers` per privilegi utente non previsti che potrebbero essere stati concessi.
- Verifica `/etc/sudoers.d/` per privilegi utente non previsti che potrebbero essere stati concessi.
- Esamina `/etc/groups` per identificare eventuali appartenenze o autorizzazioni di gruppo insolite.
- Esamina `/etc/passwd` per identificare eventuali appartenenze o autorizzazioni di gruppo insolite.

Alcune applicazioni generano anche i propri log:

- **SSH**: Esamina _~/.ssh/authorized_keys_ e _~/.ssh/known_hosts_ per connessioni remote non autorizzate.
- **Desktop Gnome**: Controlla _~/.recently-used.xbel_ per i file recentemente accessati tramite le applicazioni Gnome.
- **Firefox/Chrome**: Verifica la cronologia del browser e i download in _~/.mozilla/firefox_ o _~/.config/google-chrome_ per attività sospette.
- **VIM**: Esamina _~/.viminfo_ per i dettagli sull'utilizzo, come i percorsi dei file accessati e la cronologia delle ricerche.
- **Open Office**: Verifica gli accessi recenti ai documenti che potrebbero indicare file compromessi.
- **FTP/SFTP**: Controlla i log in _~/.ftp_history_ o _~/.sftp_history_ per i trasferimenti di file che potrebbero essere non autorizzati.
- **MySQL**: Indaga su _~/.mysql_history_ per le query MySQL eseguite, rivelando potenziali attività non autorizzate sul database.
- **Less**: Analizza _~/.lesshst_ per la cronologia dell'utilizzo, inclusi i file visualizzati e i comandi eseguiti.
- **Git**: Esamina _~/.gitconfig_ e il progetto _.git/logs_ per le modifiche ai repository.

### Log USB

[**usbrip**](https://github.com/snovvcrash/usbrip) è un piccolo software scritto in Python 3 puro che analizza i file di log di Linux (`/var/log/syslog*` o `/var/log/messages*` a seconda della distribuzione) per costruire tabelle di cronologia degli eventi USB.

È interessante **conoscere tutte le USB che sono state utilizzate** e sarà ancora più utile se si dispone di un elenco autorizzato di USB per individuare "eventi di violazione" (l'uso di USB che non sono presenti in quell'elenco).

### Installazione
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Esempi

#### Esempio 1: Analisi delle informazioni di sistema

Per ottenere informazioni sul sistema Linux, è possibile utilizzare i seguenti comandi:

```bash
$ uname -a
$ cat /etc/issue
$ cat /etc/*-release
$ cat /proc/version
$ cat /proc/cpuinfo
$ cat /proc/meminfo
$ cat /proc/mounts
$ cat /proc/net/dev
$ cat /proc/net/route
$ cat /proc/net/tcp
$ cat /proc/net/udp
$ cat /proc/net/icmp
$ cat /proc/net/ip_conntrack
$ cat /proc/net/ip_tables_matches
$ cat /proc/net/ip_tables_names
$ cat /proc/net/ip_tables_targets
$ cat /proc/net/ip6_tables_matches
$ cat /proc/net/ip6_tables_names
$ cat /proc/net/ip6_tables_targets
$ cat /proc/net/arp
$ cat /proc/net/igmp
$ cat /proc/net/unix
$ cat /proc/net/wireless
$ cat /proc/net/sockstat
$ cat /proc/net/snmp
$ cat /proc/net/sockstat6
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net/softnet_stat
$ cat /proc/net
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Ulteriori esempi e informazioni sono disponibili su GitHub: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Esamina gli Account Utente e le Attività di Accesso

Esamina i file _**/etc/passwd**_, _**/etc/shadow**_ e i **log di sicurezza** per individuare nomi o account insoliti creati e/o utilizzati in prossimità di eventi non autorizzati noti. Inoltre, controlla possibili attacchi di forza bruta su sudo.\
Inoltre, verifica i file come _**/etc/sudoers**_ e _**/etc/groups**_ per privilegi inaspettati assegnati agli utenti.\
Infine, cerca account senza password o con password facilmente indovinabili.

## Esamina il File System

### Analisi delle Strutture del File System nell'Investigazione di Malware

Nell'indagine sugli incidenti di malware, la struttura del file system è una fonte di informazioni cruciale, che rivela sia la sequenza degli eventi che il contenuto del malware. Tuttavia, gli autori di malware stanno sviluppando tecniche per ostacolare questa analisi, come la modifica dei timestamp dei file o l'evitare il file system per l'archiviazione dei dati.

Per contrastare questi metodi anti-forensi, è essenziale:

- **Condurre un'analisi temporale approfondita** utilizzando strumenti come **Autopsy** per visualizzare le sequenze temporali degli eventi o `mactime` di **Sleuth Kit** per dati temporali dettagliati.
- **Investigare script inaspettati** nel $PATH del sistema, che potrebbero includere script shell o PHP utilizzati dagli attaccanti.
- **Esaminare `/dev` per individuare file atipici**, poiché tradizionalmente contiene file speciali, ma potrebbe ospitare file correlati al malware.
- **Cercare file o directory nascoste** con nomi come ".. " (punto punto spazio) o "..^G" (punto punto control-G), che potrebbero nascondere contenuti maligni.
- **Identificare file setuid root** utilizzando il comando:
```find / -user root -perm -04000 -print```
Questo trova file con permessi elevati, che potrebbero essere sfruttati dagli attaccanti.
- **Esaminare i timestamp di cancellazione** nelle tabelle degli inode per individuare cancellazioni di file di massa, indicando possibilmente la presenza di rootkit o trojan.
- **Ispezionare gli inode consecutivi** per individuare file maligni vicini dopo averne identificato uno, poiché potrebbero essere stati posizionati insieme.
- **Controllare le directory binarie comuni** (_/bin_, _/sbin_) per file modificati di recente, poiché potrebbero essere stati alterati dal malware.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Nota che un **attaccante** può **modificare** l'**ora** per far **apparire** i **file legittimi**, ma non può modificare l'**inode**. Se scopri che un **file** indica che è stato creato e modificato allo **stesso tempo** degli altri file nella stessa cartella, ma l'**inode** è **inesperientemente più grande**, allora i **timestamp di quel file sono stati modificati**.
{% endhint %}

## Confrontare file di diverse versioni del filesystem

### Riassunto del confronto delle versioni del filesystem

Per confrontare le versioni del filesystem e individuare le modifiche, utilizziamo comandi semplificati di `git diff`:

- **Per trovare nuovi file**, confronta due directory:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Per contenuto modificato**, elenca le modifiche ignorando le linee specifiche:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Per rilevare file eliminati**:

```bash
$ sudo find / -type f -name "*.deleted" -print
```

Questo comando cerca tutti i file con l'estensione ".deleted" nel sistema operativo Linux.
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opzioni di filtro** (`--diff-filter`) aiutano a restringere le modifiche specifiche come file aggiunti (`A`), file eliminati (`D`) o file modificati (`M`).
- `A`: File aggiunti
- `C`: File copiati
- `D`: File eliminati
- `M`: File modificati
- `R`: File rinominati
- `T`: Cambiamenti di tipo (ad esempio, file a collegamento simbolico)
- `U`: File non uniti
- `X`: File sconosciuti
- `B`: File danneggiati

## Riferimenti

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Libro: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!

* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** basati sugli strumenti comunitari più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
