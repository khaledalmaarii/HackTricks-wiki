# Linux-Forensik

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Initiale Informationsbeschaffung

### Grundlegende Informationen

Zunächst wird empfohlen, einen **USB-Stick** mit **bekannten guten Binärdateien und Bibliotheken** zu haben (Sie können einfach Ubuntu nehmen und die Ordner _/bin_, _/sbin_, _/lib_ und _/lib64_ kopieren), dann den USB-Stick mounten und die Umgebungsvariablen ändern, um diese Binärdateien zu verwenden:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sobald Sie das System so konfiguriert haben, dass gute und bekannte Binärdateien verwendet werden, können Sie damit beginnen, **grundlegende Informationen zu extrahieren**:
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
#### Verdächtige Informationen

Bei der Beschaffung grundlegender Informationen sollten Sie nach seltsamen Dingen wie folgt suchen:

* **Root-Prozesse** laufen normalerweise mit niedrigen PIDs. Wenn Sie also einen Root-Prozess mit einer großen PID finden, können Sie Verdacht schöpfen.
* Überprüfen Sie **registrierte Anmeldungen** von Benutzern ohne Shell in `/etc/passwd`.
* Überprüfen Sie nach **Passwort-Hashes** von Benutzern ohne Shell in `/etc/shadow`.

### Speicherabbild

Um den Speicher des laufenden Systems zu erhalten, wird empfohlen, [**LiME**](https://github.com/504ensicsLabs/LiME) zu verwenden.\
Um es **zu kompilieren**, müssen Sie den **gleichen Kernel** verwenden, den die Opfermaschine verwendet.

{% hint style="info" %}
Denken Sie daran, dass Sie **LiME oder irgendetwas anderes** nicht in der Opfermaschine installieren können, da dies mehrere Änderungen daran vornehmen würde.
{% endhint %}

Wenn Sie also eine identische Version von Ubuntu haben, können Sie `apt-get install lime-forensics-dkms` verwenden.\
In anderen Fällen müssen Sie [**LiME**](https://github.com/504ensicsLabs/LiME) von GitHub herunterladen und mit den richtigen Kernel-Headern kompilieren. Um die genauen Kernel-Header der Opfermaschine zu erhalten, können Sie einfach das Verzeichnis `/lib/modules/<Kernel-Version>` auf Ihren Computer kopieren und dann LiME damit kompilieren:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME unterstützt 3 **Formate**:

* Raw (jedes Segment zusammengefügt)
* Gepolstert (wie Raw, aber mit Nullen in den rechten Bits)
* Lime (empfohlenes Format mit Metadaten)

LiME kann auch verwendet werden, um das Dump über das Netzwerk zu **senden**, anstatt es im System zu speichern, indem man etwas wie `path=tcp:4444` verwendet.

### Disk-Imaging

#### Herunterfahren

Zunächst müssen Sie das System **herunterfahren**. Dies ist nicht immer eine Option, da das System manchmal ein Produktivserver ist, den sich das Unternehmen nicht leisten kann herunterzufahren.\
Es gibt **2 Möglichkeiten**, das System herunterzufahren: ein **normales Herunterfahren** und ein **"Stecker ziehen" Herunterfahren**. Das erste ermöglicht es den **Prozessen, wie gewohnt zu beenden** und das **Dateisystem** zu **synchronisieren**, aber es ermöglicht auch möglicherweise der **Malware**, Beweise zu **zerstören**. Der Ansatz "Stecker ziehen" kann **einen gewissen Informationsverlust** mit sich bringen (nicht viel Information geht verloren, da wir bereits ein Abbild des Speichers erstellt haben) und die **Malware hat keine Möglichkeit**, etwas dagegen zu unternehmen. Wenn Sie also **vermuten**, dass möglicherweise eine **Malware** vorhanden ist, führen Sie einfach den **`sync`** **Befehl** auf dem System aus und ziehen Sie den Stecker.

#### Erstellen eines Abbilds der Festplatte

Es ist wichtig zu beachten, dass **bevor Sie Ihren Computer mit etwas in Verbindung bringen, das mit dem Fall zusammenhängt**, Sie sicherstellen müssen, dass es als **nur lesend** eingebunden wird, um keine Informationen zu ändern.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Voranalyse des Festplattenabbilds

Erstellen eines Abbilds der Festplatte ohne weitere Daten.
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

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Suche nach bekannten Malware

### Modifizierte Systemdateien

Linux bietet Tools zur Sicherstellung der Integrität von Systemkomponenten, die zur Erkennung potenziell problematischer Dateien dienen.

- **RedHat-basierte Systeme**: Verwenden Sie `rpm -Va` für eine umfassende Überprüfung.
- **Debian-basierte Systeme**: `dpkg --verify` für die erste Überprüfung, gefolgt von `debsums | grep -v "OK$"` (nach der Installation von `debsums` mit `apt-get install debsums`), um mögliche Probleme zu identifizieren.

### Malware/Rootkit-Detektoren

Lesen Sie die folgende Seite, um mehr über Tools zu erfahren, die zur Suche nach Malware nützlich sein können:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Suche nach installierten Programmen

Um effektiv nach installierten Programmen in Debian- und RedHat-Systemen zu suchen, sollten Sie neben manuellen Überprüfungen in gängigen Verzeichnissen auch Systemprotokolle und Datenbanken nutzen.

- Bei Debian überprüfen Sie **_`/var/lib/dpkg/status`_** und **_`/var/log/dpkg.log`_**, um Details über die Installation von Paketen abzurufen, und verwenden Sie `grep`, um nach spezifischen Informationen zu filtern.

- RedHat-Benutzer können die RPM-Datenbank mit `rpm -qa --root=/mntpath/var/lib/rpm` abfragen, um installierte Pakete aufzulisten.

Um Software zu finden, die manuell oder außerhalb dieser Paketverwaltungsprogramme installiert wurde, erkunden Sie Verzeichnisse wie **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_** und **_`/sbin`_**. Kombinieren Sie Verzeichnisauflistungen mit systemspezifischen Befehlen, um ausführbare Dateien zu identifizieren, die nicht mit bekannten Paketen in Verbindung stehen, und verbessern Sie so Ihre Suche nach allen installierten Programmen.
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

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Wiederherstellen gelöschter ausführbarer Dateien

Stellen Sie sich einen Prozess vor, der von /tmp/exec ausgeführt und gelöscht wurde. Es ist möglich, ihn wiederherzustellen.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
### Geplante Aufgaben

Scheduled Tasks sind Aufgaben, die zu bestimmten Zeiten oder Ereignissen automatisch ausgeführt werden. Sie können verwendet werden, um Programme oder Skripte zu starten. In Linux können Sie die geplanten Aufgaben überprüfen, um verdächtige Aktivitäten zu identifizieren.

Um die geplanten Aufgaben in Linux zu überprüfen, können Sie den Befehl `crontab -l` verwenden. Dieser Befehl zeigt die geplanten Aufgaben für den aktuellen Benutzer an.

```bash
$ crontab -l
```

Sie können auch den Inhalt des Verzeichnisses `/etc/cron.d` überprüfen, um weitere geplante Aufgaben zu finden.

```bash
$ ls -l /etc/cron.d
```

Überprüfen Sie die geplanten Aufgaben auf verdächtige Einträge, die auf mögliche Angriffe oder ungewöhnliche Aktivitäten hinweisen könnten.
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
### Dienste

Pfade, an denen sich Malware als Dienst installieren könnte:

- **/etc/inittab**: Ruft Initialisierungsskripte wie rc.sysinit auf und leitet sie an Startskripte weiter.
- **/etc/rc.d/** und **/etc/rc.boot/**: Enthalten Skripte für den Start von Diensten, wobei letzteres in älteren Linux-Versionen zu finden ist.
- **/etc/init.d/**: Wird in bestimmten Linux-Versionen wie Debian zum Speichern von Startskripten verwendet.
- Dienste können auch über **/etc/inetd.conf** oder **/etc/xinetd/** aktiviert werden, abhängig von der Linux-Variante.
- **/etc/systemd/system**: Ein Verzeichnis für System- und Dienstmanager-Skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Enthält Links zu Diensten, die in einem Multi-User-Runlevel gestartet werden sollen.
- **/usr/local/etc/rc.d/**: Für benutzerdefinierte oder Drittanbieterdienste.
- **~/.config/autostart/**: Für benutzerspezifische automatische Startanwendungen, die ein Versteck für auf Benutzer abzielende Malware sein können.
- **/lib/systemd/system/**: Systemweite Standard-Einheitsdateien, die von installierten Paketen bereitgestellt werden.


### Kernel-Module

Linux-Kernel-Module, die von Malware häufig als Rootkit-Komponenten verwendet werden, werden beim Systemstart geladen. Die für diese Module kritischen Verzeichnisse und Dateien sind:

- **/lib/modules/$(uname -r)**: Enthält Module für die aktuell verwendete Kernel-Version.
- **/etc/modprobe.d**: Enthält Konfigurationsdateien zur Steuerung des Modulladens.
- **/etc/modprobe** und **/etc/modprobe.conf**: Dateien für globale Moduleinstellungen.

### Andere Autostart-Positionen

Linux verwendet verschiedene Dateien, um Programme automatisch beim Benutzerlogin auszuführen, die potenziell Malware beherbergen können:

- **/etc/profile.d/***, **/etc/profile** und **/etc/bash.bashrc**: Werden bei jedem Benutzerlogin ausgeführt.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** und **~/.config/autostart**: Benutzerspezifische Dateien, die beim Benutzerlogin ausgeführt werden.
- **/etc/rc.local**: Wird nach dem Start aller Systemdienste ausgeführt und markiert das Ende des Übergangs in eine Multi-User-Umgebung.

## Untersuchung von Protokollen

Linux-Systeme verfolgen Benutzeraktivitäten und Systemereignisse in verschiedenen Protokolldateien. Diese Protokolle sind entscheidend, um unbefugten Zugriff, Malware-Infektionen und andere Sicherheitsvorfälle zu identifizieren. Zu den wichtigsten Protokolldateien gehören:

- **/var/log/syslog** (Debian) oder **/var/log/messages** (RedHat): Erfassen systemweite Nachrichten und Aktivitäten.
- **/var/log/auth.log** (Debian) oder **/var/log/secure** (RedHat): Protokollieren von Authentifizierungsversuchen, erfolgreichen und fehlgeschlagenen Anmeldungen.
- Verwenden Sie `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, um relevante Authentifizierungsereignisse zu filtern.
- **/var/log/boot.log**: Enthält Systemstartnachrichten.
- **/var/log/maillog** oder **/var/log/mail.log**: Protokollieren von E-Mail-Serveraktivitäten, nützlich zur Verfolgung von E-Mail-bezogenen Diensten.
- **/var/log/kern.log**: Speichert Kernel-Nachrichten, einschließlich Fehler und Warnungen.
- **/var/log/dmesg**: Enthält Gerätetreiber-Nachrichten.
- **/var/log/faillog**: Protokolliert fehlgeschlagene Anmeldeversuche und unterstützt die Untersuchung von Sicherheitsverletzungen.
- **/var/log/cron**: Protokolliert die Ausführung von Cron-Jobs.
- **/var/log/daemon.log**: Verfolgt Aktivitäten von Hintergrunddiensten.
- **/var/log/btmp**: Dokumentiert fehlgeschlagene Anmeldeversuche.
- **/var/log/httpd/**: Enthält Apache HTTPD-Fehler- und Zugriffsprotokolle.
- **/var/log/mysqld.log** oder **/var/log/mysql.log**: Protokollieren von MySQL-Datenbankaktivitäten.
- **/var/log/xferlog**: Protokolliert FTP-Dateiübertragungen.
- **/var/log/**: Überprüfen Sie immer auf unerwartete Protokolleinträge.

{% hint style="info" %}
Linux-Systemprotokolle und Überwachungsunterstützung können in einem Eindringlings- oder Malware-Vorfall deaktiviert oder gelöscht werden. Da Protokolle auf Linux-Systemen in der Regel einige der nützlichsten Informationen über bösartige Aktivitäten enthalten, löschen Eindringlinge sie routinemäßig. Daher ist es bei der Untersuchung verfügbarer Protokolldateien wichtig, nach Lücken oder nicht in der richtigen Reihenfolge vorhandenen Einträgen zu suchen, die auf Löschung oder Manipulation hinweisen könnten.
{% endhint %}

**Linux speichert eine Befehlshistorie für jeden Benutzer**, die in folgenden Dateien gespeichert ist:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Darüber hinaus liefert der Befehl `last -Faiwx` eine Liste der Benutzeranmeldungen. Überprüfen Sie sie auf unbekannte oder unerwartete Anmeldungen.

Überprüfen Sie Dateien, die zusätzliche Berechtigungen gewähren können:

- Überprüfen Sie `/etc/sudoers` auf unerwartete Benutzerberechtigungen, die möglicherweise gewährt wurden.
- Überprüfen Sie `/etc/sudoers.d/` auf unerwartete Benutzerberechtigungen, die möglicherweise gewährt wurden.
- Untersuchen Sie `/etc/groups`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.
- Untersuchen Sie `/etc/passwd`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.

Einige Apps generieren auch ihre eigenen Protokolle:

- **SSH**: Überprüfen Sie _~/.ssh/authorized_keys_ und _~/.ssh/known_hosts_ auf nicht autorisierte Remote-Verbindungen.
- **Gnome Desktop**: Schauen Sie in _~/.recently-used.xbel_ nach kürzlich über Gnome-Anwendungen zugegriffenen Dateien.
- **Firefox/Chrome**: Überprüfen Sie den Browserverlauf und die Downloads in _~/.mozilla/firefox_ oder _~/.config/google-chrome_ auf verdächtige Aktivitäten.
- **VIM**: Überprüfen Sie _~/.viminfo_ auf Details zur Verwendung, wie z. B. aufgerufene Dateipfade und Suchverlauf.
- **Open Office**: Überprüfen Sie den Zugriff auf kürzlich verwendete Dokumente, die auf kompromittierte Dateien hinweisen können.
- **FTP/SFTP**: Überprüfen Sie Protokolle in _~/.ftp_history_ oder _~/.sftp_history_ auf Dateiübertragungen, die möglicherweise nicht autorisiert sind.
- **MySQL**: Untersuchen Sie _~/.mysql_history_ auf ausgeführte MySQL-Abfragen, die möglicherweise nicht autorisierte Datenbankaktivitäten aufdecken.
- **Less**: Analysieren Sie _~/.lesshst_ auf Verlaufsinformationen, einschließlich angezeigter Dateien und ausgeführter Befehle.
- **Git**: Untersuchen Sie _~/.gitconfig_ und das Projekt _.git/logs_ auf Änderungen an Repositories.

### USB-Protokolle

[**usbrip**](https://github.com/snovvcrash/usbrip) ist eine kleine Software, die in reinem Python 3 geschrieben ist und Linux-Protokolldateien (`/var/log/syslog*` oder `/var/log/messages*`, abhängig von der Distribution) analysiert, um USB-Ereignishistorien zu erstellen.

Es ist interessant zu **wissen, welche USB-Geräte verwendet wurden**, und es ist nützlicher, wenn Sie eine autorisierte Liste von USB-Geräten haben, um "Verstoßereignisse" (die Verwendung von USB-Geräten, die nicht in dieser Liste enthalten sind) zu finden.

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Beispiele

#### Example 1: Collecting System Information

#### Beispiel 1: Sammeln von Systeminformationen

To gather information about the Linux system, you can use the following commands:

Um Informationen über das Linux-System zu sammeln, können Sie die folgenden Befehle verwenden:

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
$ cat /proc/net/arp
$ cat /proc/net/tcp
$ cat /proc/net/udp
$ cat /proc/net/raw
$ cat /proc/net/unix
$ cat /proc/net/snmp
$ cat /proc/net/icmp
$ cat /proc/net/igmp
$ cat /proc/net/ipx
$ cat /proc/net/ax25
$ cat /proc/net/appletalk
$ cat /proc/net/nr
$ cat /proc/net/ip_conntrack
$ cat /proc/net/ip_conntrack_expect
$ cat /proc/net/ip6_conntrack
$ cat /proc/net/ip6_conntrack_expect
$ cat /proc/net/ip_tables_names
$ cat /proc/net/ip_tables_matches
$ cat /proc/net/ip_tables_targets
$ cat /proc/net/xt_recent
$ cat /proc/net/xt_recent/DEFAULT
$ cat /proc/net/xt_recent/DEFAULT/expire
$ cat /proc/net/xt_recent/DEFAULT/gc_thresh
$ cat /proc/net/xt_recent/DEFAULT/lock
$ cat /proc/net/xt_recent/DEFAULT/locktime
$ cat /proc/net/xt_recent/DEFAULT/max
$ cat /proc/net/xt_recent/DEFAULT/num
$ cat /proc/net/xt_recent/DEFAULT/refresh
$ cat /proc/net/xt_recent/DEFAULT/timeout
$ cat /proc/net/xt_recent/DEFAULT/uid
$ cat /proc/net/xt_recent/DEFAULT/update
$ cat /proc/net/xt_recent/DEFAULT/use
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc/net/xt_recent/DEFAULT/visited
$ cat /proc
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Weitere Beispiele und Informationen finden Sie auf GitHub: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Überprüfen von Benutzerkonten und Anmeldeaktivitäten

Überprüfen Sie die Dateien _**/etc/passwd**_, _**/etc/shadow**_ und **Sicherheitsprotokolle** auf ungewöhnliche Namen oder Konten, die in der Nähe bekannter unbefugter Ereignisse erstellt oder verwendet wurden. Überprüfen Sie auch mögliche sudo-Brute-Force-Angriffe.\
Überprüfen Sie außerdem Dateien wie _**/etc/sudoers**_ und _**/etc/groups**_ auf unerwartete Berechtigungen für Benutzer.\
Suchen Sie schließlich nach Konten ohne Passwörter oder leicht zu erratenden Passwörtern.

## Dateisystem untersuchen

### Analyse von Dateisystemstrukturen bei der Untersuchung von Malware

Bei der Untersuchung von Malware-Vorfällen ist die Struktur des Dateisystems eine wichtige Informationsquelle, die sowohl die Ereignisabfolge als auch den Inhalt der Malware offenbart. Malware-Autoren entwickeln jedoch Techniken, um diese Analyse zu erschweren, z. B. durch Änderung der Dateizeitstempel oder Vermeidung des Dateisystems zur Datenspeicherung.

Um diesen anti-forensischen Methoden entgegenzuwirken, ist es wichtig:

- **Eine gründliche Zeitachsenanalyse** durchzuführen, indem Tools wie **Autopsy** zur Visualisierung von Ereigniszeitachsen oder **Sleuth Kit's** `mactime` zur detaillierten Zeitachsen-Datenanalyse verwendet werden.
- **Unerwartete Skripte** im $PATH des Systems zu untersuchen, die Shell- oder PHP-Skripte enthalten könnten, die von Angreifern verwendet werden.
- **`/dev` nach untypischen Dateien** zu durchsuchen, da es traditionell spezielle Dateien enthält, aber auch malwarebezogene Dateien enthalten kann.
- Nach versteckten Dateien oder Verzeichnissen** mit Namen wie ".. " (Punkt Punkt Leerzeichen) oder "..^G" (Punkt Punkt Steuerung-G) zu suchen, die bösartigen Inhalt verbergen könnten.
- **Setuid-Root-Dateien zu identifizieren**, indem der Befehl verwendet wird:
```find / -user root -perm -04000 -print```
Dies findet Dateien mit erhöhten Berechtigungen, die von Angreifern missbraucht werden könnten.
- **Löschungszeitstempel** in Inode-Tabellen zu überprüfen, um Massenlöschungen von Dateien zu erkennen, die möglicherweise auf das Vorhandensein von Rootkits oder Trojanern hinweisen.
- **Aufeinanderfolgende Inodes** nach einer Identifizierung einer bösartigen Datei auf nahegelegene bösartige Dateien zu überprüfen, da sie möglicherweise zusammen platziert wurden.
- **Gängige binäre Verzeichnisse** (_/bin_, _/sbin_) auf kürzlich geänderte Dateien zu überprüfen, da diese von Malware verändert worden sein könnten.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Beachten Sie, dass ein **Angreifer** die **Zeit** ändern kann, um **Dateien als legitim** erscheinen zu lassen, aber er kann das **Inode** nicht ändern. Wenn Sie feststellen, dass eine **Datei angibt**, dass sie zur **gleichen Zeit** wie die anderen Dateien im selben Ordner erstellt und geändert wurde, aber das **Inode** unerwartet größer ist, dann wurden die **Zeitstempel dieser Datei geändert**.
{% endhint %}

## Vergleich von Dateien verschiedener Dateisystemversionen

### Zusammenfassung des Vergleichs der Dateisystemversionen

Um Dateisystemversionen zu vergleichen und Änderungen zu ermitteln, verwenden wir vereinfachte `git diff`-Befehle:

- **Um neue Dateien zu finden**, vergleichen Sie zwei Verzeichnisse:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Für modifizierten Inhalt**, listen Sie Änderungen auf, während Sie spezifische Zeilen ignorieren:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Zum Erkennen gelöschter Dateien**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filteroptionen** (`--diff-filter`) helfen dabei, die Suche auf bestimmte Änderungen wie hinzugefügte (`A`), gelöschte (`D`) oder modifizierte (`M`) Dateien einzugrenzen.
- `A`: Hinzugefügte Dateien
- `C`: Kopierte Dateien
- `D`: Gelöschte Dateien
- `M`: Modifizierte Dateien
- `R`: Umbenannte Dateien
- `T`: Typänderungen (z. B. Datei zu Symlink)
- `U`: Nicht zusammengeführte Dateien
- `X`: Unbekannte Dateien
- `B`: Beschädigte Dateien

## Referenzen

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Buch: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!

* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
