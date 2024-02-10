# AppArmor

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>

## Grundlegende Informationen

AppArmor ist eine **Kernel-Erweiterung, die die Ressourcen, die Programmen zur Verfügung stehen, durch programmbezogene Profile einschränkt** und damit eine Mandatory Access Control (MAC) implementiert, indem sie Zugriffskontrollattribute direkt an Programme bindet, anstatt an Benutzer. Dieses System funktioniert, indem Profile in den Kernel geladen werden, normalerweise beim Booten, und diese Profile bestimmen, auf welche Ressourcen ein Programm zugreifen kann, wie z.B. Netzwerkverbindungen, Zugriff auf Raw Sockets und Dateiberechtigungen.

Es gibt zwei Betriebsmodi für AppArmor-Profile:

- **Durchsetzungsmodus**: In diesem Modus werden die in dem Profil definierten Richtlinien aktiv durchgesetzt. Aktionen, die gegen diese Richtlinien verstoßen, werden blockiert und alle Versuche, diese zu umgehen, werden über Systeme wie syslog oder auditd protokolliert.
- **Beschwerdemodus**: Im Gegensatz zum Durchsetzungsmodus blockiert der Beschwerdemodus keine Aktionen, die gegen die Richtlinien des Profils verstoßen. Stattdessen werden diese Versuche als Verstoß gegen die Richtlinien protokolliert, ohne Einschränkungen durchzusetzen.

### Komponenten von AppArmor

- **Kernelmodul**: Verantwortlich für die Durchsetzung von Richtlinien.
- **Richtlinien**: Spezifizieren die Regeln und Einschränkungen für das Verhalten von Programmen und den Zugriff auf Ressourcen.
- **Parser**: Lädt Richtlinien in den Kernel zur Durchsetzung oder Berichterstattung.
- **Dienstprogramme**: Dies sind benutzermodus-Programme, die eine Schnittstelle zur Interaktion mit und Verwaltung von AppArmor bereitstellen.

### Profile-Pfad

AppArmor-Profile werden normalerweise in _**/etc/apparmor.d/**_ gespeichert.\
Mit `sudo aa-status` können Sie die Binärdateien auflisten, die durch ein Profil eingeschränkt sind. Wenn Sie den Schrägstrich "/" durch einen Punkt im Pfad jeder aufgelisteten Binärdatei ersetzen, erhalten Sie den Namen des AppArmor-Profils im genannten Ordner.

Zum Beispiel befindet sich ein **AppArmor**-Profil für _/usr/bin/man_ in _/etc/apparmor.d/usr.bin.man_

### Befehle
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Erstellen eines Profils

* Um das betroffene ausführbare Programm anzugeben, sind **absolute Pfade und Platzhalter** (für Dateiglobbing) erlaubt, um Dateien zu spezifizieren.
* Um den Zugriff des Binärprogramms auf **Dateien** anzugeben, können folgende **Zugriffskontrollen** verwendet werden:
* **r** (lesen)
* **w** (schreiben)
* **m** (als ausführbar in den Speicher abbilden)
* **k** (Dateisperrung)
* **l** (Erstellen von Hardlinks)
* **ix** (ein anderes Programm mit dem neuen Programm ausführen, das die Richtlinie erbt)
* **Px** (unter einem anderen Profil ausführen, nachdem die Umgebung bereinigt wurde)
* **Cx** (unter einem Kindprofil ausführen, nachdem die Umgebung bereinigt wurde)
* **Ux** (unbeschränkt ausführen, nachdem die Umgebung bereinigt wurde)
* **Variablen** können in den Profilen definiert und von außerhalb des Profils manipuliert werden. Zum Beispiel: @{PROC} und @{HOME} (fügen Sie #include \<tunables/global> zur Profildatei hinzu)
* **Deny-Regeln werden unterstützt, um Allow-Regeln zu überschreiben**.

### aa-genprof

Um das Erstellen eines Profils zu erleichtern, kann Ihnen AppArmor helfen. Es ist möglich, **AppArmor die Aktionen, die von einem Binärprogramm ausgeführt werden, überprüfen zu lassen und dann zu entscheiden, welche Aktionen Sie erlauben oder ablehnen möchten**.\
Sie müssen nur Folgendes ausführen:
```bash
sudo aa-genprof /path/to/binary
```
Dann führen Sie in einer anderen Konsole alle Aktionen aus, die das Binärprogramm normalerweise ausführt:
```bash
/path/to/binary -a dosomething
```
Dann drücken Sie in der ersten Konsole "**s**" und geben Sie dann die aufgezeichneten Aktionen an, ob Sie sie ignorieren, erlauben oder was auch immer möchten. Wenn Sie fertig sind, drücken Sie "**f**" und das neue Profil wird in _/etc/apparmor.d/path.to.binary_ erstellt.

{% hint style="info" %}
Mit den Pfeiltasten können Sie auswählen, was Sie erlauben/ablehnen/machen möchten.
{% endhint %}

### aa-easyprof

Sie können auch eine Vorlage für ein AppArmor-Profil einer Binärdatei erstellen mit:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Beachten Sie, dass standardmäßig in einem erstellten Profil nichts erlaubt ist, daher wird alles abgelehnt. Sie müssen Zeilen wie `/etc/passwd r,` hinzufügen, um beispielsweise das Lesen der Binärdatei `/etc/passwd` zu ermöglichen.
{% endhint %}

Sie können dann das neue Profil **erzwingen** mit
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Ändern eines Profils aus Protokollen

Das folgende Tool liest die Protokolle und fragt den Benutzer, ob er einige der erkannten verbotenen Aktionen erlauben möchte:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Mit den Pfeiltasten können Sie auswählen, was Sie erlauben/ablehnen/whatever möchten.
{% endhint %}

### Profil verwalten
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Protokolle

Beispiel für **AUDIT**- und **DENIED**-Protokolle aus _/var/log/audit/audit.log_ der ausführbaren Datei **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Sie können diese Informationen auch mit folgendem Befehl abrufen:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

Beachten Sie, wie das Profil **docker-profile** von Docker standardmäßig geladen wird:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Standardmäßig wird das **Apparmor docker-default-Profil** von [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) generiert.

**Zusammenfassung des docker-default-Profils**:

* **Zugriff** auf alle **Netzwerke**
* Es sind **keine Berechtigungen** definiert (Einige Berechtigungen werden jedoch durch das Einbinden grundlegender Basisregeln wie #include \<abstractions/base> gewährt)
* Das **Schreiben** in beliebige **/proc**-Dateien ist **nicht erlaubt**
* Andere **Unterverzeichnisse**/**Dateien** von /**proc** und /**sys** haben keinen Lese-/Schreib-/Sperr-/Verknüpfungs-/Ausführungszugriff
* **Mounten** ist **nicht erlaubt**
* **Ptrace** kann nur auf einen Prozess ausgeführt werden, der durch dasselbe Apparmor-Profil eingeschränkt ist

Sobald Sie einen Docker-Container ausführen, sollten Sie die folgende Ausgabe sehen:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Beachten Sie, dass **AppArmor standardmäßig sogar die Berechtigungen für Fähigkeiten blockiert**, die dem Container gewährt werden. Zum Beispiel kann es **die Berechtigung zum Schreiben in /proc blockieren, selbst wenn die SYS\_ADMIN-Fähigkeit gewährt wurde**, da das Docker-AppArmor-Profil standardmäßig diesen Zugriff verweigert:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Sie müssen **AppArmor deaktivieren**, um seine Beschränkungen zu umgehen:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Beachten Sie, dass standardmäßig **AppArmor** auch das **Mounten von Ordnern** von innen im Container verbietet, selbst mit der SYS\_ADMIN-Fähigkeit.

Beachten Sie, dass Sie **Fähigkeiten** zum Docker-Container **hinzufügen/entfernen** können (dies wird immer noch durch Schutzmethoden wie **AppArmor** und **Seccomp** eingeschränkt):

* `--cap-add=SYS_ADMIN` gibt die Fähigkeit `SYS_ADMIN`
* `--cap-add=ALL` gibt alle Fähigkeiten
* `--cap-drop=ALL --cap-add=SYS_PTRACE` entfernt alle Fähigkeiten und gibt nur `SYS_PTRACE`

{% hint style="info" %}
Normalerweise, wenn Sie feststellen, dass Sie eine **privilegierte Fähigkeit** innerhalb eines **Docker-Containers haben**, aber ein Teil des **Exploits nicht funktioniert**, liegt dies daran, dass Docker **AppArmor dies verhindert**.
{% endhint %}

### Beispiel

(Beispiel von [**hier**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Um die Funktionalität von AppArmor zu veranschaulichen, habe ich ein neues Docker-Profil "mydocker" erstellt und die folgende Zeile hinzugefügt:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Um das Profil zu aktivieren, müssen wir Folgendes tun:
```
sudo apparmor_parser -r -W mydocker
```
Um die Profile aufzulisten, können wir den folgenden Befehl verwenden. Der unten stehende Befehl listet mein neues AppArmor-Profil auf.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Wie unten gezeigt, erhalten wir einen Fehler, wenn wir versuchen, "/etc/" zu ändern, da das AppArmor-Profil den Schreibzugriff auf "/etc" verhindert.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Sie können herausfinden, welches **AppArmor-Profil einen Container ausführt**, indem Sie Folgendes verwenden:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Dann können Sie die folgende Zeile ausführen, um das genaue Profil zu finden, das verwendet wird:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Im seltsamen Fall können Sie das AppArmor-Docker-Profil **ändern und neu laden**. Sie könnten die Beschränkungen entfernen und sie "umgehen".

### AppArmor Docker Umgehung2

**AppArmor basiert auf Pfaden**, das bedeutet, dass selbst wenn es Dateien innerhalb eines Verzeichnisses wie **`/proc`** schützt, wenn Sie **konfigurieren können, wie der Container ausgeführt wird**, könnten Sie das proc-Verzeichnis des Hosts in **`/host/proc`** einbinden und es **wird nicht mehr von AppArmor geschützt**.

### AppArmor Shebang Umgehung

In [**diesem Fehler**](https://bugs.launchpad.net/apparmor/+bug/1911431) können Sie ein Beispiel dafür sehen, wie **selbst wenn Sie verhindern, dass Perl mit bestimmten Ressourcen ausgeführt wird**, wenn Sie einfach ein Shell-Skript erstellen und in der ersten Zeile **`#!/usr/bin/perl`** angeben und die Datei direkt ausführen, können Sie alles ausführen, was Sie wollen. Zum Beispiel:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
