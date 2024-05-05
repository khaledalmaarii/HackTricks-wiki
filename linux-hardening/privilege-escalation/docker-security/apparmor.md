# AppArmor

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

***

## Grundlegende Informationen

AppArmor ist eine **Kernel-Erweiterung, die darauf ausgelegt ist, die Ressourcen, die Programmen über programmbezogene Profile zur Verfügung stehen, einzuschränken**, und implementiert effektiv Mandatory Access Control (MAC), indem sie Zugriffssteuerungsattribute direkt an Programme anknüpft, anstatt an Benutzer. Dieses System funktioniert durch **Laden von Profilen in den Kernel**, normalerweise während des Bootvorgangs, und diese Profile geben an, auf welche Ressourcen ein Programm zugreifen kann, wie Netzwerkverbindungen, Raw-Socket-Zugriff und Dateiberechtigungen.

Es gibt zwei Betriebsmodi für AppArmor-Profile:

* **Durchsetzungsmodus**: Dieser Modus setzt die innerhalb des Profils definierten Richtlinien aktiv durch, blockiert Aktionen, die gegen diese Richtlinien verstoßen, und protokolliert jeden Versuch, sie durch Systeme wie syslog oder auditd zu verletzen.
* **Beschwerdemodus**: Im Gegensatz zum Durchsetzungsmodus blockiert der Beschwerdemodus keine Aktionen, die gegen die Richtlinien des Profils verstoßen. Stattdessen protokolliert er diese Versuche als Richtlinienverletzungen, ohne Einschränkungen durchzusetzen.

### Komponenten von AppArmor

* **Kernelmodul**: Verantwortlich für die Durchsetzung von Richtlinien.
* **Richtlinien**: Spezifizieren die Regeln und Einschränkungen für das Programmverhalten und den Ressourcenzugriff.
* **Parser**: Lädt Richtlinien in den Kernel für die Durchsetzung oder Berichterstattung.
* **Dienstprogramme**: Dies sind Benutzermodusprogramme, die eine Schnittstelle für die Interaktion mit und Verwaltung von AppArmor bereitstellen.

### Profile-Pfad

AppArmor-Profile werden normalerweise in _**/etc/apparmor.d/**_ gespeichert\
Mit `sudo aa-status` können Sie die Binärdateien auflisten, die durch ein Profil eingeschränkt sind. Wenn Sie den Schrägstrich "/" für einen Punkt des Pfads jeder aufgelisteten Binärdatei ändern, erhalten Sie den Namen des AppArmor-Profils im genannten Ordner.

Beispiel: Ein **AppArmor**-Profil für _/usr/bin/man_ befindet sich in _/etc/apparmor.d/usr.bin.man_

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

* Um das betroffene ausführbare Programm anzugeben, sind **absolute Pfade und Platzhalter** (für Datei-Globbing) zur Spezifizierung von Dateien erlaubt.
* Um den Zugriff anzugeben, den die Binärdatei über **Dateien** haben wird, können die folgenden **Zugriffskontrollen** verwendet werden:
* **r** (lesen)
* **w** (schreiben)
* **m** (als ausführbare Speicherabbildung)
* **k** (Dateisperre)
* **l** (Erstellen von harten Links)
* **ix** (um ein anderes Programm mit dem neuen Programm unter Vererbung der Richtlinie auszuführen)
* **Px** (unter einem anderen Profil ausführen, nach Bereinigung der Umgebung)
* **Cx** (unter einem untergeordneten Profil ausführen, nach Bereinigung der Umgebung)
* **Ux** (unbeschränkt ausführen, nach Bereinigung der Umgebung)
* **Variablen** können in den Profilen definiert und von außerhalb des Profils manipuliert werden. Zum Beispiel: @{PROC} und @{HOME} (fügen Sie #include \<tunables/global> zur Profildatei hinzu)
* **Deny-Regeln werden unterstützt, um Allow-Regeln außer Kraft zu setzen**.

### aa-genprof

Um das Erstellen eines Profils zu erleichtern, kann Ihnen AppArmor helfen. Es ist möglich, **AppArmor die Aktionen überwachen zu lassen, die von einer Binärdatei ausgeführt werden, und dann zu entscheiden, welche Aktionen Sie zulassen oder ablehnen möchten**.\
Sie müssen nur Folgendes ausführen:
```bash
sudo aa-genprof /path/to/binary
```
Dann führen Sie in einer anderen Konsole alle Aktionen aus, die das Binärprogramm normalerweise ausführen würde:
```bash
/path/to/binary -a dosomething
```
Dann drücken Sie in der ersten Konsole "**s**" und geben Sie dann in den aufgezeichneten Aktionen an, ob Sie ignorieren, erlauben oder was auch immer möchten. Wenn Sie fertig sind, drücken Sie "**f**" und das neue Profil wird in _/etc/apparmor.d/path.to.binary_ erstellt.

{% hint style="info" %}
Mit den Pfeiltasten können Sie auswählen, was Sie erlauben/ablehnen/möchten
{% endhint %}

### aa-easyprof

Sie können auch eine Vorlage eines AppArmor-Profils einer Binärdatei mit erstellen:
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
Beachten Sie, dass standardmäßig in einem erstellten Profil nichts erlaubt ist, daher ist alles verweigert. Sie müssen Zeilen wie `/etc/passwd r,` hinzufügen, um das Lesen der Binärdatei `/etc/passwd` zu erlauben, zum Beispiel.
{% endhint %}

Sie können dann das neue Profil **erzwingen** mit
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Bearbeiten eines Profils aus Logs

Das folgende Tool liest die Logs und fragt den Benutzer, ob er einige der erkannten verbotenen Aktionen erlauben möchte:
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

Beispiel für **AUDIT**- und **DENIED**-Protokolle aus _/var/log/audit/audit.log_ des ausführbaren Programms **`service_bin`**:
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
Standardmäßig wird das **Apparmor Docker-Standardprofil** von [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) generiert.

**Zusammenfassung des Docker-Standardprofils**:

- **Zugriff** auf alle **Netzwerke**
- Es sind **keine Fähigkeiten** definiert (Einige Fähigkeiten werden jedoch durch das Einbeziehen grundlegender Basissätze wie #include \<abstractions/base> bereitgestellt)
- **Schreiben** in jede **/proc**-Datei ist **nicht erlaubt**
- Andere **Unterverzeichnisse**/**Dateien** von /**proc** und /**sys** haben keinen Lese-/Schreib-/Sperr-/Verknüpfungs-/Ausführungszugriff
- **Mounten** ist **nicht erlaubt**
- **Ptrace** kann nur auf einen Prozess ausgeführt werden, der durch dasselbe **Apparmor-Profil** eingeschränkt ist

Nachdem Sie einen **Docker-Container gestartet** haben, sollten Sie die folgende Ausgabe sehen:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Beachten Sie, dass **AppArmor standardmäßig sogar die Berechtigungen für Fähigkeiten blockiert**, die dem Container gewährt wurden. Zum Beispiel wird es in der Lage sein, **die Erlaubnis zum Schreiben innerhalb von /proc zu blockieren, selbst wenn die SYS\_ADMIN-Fähigkeit gewährt wurde**, da das Docker-AppArmor-Profil standardmäßig diesen Zugriff verweigert:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Du musst **AppArmor deaktivieren**, um seine Beschränkungen zu umgehen:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Beachten Sie, dass standardmäßig **AppArmor** auch **das Mounten von Ordnern im Container verbietet**, selbst mit der SYS\_ADMIN-Fähigkeit.

Beachten Sie, dass Sie **Berechtigungen hinzufügen/entfernen** können, um dem Docker-Container **Berechtigungen** hinzuzufügen (dies wird immer noch durch Schutzmethoden wie **AppArmor** und **Seccomp** eingeschränkt):

* `--cap-add=SYS_ADMIN` gibt die `SYS_ADMIN`-Berechtigung
* `--cap-add=ALL` gibt alle Berechtigungen
* `--cap-drop=ALL --cap-add=SYS_PTRACE` verwirft alle Berechtigungen und gibt nur `SYS_PTRACE`

{% hint style="info" %}
Normalerweise, wenn Sie feststellen, dass Sie eine **privilegierte Berechtigung** im **Inneren** eines **Docker**-Containers haben, aber ein Teil des **Exploits nicht funktioniert**, liegt das daran, dass Docker **AppArmor es verhindert**.
{% endhint %}

### Beispiel

(Beispiel von [**hier**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Um die Funktionalität von AppArmor zu veranschaulichen, habe ich ein neues Docker-Profil "mydocker" erstellt, mit der folgenden hinzugefügten Zeile:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Um das Profil zu aktivieren, müssen wir Folgendes tun:
```
sudo apparmor_parser -r -W mydocker
```
Um die Profile aufzulisten, können wir den folgenden Befehl ausführen. Der unten stehende Befehl listet mein neues AppArmor-Profil auf.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Wie unten gezeigt, erhalten wir einen Fehler, wenn wir versuchen, "/etc/" zu ändern, da das AppArmor-Profil den Schreibzugriff auf "/etc" verhindert.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Umgehung1

Sie können herausfinden, welches **AppArmor-Profil einen Container ausführt**, indem Sie Folgendes verwenden:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Dann können Sie die folgende Zeile ausführen, um **das genaue verwendete Profil zu finden**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Umgehung2

**AppArmor basiert auf Pfaden**, das bedeutet, selbst wenn es Dateien innerhalb eines Verzeichnisses wie **`/proc`** schützt, könnten Sie, wenn Sie **konfigurieren können, wie der Container ausgeführt wird**, das proc-Verzeichnis des Hosts innerhalb von **`/host/proc`** einhängen und es **wird nicht mehr von AppArmor geschützt**.

### AppArmor Shebang Umgehung

In [**diesem Fehler**](https://bugs.launchpad.net/apparmor/+bug/1911431) können Sie ein Beispiel sehen, wie **selbst wenn Sie verhindern, dass Perl mit bestimmten Ressourcen ausgeführt wird**, wenn Sie einfach ein Shell-Skript erstellen, das in der ersten Zeile **`#!/usr/bin/perl`** angibt und die Datei **direkt ausführen**, können Sie alles ausführen, was Sie wollen. Z. B.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die kostenlose Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Suchmaschine kostenlos ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
