# AppArmor

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Grundinformationen

AppArmor ist eine **Kernel-Erweiterung, die entwickelt wurde, um die Ressourcen, die Programmen zur Verfügung stehen, durch programmspezifische Profile einzuschränken**, und implementiert effektiv Mandatory Access Control (MAC), indem Zugriffssteuerungsattribute direkt an Programme anstelle von Benutzern gebunden werden. Dieses System funktioniert, indem es **Profile in den Kernel lädt**, normalerweise beim Booten, und diese Profile bestimmen, auf welche Ressourcen ein Programm zugreifen kann, wie z.B. Netzwerkverbindungen, Rohsocket-Zugriff und Dateiberechtigungen.

Es gibt zwei Betriebsmodi für AppArmor-Profile:

* **Durchsetzungsmodus**: Dieser Modus setzt aktiv die im Profil definierten Richtlinien durch, blockiert Aktionen, die gegen diese Richtlinien verstoßen, und protokolliert alle Versuche, diese zu verletzen, über Systeme wie syslog oder auditd.
* **Beschwerdemodus**: Im Gegensatz zum Durchsetzungsmodus blockiert der Beschwerdemodus keine Aktionen, die gegen die Richtlinien des Profils verstoßen. Stattdessen protokolliert er diese Versuche als Richtlinienverletzungen, ohne Einschränkungen durchzusetzen.

### Komponenten von AppArmor

* **Kernelmodul**: Verantwortlich für die Durchsetzung der Richtlinien.
* **Richtlinien**: Legen die Regeln und Einschränkungen für das Verhalten von Programmen und den Zugriff auf Ressourcen fest.
* **Parser**: Lädt Richtlinien in den Kernel zur Durchsetzung oder Berichterstattung.
* **Hilfsprogramme**: Dies sind Programme im Benutzermodus, die eine Schnittstelle zur Interaktion mit und Verwaltung von AppArmor bereitstellen.

### Profile-Pfad

AppArmor-Profile werden normalerweise in _**/etc/apparmor.d/**_ gespeichert.\
Mit `sudo aa-status` können Sie die Binärdateien auflisten, die durch ein bestimmtes Profil eingeschränkt sind. Wenn Sie das Zeichen "/" im Pfad jeder aufgelisteten Binärdatei durch einen Punkt ersetzen, erhalten Sie den Namen des AppArmor-Profils im genannten Ordner.

Zum Beispiel wird ein **AppArmor**-Profil für _/usr/bin/man_ in _/etc/apparmor.d/usr.bin.man_ gespeichert.

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

* Um die betroffene ausführbare Datei anzugeben, sind **absolute Pfade und Platzhalter** (für die Dateiglobierung) zur Angabe von Dateien erlaubt.
* Um den Zugriff anzugeben, den die Binärdatei über **Dateien** haben wird, können die folgenden **Zugriffssteuerungen** verwendet werden:
* **r** (lesen)
* **w** (schreiben)
* **m** (Speicherkarten als ausführbar)
* **k** (Dateisperrung)
* **l** (Erstellung harter Links)
* **ix** (um ein anderes Programm auszuführen, wobei das neue Programm die Richtlinie erbt)
* **Px** (unter einem anderen Profil ausführen, nach Bereinigung der Umgebung)
* **Cx** (unter einem Kindprofil ausführen, nach Bereinigung der Umgebung)
* **Ux** (unbeschränkt ausführen, nach Bereinigung der Umgebung)
* **Variablen** können in den Profilen definiert und von außerhalb des Profils manipuliert werden. Zum Beispiel: @{PROC} und @{HOME} (füge #include \<tunables/global> zur Profildatei hinzu)
* **Ablehnungsregeln werden unterstützt, um Erlaubensregeln zu überschreiben**.

### aa-genprof

Um das Erstellen eines Profils zu erleichtern, kann apparmor Ihnen helfen. Es ist möglich, **apparmor die von einer Binärdatei durchgeführten Aktionen zu inspizieren und Ihnen dann zu ermöglichen, zu entscheiden, welche Aktionen Sie erlauben oder ablehnen möchten**.\
Sie müssen nur Folgendes ausführen:
```bash
sudo aa-genprof /path/to/binary
```
Dann führen Sie in einer anderen Konsole alle Aktionen aus, die die Binärdatei normalerweise ausführen wird:
```bash
/path/to/binary -a dosomething
```
Dann drücken Sie in der ersten Konsole "**s**" und geben Sie dann in den aufgezeichneten Aktionen an, ob Sie ignorieren, erlauben oder etwas anderes möchten. Wenn Sie fertig sind, drücken Sie "**f**" und das neue Profil wird in _/etc/apparmor.d/path.to.binary_ erstellt.

{% hint style="info" %}
Mit den Pfeiltasten können Sie auswählen, was Sie erlauben/ablehnen/whatever möchten.
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
Beachten Sie, dass standardmäßig in einem erstellten Profil nichts erlaubt ist, sodass alles verweigert wird. Sie müssen Zeilen wie `/etc/passwd r,` hinzufügen, um beispielsweise das Lesen der Binärdatei `/etc/passwd` zu erlauben.
{% endhint %}

Sie können dann das neue Profil **durchsetzen** mit
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modifizieren eines Profils aus Protokollen

Das folgende Tool liest die Protokolle und fragt den Benutzer, ob er einige der erkannten verbotenen Aktionen erlauben möchte:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Mit den Pfeiltasten können Sie auswählen, was Sie erlauben/ablehnen/was auch immer möchten
{% endhint %}

### Verwaltung eines Profils
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Beispiel für **AUDIT**- und **DENIED**-Protokolle aus _/var/log/audit/audit.log_ der ausführbaren **`service_bin`**:
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
By default **Apparmor docker-default profile** wird generiert von [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profile Zusammenfassung**:

* **Zugriff** auf alle **Netzwerke**
* **Keine Fähigkeit** ist definiert (Allerdings werden einige Fähigkeiten durch das Einfügen grundlegender Basisregeln kommen, d.h. #include \<abstractions/base>)
* **Schreiben** in eine **/proc**-Datei ist **nicht erlaubt**
* Andere **Unterverzeichnisse**/**Dateien** von /**proc** und /**sys** haben **verweigerten** Lese-/Schreib-/Sperr-/Link-/Ausführungszugriff
* **Mount** ist **nicht erlaubt**
* **Ptrace** kann nur auf einem Prozess ausgeführt werden, der durch **das gleiche apparmor-Profil** eingeschränkt ist

Sobald Sie **einen Docker-Container ausführen**, sollten Sie die folgende Ausgabe sehen:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Beachten Sie, dass **apparmor sogar die Berechtigungen für Fähigkeiten** blockiert, die standardmäßig dem Container gewährt werden. Zum Beispiel wird es in der Lage sein, **die Berechtigung zum Schreiben in /proc zu blockieren, selbst wenn die SYS\_ADMIN-Fähigkeit gewährt wird**, da das standardmäßige docker apparmor-Profil diesen Zugriff verweigert:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Sie müssen **apparmor deaktivieren**, um seine Einschränkungen zu umgehen:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Beachten Sie, dass **AppArmor** standardmäßig auch **verhindert, dass der Container** Ordner von innen mountet, selbst mit der SYS\_ADMIN-Fähigkeit.

Beachten Sie, dass Sie **Fähigkeiten** zum Docker-Container **hinzufügen/entfernen** können (dies wird weiterhin durch Schutzmethoden wie **AppArmor** und **Seccomp** eingeschränkt):

* `--cap-add=SYS_ADMIN` gibt die `SYS_ADMIN`-Fähigkeit
* `--cap-add=ALL` gibt alle Fähigkeiten
* `--cap-drop=ALL --cap-add=SYS_PTRACE` entfernt alle Fähigkeiten und gibt nur `SYS_PTRACE`

{% hint style="info" %}
In der Regel, wenn Sie **feststellen**, dass Sie eine **privilegierte Fähigkeit** **innerhalb** eines **Docker**-Containers zur Verfügung haben, **aber** ein Teil des **Exploits nicht funktioniert**, liegt das daran, dass Docker **AppArmor es verhindern wird**.
{% endhint %}

### Beispiel

(Beispiel von [**hier**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Um die Funktionalität von AppArmor zu veranschaulichen, habe ich ein neues Docker-Profil „mydocker“ mit der folgenden Zeile hinzugefügt:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Um das Profil zu aktivieren, müssen wir Folgendes tun:
```
sudo apparmor_parser -r -W mydocker
```
Um die Profile aufzulisten, können wir den folgenden Befehl ausführen. Der untenstehende Befehl listet mein neues AppArmor-Profil auf.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Wie unten gezeigt, erhalten wir einen Fehler, wenn wir versuchen, “/etc/” zu ändern, da das AppArmor-Profil den Schreibzugriff auf “/etc” verhindert.
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
Dann können Sie die folgende Zeile ausführen, um **das genaue Profil zu finden, das verwendet wird**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In dem seltsamen Fall, dass Sie **das AppArmor-Docker-Profil ändern und neu laden können.** Könnten Sie die Einschränkungen entfernen und sie "umgehen".

### AppArmor Docker Bypass2

**AppArmor ist pfadbasiert**, das bedeutet, dass selbst wenn es möglicherweise **Dateien** in einem Verzeichnis wie **`/proc`** **schützt**, wenn Sie **konfigurieren können, wie der Container ausgeführt wird**, könnten Sie das proc-Verzeichnis des Hosts innerhalb von **`/host/proc`** **einbinden** und es **wird nicht mehr von AppArmor geschützt**.

### AppArmor Shebang Bypass

In [**diesem Bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) sehen Sie ein Beispiel dafür, wie **selbst wenn Sie verhindern, dass Perl mit bestimmten Ressourcen ausgeführt wird**, wenn Sie einfach ein Shell-Skript **erstellen**, das in der ersten Zeile **`#!/usr/bin/perl`** **spezifiziert** und Sie **die Datei direkt ausführen**, werden Sie in der Lage sein, alles auszuführen, was Sie wollen. Z.B.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
