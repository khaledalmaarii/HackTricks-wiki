# User Namespace

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlegende Informationen

Ein Benutzernamensraum ist eine Funktion des Linux-Kernels, die **eine Isolierung von Benutzer- und Gruppen-ID-Zuordnungen** ermöglicht und es jedem Benutzernamensraum ermöglicht, seinen **eigenen Satz von Benutzer- und Gruppen-IDs** zu haben. Diese Isolierung ermöglicht es Prozessen, die in verschiedenen Benutzernamensräumen ausgeführt werden, **unterschiedliche Berechtigungen und Besitzverhältnisse** zu haben, auch wenn sie numerisch dieselben Benutzer- und Gruppen-IDs teilen.

Benutzernamensräume sind besonders nützlich bei der Containerisierung, bei der jeder Container seinen eigenen unabhängigen Satz von Benutzer- und Gruppen-IDs haben sollte, um eine bessere Sicherheit und Isolierung zwischen Containern und dem Host-System zu ermöglichen.

### Wie es funktioniert:

1. Wenn ein neuer Benutzernamensraum erstellt wird, **beginnt er mit einem leeren Satz von Benutzer- und Gruppen-ID-Zuordnungen**. Das bedeutet, dass jeder Prozess, der im neuen Benutzernamensraum ausgeführt wird, **anfangs keine Berechtigungen außerhalb des Namensraums hat**.
2. ID-Zuordnungen können zwischen den Benutzer- und Gruppen-IDs im neuen Namensraum und denen im übergeordneten (oder Host-) Namensraum hergestellt werden. Dadurch können Prozesse im neuen Namensraum Berechtigungen und Besitzverhältnisse entsprechend den Benutzer- und Gruppen-IDs im übergeordneten Namensraum haben. Die ID-Zuordnungen können jedoch auf bestimmte Bereiche und Teilgruppen von IDs beschränkt werden, um eine feinere Kontrolle über die den Prozessen im neuen Namensraum gewährten Berechtigungen zu ermöglichen.
3. Innerhalb eines Benutzernamensraums können **Prozesse volle Root-Berechtigungen (UID 0) für Operationen innerhalb des Namensraums** haben, während sie außerhalb des Namensraums nur begrenzte Berechtigungen haben. Dies ermöglicht es **Containern, mit root-ähnlichen Fähigkeiten in ihrem eigenen Namensraum zu laufen, ohne volle Root-Berechtigungen auf dem Host-System zu haben**.
4. Prozesse können zwischen Namensräumen wechseln, indem sie den Systemaufruf `setns()` verwenden oder neue Namensräume erstellen, indem sie die Systemaufrufe `unshare()` oder `clone()` mit dem Flag `CLONE_NEWUSER` verwenden. Wenn ein Prozess zu einem neuen Namensraum wechselt oder einen neuen erstellt, beginnt er die Benutzer- und Gruppen-ID-Zuordnungen zu verwenden, die mit diesem Namensraum verbunden sind.

## Labor:

### Verschiedene Namensräume erstellen

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Durch das Einbinden einer neuen Instanz des `/proc`-Dateisystems mit dem Parameter `--mount-proc` stellen Sie sicher, dass der neue Mount-Namespace eine genaue und isolierte Ansicht der prozessspezifischen Informationen für diesen Namespace hat.

<details>

<summary>Fehler: bash: fork: Kann keinen Speicher zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler aufgrund der Art und Weise auf, wie Linux neue PID (Process ID)-Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problem Erklärung**:
- Der Linux-Kernel ermöglicht es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespaces initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Die Ausführung von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, löst er die Bereinigung des Namespaces aus, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Konsequenz**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` beim Erstellen eines neuen Prozesses keinen neuen PID zuweisen kann und den Fehler "Kann keinen Speicher zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann behoben werden, indem die Option `-f` zusammen mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` nach der Erstellung des neuen PID-Namespaces einen neuen Prozess forkt.
- Die Ausführung von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, was das vorzeitige Beenden von PID 1 verhindert und eine normale PID-Zuweisung ermöglicht.

Durch die Gewährleistung, dass `unshare` mit der `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt beibehalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler ausgeführt werden können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Um den Benutzernamensraum zu verwenden, muss der Docker-Daemon mit **`--userns-remap=default`** gestartet werden (In Ubuntu 14.04 kann dies durch Ändern von `/etc/default/docker` und anschließendes Ausführen von `sudo service docker restart` erfolgen).

### Überprüfen Sie, in welchem Namensraum sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es ist möglich, die Benutzerzuordnung des Docker-Containers mit folgendem Befehl zu überprüfen:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Oder vom Host aus mit:
```bash
cat /proc/<pid>/uid_map
```
### Alle Benutzernamenräume finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betreten Sie einen Benutzernamensraum

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Außerdem können Sie nur in einen anderen Prozess-Namespace wechseln, wenn Sie root sind. Und Sie können nicht in einen anderen Namespace wechseln, ohne einen Descriptor darauf zu verweisen (wie z.B. `/proc/self/ns/user`).

### Neuen Benutzer-Namespace erstellen (mit Zuordnungen)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Wiederherstellung von Berechtigungen

Im Fall von Benutzernamensräumen wird **einem Prozess, der in den Namensraum eintritt, ein vollständiger Satz von Berechtigungen innerhalb dieses Namensraums gewährt**. Diese Berechtigungen ermöglichen es dem Prozess, privilegierte Operationen wie das **Mounten von Dateisystemen**, das Erstellen von Geräten oder das Ändern des Dateibesitzes durchzuführen, jedoch **nur im Kontext seines Benutzernamensraums**.

Wenn Sie beispielsweise die `CAP_SYS_ADMIN`-Berechtigung innerhalb eines Benutzernamensraums haben, können Sie Operationen durchführen, die normalerweise diese Berechtigung erfordern, wie das Mounten von Dateisystemen, jedoch nur im Kontext Ihres Benutzernamensraums. Alle Operationen, die Sie mit dieser Berechtigung durchführen, wirken sich nicht auf das Host-System oder andere Namensräume aus.

{% hint style="warning" %}
Daher erhalten Sie durch das Erstellen eines neuen Prozesses in einem neuen Benutzernamensraum **alle Berechtigungen zurück** (CapEff: 000001ffffffffff), Sie können jedoch tatsächlich **nur diejenigen verwenden, die mit dem Namensraum zusammenhängen** (z. B. Mounten), aber nicht alle. Daher reicht dies allein nicht aus, um aus einem Docker-Container auszubrechen.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
## Referenzen
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
