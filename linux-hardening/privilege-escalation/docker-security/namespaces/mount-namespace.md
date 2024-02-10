# Mount-Namespace

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

Ein Mount-Namespace ist eine Funktion des Linux-Kernels, die eine Isolierung der Dateisystem-Mount-Punkte für eine Gruppe von Prozessen ermöglicht. Jeder Mount-Namespace hat seine eigenen Dateisystem-Mount-Punkte, und **Änderungen an den Mount-Punkten in einem Namespace wirken sich nicht auf andere Namespaces aus**. Das bedeutet, dass Prozesse, die in verschiedenen Mount-Namespaces ausgeführt werden, unterschiedliche Ansichten der Dateisystem-Hierarchie haben können.

Mount-Namespaces sind besonders nützlich bei der Containerisierung, bei der jeder Container sein eigenes Dateisystem und seine eigene Konfiguration haben sollte, isoliert von anderen Containern und dem Host-System.

### Funktionsweise:

1. Wenn ein neuer Mount-Namespace erstellt wird, wird er mit einer **Kopie der Mount-Punkte aus seinem übergeordneten Namespace initialisiert**. Das bedeutet, dass der neue Namespace bei der Erstellung die gleiche Ansicht des Dateisystems wie sein übergeordneter Namespace teilt. Jegliche nachfolgende Änderungen an den Mount-Punkten innerhalb des Namespace wirken sich jedoch nicht auf den übergeordneten Namespace oder andere Namespaces aus.
2. Wenn ein Prozess einen Mount-Punkt innerhalb seines Namespaces ändert, z.B. ein Dateisystem einbindet oder aushängt, ist die **Änderung lokal für diesen Namespace** und wirkt sich nicht auf andere Namespaces aus. Dadurch kann jeder Namespace seine eigene unabhängige Dateisystem-Hierarchie haben.
3. Prozesse können zwischen Namespaces wechseln, indem sie den Systemaufruf `setns()` verwenden oder neue Namespaces erstellen, indem sie die Systemaufrufe `unshare()` oder `clone()` mit dem Flag `CLONE_NEWNS` verwenden. Wenn ein Prozess zu einem neuen Namespace wechselt oder einen erstellt, verwendet er die mit diesem Namespace verbundenen Mount-Punkte.
4. **Dateideskriptoren und Inodes werden über Namespaces hinweg geteilt**, d.h. wenn ein Prozess in einem Namespace einen geöffneten Dateideskriptor hat, der auf eine Datei zeigt, kann er diesen Dateideskriptor an einen Prozess in einem anderen Namespace **weitergeben**, und **beide Prozesse greifen auf dieselbe Datei zu**. Die Pfadangabe der Datei kann jedoch in beiden Namespaces aufgrund von Unterschieden in den Mount-Punkten unterschiedlich sein.

## Labor:

### Erstellen Sie verschiedene Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems mit dem Parameter `--mount-proc` stellen Sie sicher, dass der neue Mount-Namespace eine genaue und isolierte Ansicht der prozessspezifischen Informationen für diesen Namespace hat.

<details>

<summary>Fehler: bash: fork: Kann keinen Speicher zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler aufgrund der Art und Weise auf, wie Linux neue PID (Process ID)-Namespaces behandelt. Die wichtigsten Details und die Lösung sind wie folgt:

1. **Problem Erklärung**:
- Der Linux-Kernel ermöglicht es einem Prozess, neue Namespaces mit dem `unshare`-Systemaufruf zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespaces initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Die Ausführung von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, löst er die Bereinigung des Namespaces aus, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Konsequenz**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` beim Erstellen eines neuen Prozesses keinen neuen PID zuweisen kann und den Fehler "Kann keinen Speicher zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann behoben werden, indem die Option `-f` zusammen mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` nach der Erstellung des neuen PID-Namespaces einen neuen Prozess forkt.
- Die Ausführung von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, was das vorzeitige Beenden von PID 1 verhindert und eine normale PID-Zuweisung ermöglicht.

Durch die Gewährleistung, dass `unshare` mit der `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt verwaltet, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler ausgeführt werden können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Überprüfen, in welchem Namespace sich Ihr Prozess befindet

Um festzustellen, in welchem Namespace sich Ihr Prozess befindet, können Sie den folgenden Befehl verwenden:

```bash
ls -l /proc/$$/ns
```

Dieser Befehl zeigt die Symbolic Links zu den verschiedenen Namespaces an, in denen Ihr Prozess läuft. Der `$$`-Teil des Befehls stellt die Prozess-ID (PID) Ihres aktuellen Prozesses dar.
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Alle Mount-Namespaces finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betreten Sie einen Mount-Namespace

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Auch können Sie nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind. Und Sie können nicht in einen anderen Namespace eintreten, ohne einen darauf verweisenden Deskriptor (wie `/proc/self/ns/mnt`).

Da neue Mounts nur innerhalb des Namespaces zugänglich sind, ist es möglich, dass ein Namespace sensible Informationen enthält, die nur von dort aus zugänglich sind.

### Etwas mounten
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
## Referenzen
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
