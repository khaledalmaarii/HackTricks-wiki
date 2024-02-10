# IPC-Namespace

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

Ein IPC (Inter-Process Communication)-Namespace ist eine Funktion des Linux-Kernels, die eine **Isolierung** von System V IPC-Objekten wie Nachrichtenwarteschlangen, gemeinsam genutzten Speichersegmenten und Semaphoren ermöglicht. Diese Isolierung gewährleistet, dass Prozesse in **unterschiedlichen IPC-Namespaces nicht direkt auf die IPC-Objekte anderer Namespaces zugreifen oder diese ändern können**, und bietet somit eine zusätzliche Sicherheitsschicht und Privatsphäre zwischen Prozessgruppen.

### Funktionsweise:

1. Beim Erstellen eines neuen IPC-Namespaces wird ein **vollständig isolierter Satz von System V IPC-Objekten** erstellt. Das bedeutet, dass Prozesse, die in dem neuen IPC-Namespace ausgeführt werden, standardmäßig nicht auf die IPC-Objekte in anderen Namespaces oder auf das Host-System zugreifen oder diese beeinflussen können.
2. Innerhalb eines Namespaces erstellte IPC-Objekte sind nur für Prozesse innerhalb dieses Namespaces sichtbar und **zugänglich**. Jedes IPC-Objekt wird durch einen eindeutigen Schlüssel innerhalb seines Namespaces identifiziert. Obwohl der Schlüssel in verschiedenen Namespaces identisch sein kann, sind die Objekte selbst isoliert und können nicht zwischen Namespaces zugegriffen werden.
3. Prozesse können zwischen Namespaces wechseln, indem sie den Systemaufruf `setns()` verwenden oder neue Namespaces erstellen, indem sie die Systemaufrufe `unshare()` oder `clone()` mit dem Flag `CLONE_NEWIPC` verwenden. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, verwendet er die mit diesem Namespace verbundenen IPC-Objekte.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Durch das Einbinden einer neuen Instanz des `/proc`-Dateisystems mit dem Parameter `--mount-proc` stellen Sie sicher, dass der neue Mount-Namespace eine genaue und isolierte Ansicht der prozessspezifischen Informationen für diesen Namespace hat.

<details>

<summary>Fehler: bash: fork: Kann keinen Speicher zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler aufgrund der Art und Weise auf, wie Linux neue PID (Process ID)-Namespaces behandelt. Die wichtigsten Details und die Lösung sind wie folgt:

1. **Problem Erklärung**:
- Der Linux-Kernel ermöglicht es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespaces initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
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
### Überprüfen Sie, in welchem Namespace sich Ihr Prozess befindet

Um festzustellen, in welchem Namespace sich Ihr Prozess befindet, können Sie den folgenden Befehl verwenden:

```bash
ls -l /proc/$$/ns/ipc
```

Dieser Befehl gibt den Pfad zum IPC-Namespace des aktuellen Prozesses aus. Der Platzhalter "$$" wird automatisch durch die Prozess-ID (PID) des aktuellen Prozesses ersetzt.

Wenn der Befehl erfolgreich ist, erhalten Sie eine Ausgabe ähnlich der folgenden:

```
lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/1234/ns/ipc -> ipc:[4026531839]
```

Die Zahl am Ende des Ausgabeergebnisses ist die eindeutige Kennung des IPC-Namespaces, in dem sich Ihr Prozess befindet.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Alle IPC-Namespaces finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betreten Sie einen IPC-Namespace

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
### IPC-Objekt erstellen

Um ein IPC-Objekt zu erstellen, können Sie die folgenden Schritte ausführen:

1. Erstellen Sie eine IPC-Struktur, wie z.B. eine Semaphore, eine Shared Memory oder eine Message Queue.
2. Rufen Sie die entsprechende Systemaufrufsfunktion auf, um das IPC-Objekt zu erstellen.
3. Speichern Sie den Rückgabewert der Systemaufrufsfunktion, der den Deskriptor des erstellten IPC-Objekts enthält.

Beachten Sie, dass Sie nur in einen anderen Prozess-Namespace wechseln können, wenn Sie root sind. Sie können auch nicht in einen anderen Namespace wechseln, ohne einen Deskriptor zu haben, der darauf zeigt (wie z.B. `/proc/self/ns/net`).
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referenzen
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
