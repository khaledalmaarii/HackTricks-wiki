# UTS-Namespace

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>

## Grundlegende Informationen

Ein UTS (UNIX Time-Sharing System) Namespace ist eine Funktion des Linux-Kernels, die eine **Isolierung von zwei Systemidentifikatoren** ermöglicht: dem **Hostname** und dem **NIS** (Network Information Service) Domänennamen. Diese Isolierung ermöglicht es jedem UTS-Namespace, einen **eigenständigen Hostnamen und NIS-Domänennamen** zu haben, was besonders nützlich ist in Containerisierungsszenarien, in denen jeder Container als eigenständiges System mit eigenem Hostnamen erscheinen sollte.

### Wie es funktioniert:

1. Wenn ein neuer UTS-Namespace erstellt wird, startet er mit einer **Kopie des Hostnamens und des NIS-Domänennamens aus seinem übergeordneten Namespace**. Das bedeutet, dass der neue Namespace bei der Erstellung die gleichen Identifikatoren wie sein übergeordneter Namespace **teilt**. Jegliche nachfolgende Änderungen am Hostnamen oder NIS-Domänennamen innerhalb des Namespace haben jedoch keine Auswirkungen auf andere Namespaces.
2. Prozesse innerhalb eines UTS-Namespace **können den Hostnamen und den NIS-Domänennamen ändern**, indem sie die Systemaufrufe `sethostname()` und `setdomainname()` verwenden. Diese Änderungen gelten nur für den Namespace und haben keine Auswirkungen auf andere Namespaces oder das Hostsystem.
3. Prozesse können zwischen Namespaces wechseln, indem sie den Systemaufruf `setns()` verwenden oder neue Namespaces erstellen, indem sie die Systemaufrufe `unshare()` oder `clone()` mit dem Flag `CLONE_NEWUTS` verwenden. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, verwendet er den Hostnamen und den NIS-Domänennamen, die mit diesem Namespace verknüpft sind.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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
### Überprüfen Sie, in welchem Namespace sich Ihr Prozess befindet

Um festzustellen, in welchem Namespace sich Ihr Prozess befindet, können Sie den folgenden Befehl verwenden:

```bash
readlink /proc/$$/ns/uts
```

Dieser Befehl gibt den Pfad zum UTS-Namespace-Symbolischen Link zurück, der mit Ihrem Prozess verbunden ist.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Alle UTS-Namespaces finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betreten Sie einen UTS-Namespace

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
Auch hier können Sie nur in einen anderen Prozess-Namespace wechseln, wenn Sie root sind. Und Sie können nicht in einen anderen Namespace wechseln, ohne einen darauf verweisenden Deskriptor (wie `/proc/self/ns/uts`) zu haben.

### Hostnamen ändern
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
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
