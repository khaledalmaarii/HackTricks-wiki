# CGroup-Namespace

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

Ein CGroup-Namespace ist eine Funktion des Linux-Kernels, die **die Isolierung von CGroup-Hierarchien für Prozesse innerhalb eines Namespaces** ermöglicht. CGroups, kurz für **Control Groups**, sind eine Funktion des Kernels, die es ermöglicht, Prozesse in hierarchische Gruppen zu organisieren, um **Grenzen für Systemressourcen** wie CPU, Speicher und I/O zu verwalten und durchzusetzen.

Obwohl CGroup-Namespaces kein separater Namespacetyp wie die zuvor besprochenen (PID, Mount, Netzwerk usw.) sind, stehen sie im Zusammenhang mit dem Konzept der Namespacen-Isolierung. **CGroup-Namespaces virtualisieren die Ansicht der CGroup-Hierarchie**, sodass Prozesse, die in einem CGroup-Namespace ausgeführt werden, eine andere Ansicht der Hierarchie haben als Prozesse, die im Host oder in anderen Namespaces ausgeführt werden.

### Funktionsweise:

1. Wenn ein neuer CGroup-Namespace erstellt wird, **beginnt er mit einer Ansicht der CGroup-Hierarchie basierend auf der CGroup des erstellenden Prozesses**. Das bedeutet, dass Prozesse, die in dem neuen CGroup-Namespace ausgeführt werden, nur einen Teil der gesamten CGroup-Hierarchie sehen, der auf den CGroup-Unterbaum beschränkt ist, der bei der CGroup des erstellenden Prozesses beginnt.
2. Prozesse innerhalb eines CGroup-Namespace **sehen ihre eigene CGroup als Wurzel der Hierarchie**. Das bedeutet, dass aus der Perspektive von Prozessen innerhalb des Namespaces ihre eigene CGroup als Wurzel erscheint und sie CGroups außerhalb ihres eigenen Unterbaums nicht sehen oder darauf zugreifen können.
3. CGroup-Namespaces bieten keine direkte Isolierung von Ressourcen; **sie bieten nur eine Isolierung der Ansicht der CGroup-Hierarchie**. **Die Ressourcenkontrolle und -isolierung wird weiterhin von den CGroup-Subsystemen (z. B. CPU, Speicher usw.) selbst durchgesetzt**.

Weitere Informationen zu CGroups finden Sie unter:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Labor:

### Erstellen Sie verschiedene Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems mit dem Parameter `--mount-proc` stellen Sie sicher, dass der neue Mount-Namespace eine genaue und isolierte Ansicht der prozessspezifischen Informationen für diesen Namespace hat.

<details>

<summary>Fehler: bash: fork: Kann keinen Speicher zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler aufgrund der Art und Weise auf, wie Linux neue PID (Process ID)-Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problem Erklärung**:
- Der Linux-Kernel ermöglicht es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespaces initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Die Ausführung von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, löst er die Bereinigung des Namespaces aus, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Konsequenz**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dadurch schlägt die Funktion `alloc_pid` beim Erstellen eines neuen Prozesses fehl, da kein neuer PID zugewiesen werden kann, was den Fehler "Kann keinen Speicher zuweisen" verursacht.

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
cat /proc/$$/cgroup
```

Dieser Befehl gibt Informationen über die Control Group (cgroup) des aktuellen Prozesses aus. Die cgroup-Datei enthält den Pfad zum cgroup-Verzeichnis, das dem Prozess zugeordnet ist. Wenn der Prozess in einem bestimmten Namespace ausgeführt wird, wird der Namespace-Pfad in der cgroup-Datei angezeigt.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Alle CGroup-Namespaces finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betreten Sie einen CGroup-Namespace

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Außerdem können Sie nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind. Und Sie können nicht in einen anderen Namespace eintreten, ohne einen darauf verweisenden Deskriptor (wie z.B. `/proc/self/ns/cgroup`) zu haben.

## Referenzen
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [offizielle PEASS & HackTricks-Merchandise](https://peass.creator-spring.com)
* Entdecken Sie [The PEASS Family](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [NFTs](https://opensea.io/collection/the-peass-family)
* Treten Sie der 💬 [Discord-Gruppe](https://discord.gg/hRep4RUj7f) oder der [Telegram-Gruppe](https://t.me/peass) bei oder folgen Sie uns auf Twitter 🐦 [@carlospolopm](https://twitter.com/hacktricks_live).
* Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die [HackTricks](https://github.com/carlospolop/hacktricks) und [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
