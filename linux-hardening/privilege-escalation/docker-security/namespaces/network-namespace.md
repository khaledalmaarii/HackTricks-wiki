# Netzwerk-Namespace

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

Ein Netzwerk-Namespace ist eine Funktion des Linux-Kernels, die eine Isolierung des Netzwerkstapels ermöglicht und es jedem Netzwerk-Namespace ermöglicht, seine eigene unabhängige Netzwerkkonfiguration, Schnittstellen, IP-Adressen, Routing-Tabellen und Firewall-Regeln zu haben. Diese Isolierung ist in verschiedenen Szenarien nützlich, wie z.B. bei der Containerisierung, bei der jeder Container seine eigene Netzwerkkonfiguration haben sollte, unabhängig von anderen Containern und dem Host-System.

### Wie es funktioniert:

1. Wenn ein neuer Netzwerk-Namespace erstellt wird, startet er mit einem **vollständig isolierten Netzwerkstapel**, ohne Netzwerkschnittstellen außer der Loopback-Schnittstelle (lo). Das bedeutet, dass Prozesse, die im neuen Netzwerk-Namespace ausgeführt werden, standardmäßig nicht mit Prozessen in anderen Namespaces oder dem Host-System kommunizieren können.
2. **Virtuelle Netzwerkschnittstellen**, wie z.B. veth-Paare, können erstellt und zwischen Netzwerk-Namespaces verschoben werden. Dadurch kann eine Netzwerkverbindung zwischen Namespaces oder zwischen einem Namespace und dem Host-System hergestellt werden. Zum Beispiel kann ein Ende eines veth-Paares im Netzwerk-Namespace eines Containers platziert werden und das andere Ende kann mit einer **Bridge** oder einer anderen Netzwerkschnittstelle im Host-Namespace verbunden werden, um dem Container Netzwerkverbindung bereitzustellen.
3. Netzwerkschnittstellen innerhalb eines Namespaces können ihre **eigenen IP-Adressen, Routing-Tabellen und Firewall-Regeln** haben, unabhängig von anderen Namespaces. Dadurch können Prozesse in verschiedenen Netzwerk-Namespaces unterschiedliche Netzwerkkonfigurationen haben und so arbeiten, als ob sie auf separaten vernetzten Systemen ausgeführt würden.
4. Prozesse können zwischen Namespaces wechseln, indem sie den Systemaufruf `setns()` verwenden oder neue Namespaces erstellen, indem sie die Systemaufrufe `unshare()` oder `clone()` mit dem Flag `CLONE_NEWNET` verwenden. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, beginnt er die Netzwerkkonfiguration und Schnittstellen zu verwenden, die mit diesem Namespace verbunden sind.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dadurch schlägt die Funktion `alloc_pid` beim Erstellen eines neuen Prozesses fehl, da kein neuer PID zugewiesen werden kann, was den Fehler "Kann keinen Speicher zuweisen" verursacht.

3. **Lösung**:
- Das Problem kann behoben werden, indem die Option `-f` zusammen mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` nach der Erstellung des neuen PID-Namespaces einen neuen Prozess forkt.
- Die Ausführung von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, was das vorzeitige Beenden von PID 1 verhindert und eine normale PID-Zuweisung ermöglicht.

Durch die Gewährleistung, dass `unshare` mit der `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt beibehalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler ausgeführt werden können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Überprüfen Sie, in welchem Namespace sich Ihr Prozess befindet

Um festzustellen, in welchem Namespace sich Ihr Prozess befindet, können Sie den folgenden Befehl verwenden:

```bash
ls -l /proc/$$/ns/net
```

Dieser Befehl gibt den Pfad zum Netzwerk-Namespace des aktuellen Prozesses zurück.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Alle Netzwerk-Namespaces finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betreten Sie eine Netzwerk-Namespace

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Außerdem können Sie nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind. Und Sie können nicht in einen anderen Namespace eintreten, ohne einen darauf verweisenden Deskriptor (wie z.B. `/proc/self/ns/net`) zu haben.

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
