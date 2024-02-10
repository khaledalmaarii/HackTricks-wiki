# PID-Namespace

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlegende Informationen

Der PID (Process IDentifier)-Namespace ist eine Funktion im Linux-Kernel, die Prozessisolierung ermöglicht, indem sie einer Gruppe von Prozessen eine eigene Reihe eindeutiger PIDs zuweist, die von den PIDs in anderen Namespaces getrennt sind. Dies ist besonders nützlich bei der Containerisierung, wo die Prozessisolierung für Sicherheit und Ressourcenmanagement unerlässlich ist.

Wenn ein neuer PID-Namespace erstellt wird, wird dem ersten Prozess in diesem Namespace die PID 1 zugewiesen. Dieser Prozess wird zum "init"-Prozess des neuen Namespaces und ist für die Verwaltung anderer Prozesse innerhalb des Namespaces verantwortlich. Jeder nachfolgende Prozess, der innerhalb des Namespaces erstellt wird, hat eine eindeutige PID innerhalb dieses Namespaces, und diese PIDs sind unabhängig von den PIDs in anderen Namespaces.

Aus der Sicht eines Prozesses innerhalb eines PID-Namespace kann er nur andere Prozesse im selben Namespace sehen. Er ist sich nicht bewusst von Prozessen in anderen Namespaces und kann nicht mit ihnen mithilfe herkömmlicher Prozessverwaltungstools (z. B. `kill`, `wait`, usw.) interagieren. Dies bietet eine Isolierungsebene, die verhindert, dass Prozesse sich gegenseitig beeinträchtigen.

### Wie es funktioniert:

1. Wenn ein neuer Prozess erstellt wird (z. B. durch Verwendung des `clone()`-Systemaufrufs), kann der Prozess einem neuen oder vorhandenen PID-Namespace zugewiesen werden. **Wenn ein neuer Namespace erstellt wird, wird der Prozess zum "init"-Prozess dieses Namespaces**.
2. Der **Kernel** pflegt eine **Zuordnung zwischen den PIDs im neuen Namespace und den entsprechenden PIDs** im Eltern-Namespace (d. h. dem Namespace, aus dem der neue Namespace erstellt wurde). Diese Zuordnung **ermöglicht es dem Kernel, PIDs bei Bedarf zu übersetzen**, z. B. beim Senden von Signalen zwischen Prozessen in verschiedenen Namespaces.
3. **Prozesse innerhalb eines PID-Namespace können nur andere Prozesse im selben Namespace sehen und mit ihnen interagieren**. Sie sind sich nicht bewusst von Prozessen in anderen Namespaces, und ihre PIDs sind innerhalb ihres Namespaces eindeutig.
4. Wenn ein **PID-Namespace zerstört wird** (z. B. wenn der "init"-Prozess des Namespaces beendet wird), werden **alle Prozesse innerhalb dieses Namespaces beendet**. Dadurch wird sichergestellt, dass alle mit dem Namespace verbundenen Ressourcen ordnungsgemäß bereinigt werden.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Fehler: bash: fork: Kann keinen Speicher zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler aufgrund der Art und Weise auf, wie Linux neue PID (Process ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind wie folgt:

1. **Problem Erklärung**:
- Der Linux-Kernel ermöglicht es einem Prozess, neue Namespaces mit dem `unshare`-Systemaufruf zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespaces initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Wenn `%unshare -p /bin/bash%` ausgeführt wird, wird `/bin/bash` im selben Prozess wie `unshare` gestartet. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, löst er die Bereinigung des Namespaces aus, wenn keine anderen Prozesse vorhanden sind, da PID 1 die spezielle Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Konsequenz**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` beim Erstellen eines neuen Prozesses keinen neuen PID zuweisen kann und den Fehler "Kann keinen Speicher zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann behoben werden, indem die Option `-f` zusammen mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` nach der Erstellung des neuen PID-Namespaces einen neuen Prozess forkt.
- Durch die Ausführung von `%unshare -fp /bin/bash%` wird sichergestellt, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, was das vorzeitige Beenden von PID 1 verhindert und eine normale PID-Zuweisung ermöglicht.

Durch die Gewährleistung, dass `unshare` mit der `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt verwaltet, sodass `/bin/bash` und seine Unterprozesse ohne den Fehler bei der Speicherzuweisung ausgeführt werden können.

</details>

Durch das Einbinden einer neuen Instanz des `/proc`-Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Ansicht der prozessspezifischen Informationen für diesen Namespace** hat.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Überprüfen Sie, in welchem Namespace sich Ihr Prozess befindet

Um festzustellen, in welchem Namespace sich Ihr Prozess befindet, können Sie den folgenden Befehl verwenden:

```bash
ls -l /proc/<PID>/ns
```

Ersetzen Sie `<PID>` durch die Prozess-ID, für die Sie den Namespace überprüfen möchten. Dieser Befehl listet die Symbolic Links zu den verschiedenen Namespaces auf, in denen der Prozess vorhanden ist.

Wenn Sie beispielsweise den PID 1234 überprüfen möchten, führen Sie den folgenden Befehl aus:

```bash
ls -l /proc/1234/ns
```

Die Ausgabe zeigt die verschiedenen Namespaces an, in denen der Prozess vorhanden ist.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Alle PID-Namespaces finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Beachten Sie, dass der Root-Benutzer aus dem ursprünglichen (Standard-) PID-Namespace alle Prozesse sehen kann, auch diejenigen in neuen PID-Namensräumen. Deshalb können wir alle PID-Namensräume sehen.

### Betreten Sie einen PID-Namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Wenn Sie sich innerhalb eines PID-Namespaces befinden, können Sie immer noch alle Prozesse sehen. Und der Prozess aus diesem PID-NS kann das neue Bash im PID-NS sehen.

Außerdem können Sie nur **in einen anderen Prozess-PID-Namespace eintreten, wenn Sie root sind**. Und Sie können **nicht** in einen anderen Namespace **eintreten**, ohne einen Zeiger darauf zu haben (wie z.B. `/proc/self/ns/pid`).

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
