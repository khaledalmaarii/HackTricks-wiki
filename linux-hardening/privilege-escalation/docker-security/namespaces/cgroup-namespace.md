# CGroup Namespace

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Grundinformationen

Ein Cgroup-Namespace ist eine Funktion des Linux-Kernels, die **Isolation von Cgroup-Hierarchien für Prozesse, die innerhalb eines Namespaces ausgeführt werden**, bereitstellt. Cgroups, kurz für **Control Groups**, sind eine Kernel-Funktion, die es ermöglicht, Prozesse in hierarchischen Gruppen zu organisieren, um **Grenzen für Systemressourcen** wie CPU, Speicher und I/O zu verwalten und durchzusetzen.

Während Cgroup-Namensräume kein separater Namespace-Typ wie die anderen, die wir zuvor besprochen haben (PID, Mount, Netzwerk usw.), sind, stehen sie im Zusammenhang mit dem Konzept der Namespace-Isolation. **Cgroup-Namensräume virtualisieren die Sicht auf die Cgroup-Hierarchie**, sodass Prozesse, die innerhalb eines Cgroup-Namensraums ausgeführt werden, eine andere Sicht auf die Hierarchie haben als Prozesse, die im Host oder in anderen Namespaces ausgeführt werden.

### So funktioniert es:

1. Wenn ein neuer Cgroup-Namespace erstellt wird, **beginnt er mit einer Sicht auf die Cgroup-Hierarchie, die auf der Cgroup des erstellenden Prozesses basiert**. Das bedeutet, dass Prozesse, die im neuen Cgroup-Namespace ausgeführt werden, nur einen Teil der gesamten Cgroup-Hierarchie sehen, der auf dem Cgroup-Teilbaum basiert, der an der Cgroup des erstellenden Prozesses verwurzelt ist.
2. Prozesse innerhalb eines Cgroup-Namensraums werden **ihre eigene Cgroup als Wurzel der Hierarchie sehen**. Das bedeutet, dass aus der Perspektive der Prozesse innerhalb des Namespaces ihre eigene Cgroup als Wurzel erscheint und sie Cgroups außerhalb ihres eigenen Teilbaums nicht sehen oder darauf zugreifen können.
3. Cgroup-Namensräume bieten nicht direkt Isolation von Ressourcen; **sie bieten nur Isolation der Sicht auf die Cgroup-Hierarchie**. **Die Kontrolle und Isolation von Ressourcen werden weiterhin von den Cgroup-Subsystemen** (z. B. CPU, Speicher usw.) selbst durchgesetzt.

Für weitere Informationen über CGroups siehe:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Labor:

### Erstellen Sie verschiedene Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc` Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die prozessspezifischen Informationen hat, die für diesen Namespace spezifisch sind**.

<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Prozess-ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:
- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem `unshare` Systemaufruf zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare" Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING` Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, um eine neue PID zuzuweisen, wenn ein neuer Prozess erstellt wird, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare` Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch das vorzeitige Beenden von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f` Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Alle CGroup-Namensräume finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Betreten Sie einen CGroup-Namespace
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Auch können Sie **nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind**. Und Sie **können** **nicht** **in** einen anderen Namespace **eintreten**, **ohne** einen Deskriptor, der darauf verweist (wie `/proc/self/ns/cgroup`).

## Referenzen
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
