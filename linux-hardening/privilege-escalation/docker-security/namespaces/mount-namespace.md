# Mount Namespace

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Grundinformationen

Ein Mount-Namespace ist eine Funktion des Linux-Kernels, die die Isolation der Dateisystem-Mountpunkte bietet, die von einer Gruppe von Prozessen gesehen werden. Jeder Mount-Namespace hat sein eigenes Set von Dateisystem-Mountpunkten, und **Änderungen an den Mountpunkten in einem Namespace wirken sich nicht auf andere Namespaces aus**. Das bedeutet, dass Prozesse, die in verschiedenen Mount-Namespaces laufen, unterschiedliche Ansichten der Dateisystemhierarchie haben können.

Mount-Namespaces sind besonders nützlich in der Containerisierung, wo jeder Container sein eigenes Dateisystem und seine eigene Konfiguration haben sollte, isoliert von anderen Containern und dem Host-System.

### So funktioniert es:

1. Wenn ein neuer Mount-Namespace erstellt wird, wird er mit einer **Kopie der Mountpunkte aus seinem übergeordneten Namespace** initialisiert. Das bedeutet, dass der neue Namespace bei der Erstellung die gleiche Sicht auf das Dateisystem hat wie sein übergeordneter Namespace. Änderungen an den Mountpunkten innerhalb des Namespaces wirken sich jedoch nicht auf den übergeordneten oder andere Namespaces aus.
2. Wenn ein Prozess einen Mountpunkt innerhalb seines Namespaces ändert, z. B. ein Dateisystem mountet oder unmountet, ist die **Änderung lokal für diesen Namespace** und wirkt sich nicht auf andere Namespaces aus. Dies ermöglicht es jedem Namespace, seine eigene unabhängige Dateisystemhierarchie zu haben.
3. Prozesse können zwischen Namespaces mit dem `setns()` Systemaufruf wechseln oder neue Namespaces mit den Systemaufrufen `unshare()` oder `clone()` mit dem `CLONE_NEWNS`-Flag erstellen. Wenn ein Prozess zu einem neuen Namespace wechselt oder einen erstellt, beginnt er, die mit diesem Namespace verbundenen Mountpunkte zu verwenden.
4. **Dateideskriptoren und Inodes werden über Namespaces hinweg geteilt**, was bedeutet, dass, wenn ein Prozess in einem Namespace einen offenen Dateideskriptor hat, der auf eine Datei zeigt, er **diesen Dateideskriptor** an einen Prozess in einem anderen Namespace weitergeben kann, und **beide Prozesse auf dieselbe Datei zugreifen**. Der Pfad der Datei kann jedoch in beiden Namespaces unterschiedlich sein, aufgrund von Unterschieden in den Mountpunkten.

## Labor:

### Erstelle verschiedene Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die prozessspezifischen Informationen hat, die für diesen Namespace spezifisch sind**.

<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Prozess-ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:
- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird zu PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:
- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, wenn versucht wird, eine neue PID zuzuweisen, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch das vorzeitige Beenden von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Alle Mount-Namensräume finden

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

{% code overflow="wrap" %}
```bash
findmnt
```
{% endcode %}

### Betreten Sie einen Mount-Namespace
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Auch können Sie **nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind**. Und Sie **können** **nicht** **in** einen anderen Namespace **eintreten**, **ohne einen Deskriptor**, der darauf verweist (wie `/proc/self/ns/mnt`).

Da neue Mounts nur innerhalb des Namespace zugänglich sind, ist es möglich, dass ein Namespace sensible Informationen enthält, die nur von ihm aus zugänglich sind.

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

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Referenzen
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
* [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)


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
