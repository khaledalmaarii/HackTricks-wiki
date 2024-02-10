# Missbrauch des Docker-Sockets zur Privilege-Eskalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

Es gibt Situationen, in denen Sie nur **Zugriff auf den Docker-Socket** haben und diesen verwenden möchten, um **Privilegien zu eskalieren**. Einige Aktionen können sehr verdächtig sein und Sie möchten sie möglicherweise vermeiden. Hier finden Sie verschiedene Flags, die nützlich sein können, um Privilegien zu eskalieren:

### Über das Mounten

Sie können verschiedene Teile des **Dateisystems** in einem als Root ausgeführten Container **mounten** und darauf zugreifen.\
Sie können auch ein Mount missbrauchen, um Privilegien innerhalb des Containers zu eskalieren.

* **`-v /:/host`** -> Mounten Sie das Host-Dateisystem im Container, damit Sie auf das Host-Dateisystem **zugreifen können**.
* Wenn Sie sich **wie auf dem Host fühlen möchten**, sich aber im Container befinden, können Sie andere Verteidigungsmechanismen deaktivieren, indem Sie Flags wie verwenden:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Dies ist ähnlich wie die vorherige Methode, aber hier **mounten wir die Gerätefestplatte**. Führen Sie dann innerhalb des Containers `mount /dev/sda1 /mnt` aus und Sie können auf das **Host-Dateisystem** in `/mnt` zugreifen.
* Führen Sie `fdisk -l` auf dem Host aus, um das Gerät `</dev/sda1>` zu finden, das gemountet werden soll.
* **`-v /tmp:/host`** -> Wenn Sie aus irgendeinem Grund nur ein bestimmtes Verzeichnis vom Host mounten können und Zugriff auf das Verzeichnis im Host haben. Mounten Sie es und erstellen Sie ein **`/bin/bash`** mit **suid** im gemounteten Verzeichnis, damit Sie es vom Host ausführen und zu Root eskalieren können.

{% hint style="info" %}
Beachten Sie, dass Sie möglicherweise den Ordner `/tmp` nicht mounten können, aber Sie können einen **anderen beschreibbaren Ordner** mounten. Sie können beschreibbare Verzeichnisse mit dem Befehl `find / -writable -type d 2>/dev/null` finden.

**Beachten Sie, dass nicht alle Verzeichnisse in einer Linux-Maschine das suid-Bit unterstützen!** Um zu überprüfen, welche Verzeichnisse das suid-Bit unterstützen, führen Sie `mount | grep -v "nosuid"` aus. Zum Beispiel unterstützen normalerweise `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` und `/var/lib/lxcfs` das suid-Bit nicht.

Beachten Sie auch, dass Sie, wenn Sie `/etc` oder einen anderen Ordner **mit Konfigurationsdateien mounten können**, diese als Root aus dem Docker-Container heraus ändern können, um sie im Host zu **missbrauchen** und Privilegien zu eskalieren (z. B. Änderung von `/etc/shadow`).
{% endhint %}

### Ausbruch aus dem Container

* **`--privileged`** -> Mit diesem Flag [entfernen Sie alle Isolierung aus dem Container](docker-privileged.md#what-affects). Überprüfen Sie Techniken zum [Ausbruch aus privilegierten Containern als Root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Um [Berechtigungen zu eskalieren](../linux-capabilities.md), **gewähren Sie dem Container diese Berechtigung** und deaktivieren Sie andere Schutzmethoden, die das Ausnutzen verhindern könnten.

### Curl

Auf dieser Seite haben wir Möglichkeiten diskutiert, Privilegien mithilfe von Docker-Flags zu eskalieren. Sie können **Möglichkeiten, diese Methoden mit dem Curl-Befehl zu missbrauchen**, auf der Seite finden:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
