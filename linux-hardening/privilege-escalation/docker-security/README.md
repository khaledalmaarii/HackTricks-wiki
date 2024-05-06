# Docker-Sicherheit

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=docker-security), um mühelos Workflows zu erstellen und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-security" %}

## **Grundlegende Docker-Engine-Sicherheit**

Die **Docker-Engine** verwendet die **Namespaces** und **Cgroups** des Linux-Kernels, um Container zu isolieren und bietet eine grundlegende Sicherheitsebene. Zusätzlicher Schutz wird durch das **Verwerfen von Fähigkeiten**, **Seccomp** und **SELinux/AppArmor** geboten, um die Containerisolierung zu verbessern. Ein **Authentifizierungsplugin** kann Benutzeraktionen weiter einschränken.

![Docker-Sicherheit](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Sicheren Zugriff auf die Docker-Engine

Die Docker-Engine kann entweder lokal über einen Unix-Socket oder remote über HTTP zugegriffen werden. Für den Remotezugriff ist es wichtig, HTTPS und **TLS** zu verwenden, um Vertraulichkeit, Integrität und Authentifizierung sicherzustellen.

Die Docker-Engine hört standardmäßig auf den Unix-Socket unter `unix:///var/run/docker.sock`. Auf Ubuntu-Systemen sind die Startoptionen von Docker in `/etc/default/docker` definiert. Um den Remotezugriff auf die Docker-API und den Client zu ermöglichen, aktivieren Sie den Docker-Daemon über einen HTTP-Socket, indem Sie die folgenden Einstellungen hinzufügen:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Jedoch wird das Freigeben des Docker-Daemons über HTTP aufgrund von Sicherheitsbedenken nicht empfohlen. Es ist ratsam, Verbindungen mit HTTPS zu sichern. Es gibt zwei Hauptansätze zur Sicherung der Verbindung:

1. Der Client überprüft die Identität des Servers.
2. Sowohl der Client als auch der Server authentifizieren gegenseitig die Identität des anderen.

Zur Bestätigung der Identität eines Servers werden Zertifikate verwendet. Für detaillierte Beispiele beider Methoden siehe [**dieser Leitfaden**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sicherheit von Container-Images

Container-Images können in privaten oder öffentlichen Repositories gespeichert werden. Docker bietet mehrere Speicheroptionen für Container-Images:

* [**Docker Hub**](https://hub.docker.com): Ein öffentlicher Registrierungsdienst von Docker.
* [**Docker Registry**](https://github.com/docker/distribution): Ein Open-Source-Projekt, das es Benutzern ermöglicht, ihr eigenes Register zu hosten.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Das kommerzielle Registrierungsangebot von Docker mit rollenbasierter Benutzerauthentifizierung und Integration mit LDAP-Verzeichnisdiensten.

### Bildscannen

Container können **Sicherheitslücken** aufweisen, entweder aufgrund des Basisimages oder der auf dem Basisimage installierten Software. Docker arbeitet an einem Projekt namens **Nautilus**, das Sicherheitsscans von Containern durchführt und die Sicherheitslücken auflistet. Nautilus funktioniert, indem es jedes Container-Image-Layer mit dem Schwachstellen-Repository vergleicht, um Sicherheitslücken zu identifizieren.

Für weitere [**Informationen lesen Sie dies**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Der Befehl **`docker scan`** ermöglicht es Ihnen, vorhandene Docker-Images mithilfe des Bildnamens oder der ID zu scannen. Führen Sie beispielsweise den folgenden Befehl aus, um das Image hello-world zu scannen:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker-Image-Signierung

Die Docker-Image-Signierung gewährleistet die Sicherheit und Integrität von in Containern verwendeten Bildern. Hier ist eine zusammengefasste Erklärung:

- **Docker Content Trust** nutzt das Notary-Projekt, basierend auf dem The Update Framework (TUF), zur Verwaltung der Bildsignierung. Weitere Informationen finden Sie unter [Notary](https://github.com/docker/notary) und [TUF](https://theupdateframework.github.io).
- Um Docker Content Trust zu aktivieren, setzen Sie `export DOCKER_CONTENT_TRUST=1`. Diese Funktion ist in Docker Version 1.10 und später standardmäßig deaktiviert.
- Mit dieser Funktion können nur signierte Bilder heruntergeladen werden. Das Initiieren des ersten Bild-Push erfordert das Festlegen von Passphrasen für die Root- und Tagging-Schlüssel, wobei Docker auch Yubikey zur Verbesserung der Sicherheit unterstützt. Weitere Details finden Sie [hier](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Der Versuch, ein nicht signiertes Bild mit aktiviertem Content Trust herunterzuladen, führt zu einem Fehler "Keine Vertrauensdaten für latest".
- Für Bild-Pushes nach dem ersten fordert Docker die Passphrase des Repository-Schlüssels an, um das Bild zu signieren.

Um Ihre privaten Schlüssel zu sichern, verwenden Sie den Befehl:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Beim Wechseln von Docker-Hosts ist es notwendig, die Root- und Repository-Schlüssel zu verschieben, um den Betrieb aufrechtzuerhalten.

***

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=docker-security), um einfach Workflows zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-security" %}

## Sicherheitsfunktionen von Containern

<details>

<summary>Zusammenfassung der Sicherheitsfunktionen von Containern</summary>

**Hauptfunktionen zur Prozessisolierung**

In containerisierten Umgebungen ist die Isolierung von Projekten und deren Prozessen entscheidend für Sicherheit und Ressourcenmanagement. Hier ist eine vereinfachte Erklärung der wichtigsten Konzepte:

**Namespaces**

* **Zweck**: Sicherstellung der Isolierung von Ressourcen wie Prozessen, Netzwerken und Dateisystemen. Insbesondere in Docker halten Namespaces die Prozesse eines Containers getrennt vom Host und anderen Containern.
* **Verwendung von `unshare`**: Der Befehl `unshare` (oder das zugrunde liegende Systemaufruf) wird verwendet, um neue Namespaces zu erstellen und eine zusätzliche Isolationsebene bereitzustellen. Während Kubernetes dies grundsätzlich nicht blockiert, tut Docker dies.
* **Einschränkung**: Das Erstellen neuer Namespaces erlaubt es einem Prozess nicht, zu den Standard-Namespaces des Hosts zurückzukehren. Um auf die Host-Namespaces zuzugreifen, benötigt man in der Regel Zugriff auf das Verzeichnis `/proc` des Hosts und verwendet `nsenter` für den Zugriff.

**Control Groups (CGroups)**

* **Funktion**: Hauptsächlich zur Ressourcenzuweisung zwischen Prozessen verwendet.
* **Sicherheitsaspekt**: CGroups bieten an sich keine Isolationssicherheit, außer der Funktion `release_agent`, die bei falscher Konfiguration potenziell für unbefugten Zugriff ausgenutzt werden könnte.

**Capability Drop**

* **Bedeutung**: Es ist eine entscheidende Sicherheitsfunktion für die Prozessisolierung.
* **Funktionalität**: Es beschränkt die Aktionen, die ein Root-Prozess ausführen kann, indem bestimmte Fähigkeiten abgelegt werden. Selbst wenn ein Prozess mit Root-Rechten läuft, verhindert das Fehlen der erforderlichen Fähigkeiten die Ausführung privilegierter Aktionen, da die Systemaufrufe aufgrund unzureichender Berechtigungen fehlschlagen werden.

Dies sind die **verbleibenden Fähigkeiten**, nachdem der Prozess die anderen abgelegt hat:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Es ist standardmäßig in Docker aktiviert. Es hilft, die Syscalls, die der Prozess aufrufen kann, noch weiter zu **beschränken**.\
Das **Standard-Docker-Seccomp-Profil** kann unter [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) gefunden werden.

**AppArmor**

Docker hat eine Vorlage, die aktiviert werden kann: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Dies ermöglicht die Reduzierung von Fähigkeiten, Syscalls, Zugriff auf Dateien und Ordner...

</details>

### Namespaces

**Namespaces** sind ein Feature des Linux-Kernels, das **Kernelressourcen partitioniert**, sodass eine Gruppe von **Prozessen** einen Satz von **Ressourcen sieht**, während eine **andere** Gruppe von **Prozessen** einen **anderen** Satz von Ressourcen sieht. Das Feature funktioniert, indem für einen Satz von Ressourcen und Prozessen der gleiche Namespace vorhanden ist, aber diese Namespaces beziehen sich auf unterschiedliche Ressourcen. Ressourcen können in mehreren Bereichen existieren.

Docker verwendet die folgenden Linux-Kernel-Namespaces, um die Isolierung von Containern zu erreichen:

* pid-Namespace
* mount-Namespace
* Netzwerk-Namespace
* ipc-Namespace
* UTS-Namespace

Für **weitere Informationen zu den Namespaces** siehe die folgende Seite:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Das Linux-Kernel-Feature **cgroups** bietet die Möglichkeit, Ressourcen wie CPU, Speicher, IO, Netzwerkbandbreite unter einer Gruppe von Prozessen zu **beschränken**. Docker ermöglicht die Erstellung von Containern unter Verwendung des cgroup-Features, das eine Ressourcensteuerung für den spezifischen Container ermöglicht.\
Nachfolgend wird ein Container erstellt, bei dem der Benutzerspeicher auf 500m begrenzt ist, der Kernelspeicher auf 50m begrenzt ist, der CPU-Anteil auf 512, und das blkioweight auf 400 festgelegt ist. Der CPU-Anteil ist ein Verhältnis, das die CPU-Nutzung des Containers steuert. Er hat einen Standardwert von 1024 und einen Bereich zwischen 0 und 1024. Wenn drei Container den gleichen CPU-Anteil von 1024 haben, kann jeder Container bei CPU-Ressourcenkonflikten bis zu 33 % der CPU nutzen. blkio-weight ist ein Verhältnis, das die IO des Containers steuert. Er hat einen Standardwert von 500 und einen Bereich zwischen 10 und 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Um die cgroup eines Containers zu erhalten, können Sie Folgendes tun:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Für weitere Informationen siehe:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Berechtigungen

Berechtigungen ermöglichen eine genauere Kontrolle über die Berechtigungen, die dem Root-Benutzer erlaubt werden können. Docker verwendet das Linux-Kernel-Berechtigungsmerkmal, um die Operationen zu begrenzen, die innerhalb eines Containers durchgeführt werden können, unabhängig vom Typ des Benutzers.

Wenn ein Docker-Container ausgeführt wird, verwirft der Prozess sensible Berechtigungen, die der Prozess verwenden könnte, um aus der Isolation auszubrechen. Dies soll sicherstellen, dass der Prozess keine sensiblen Aktionen ausführen und ausbrechen kann:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

Dies ist eine Sicherheitsfunktion, die es Docker ermöglicht, die Systemaufrufe zu begrenzen, die innerhalb des Containers verwendet werden können:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

AppArmor ist eine Kernel-Erweiterung, um Container auf eine begrenzte Menge von Ressourcen mit pro-Programmprofilen zu beschränken:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

* **Beschriftungssystem**: SELinux weist jedem Prozess und jedem Dateisystemobjekt ein eindeutiges Label zu.
* **Richtliniendurchsetzung**: Es setzt Sicherheitsrichtlinien durch, die definieren, welche Aktionen ein Prozesslabel auf anderen Labels im System ausführen kann.
* **Container-Prozesslabels**: Wenn Container-Engines Containerprozesse initiieren, werden ihnen in der Regel eingeschränkte SELinux-Labels zugewiesen, üblicherweise `container_t`.
* **Dateibeschriftung innerhalb von Containern**: Dateien innerhalb des Containers sind normalerweise als `container_file_t` gekennzeichnet.
* **Richtlinienregeln**: Die SELinux-Richtlinie stellt hauptsächlich sicher, dass Prozesse mit dem Label `container_t` nur mit Dateien interagieren (lesen, schreiben, ausführen) können, die als `container_file_t` gekennzeichnet sind.

Dieser Mechanismus stellt sicher, dass selbst wenn ein Prozess innerhalb eines Containers kompromittiert ist, er nur mit Objekten interagieren kann, die über die entsprechenden Labels verfügen, was das potenzielle Schadensausmaß solcher Kompromittierungen erheblich einschränkt.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker spielt ein Autorisierungsplugin eine entscheidende Rolle für die Sicherheit, indem es entscheidet, ob Anfragen an den Docker-Daemon zugelassen oder blockiert werden sollen. Diese Entscheidung wird getroffen, indem zwei Schlüsselkontexte untersucht werden:

* **Authentifizierungskontext**: Dies umfasst umfassende Informationen über den Benutzer, wie z.B. wer sie sind und wie sie sich authentifiziert haben.
* **Befehlskontext**: Dies umfasst alle relevanten Daten, die mit der gestellten Anfrage zusammenhängen.

Diese Kontexte helfen sicherzustellen, dass nur legitime Anfragen von authentifizierten Benutzern verarbeitet werden, was die Sicherheit der Docker-Operationen erhöht.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS aus einem Container

Wenn die Ressourcen, die ein Container verwenden kann, nicht ordnungsgemäß begrenzt werden, könnte ein kompromittierter Container den Host, auf dem er läuft, DoS-angreifen.

* CPU-DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandbreiten-DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interessante Docker-Flags

### --privileged Flag

Auf der folgenden Seite können Sie lernen, **was das `--privileged`-Flag bedeutet**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Wenn Sie einen Container ausführen, in dem ein Angreifer Zugriff als Benutzer mit niedrigen Berechtigungen erhält. Wenn Sie eine **falsch konfigurierte SUID-Binärdatei** haben, kann der Angreifer diese missbrauchen und **Berechtigungen innerhalb** des Containers **eskaliert**, was es ihm ermöglichen könnte, daraus zu entkommen.

Das Ausführen des Containers mit der Option **`no-new-privileges`** aktiviert wird **diese Art von Berechtigungserweiterung verhindern**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Andere
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Für weitere **`--security-opt`**-Optionen siehe: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Weitere Sicherheitsüberlegungen

### Verwaltung von Geheimnissen: Best Practices

Es ist entscheidend, Geheimnisse nicht direkt in Docker-Images einzubetten oder Umgebungsvariablen zu verwenden, da diese Methoden Ihre sensiblen Informationen für jeden freigeben, der über Befehle wie `docker inspect` oder `exec` Zugriff auf den Container hat.

**Docker-Volumes** sind eine sicherere Alternative, die empfohlen wird, um auf sensible Informationen zuzugreifen. Sie können als temporäres Dateisystem im Speicher genutzt werden, um die Risiken im Zusammenhang mit `docker inspect` und Logging zu mindern. Allerdings können Root-Benutzer und solche mit `exec`-Zugriff auf den Container immer noch auf die Geheimnisse zugreifen.

**Docker-Secrets** bieten eine noch sicherere Methode zur Behandlung sensibler Informationen. Für Fälle, in denen während der Image-Build-Phase Geheimnisse erforderlich sind, bietet **BuildKit** eine effiziente Lösung mit Unterstützung für Buildzeit-Geheimnisse, die die Build-Geschwindigkeit verbessern und zusätzliche Funktionen bereitstellen.

Um BuildKit zu nutzen, kann es auf drei Arten aktiviert werden:

1. Über eine Umgebungsvariable: `export DOCKER_BUILDKIT=1`
2. Durch Voranstellen von Befehlen: `DOCKER_BUILDKIT=1 docker build .`
3. Durch die Aktivierung als Standard in der Docker-Konfiguration: `{ "features": { "buildkit": true } }`, gefolgt von einem Neustart von Docker.

BuildKit ermöglicht die Verwendung von Buildzeit-Geheimnissen mit der `--secret`-Option, um sicherzustellen, dass diese Geheimnisse nicht im Image-Build-Cache oder im endgültigen Image enthalten sind, unter Verwendung eines Befehls wie:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Für benötigte Geheimnisse in einem laufenden Container bieten **Docker Compose und Kubernetes** robuste Lösungen. Docker Compose verwendet einen `secrets`-Schlüssel in der Service-Definition zur Angabe von Geheimdateien, wie im folgenden Beispiel einer `docker-compose.yml` gezeigt:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Diese Konfiguration ermöglicht die Verwendung von Secrets beim Starten von Diensten mit Docker Compose.

In Kubernetes-Umgebungen werden Secrets nativ unterstützt und können mit Tools wie [Helm-Secrets](https://github.com/futuresimple/helm-secrets) weiter verwaltet werden. Die rollenbasierte Zugriffskontrolle (RBAC) von Kubernetes verbessert die Sicherheit des Secret-Managements, ähnlich wie bei Docker Enterprise.

### gVisor

**gVisor** ist ein Anwendungskernel, der in Go geschrieben ist und einen erheblichen Teil der Linux-Systemoberfläche implementiert. Es enthält einen [Open Container Initiative (OCI)](https://www.opencontainers.org)-Laufzeitnamens `runsc`, der eine **Isolierungsgrenze zwischen der Anwendung und dem Host-Kernel** bereitstellt. Die `runsc`-Laufzeit integriert sich mit Docker und Kubernetes und macht es einfach, Sandbox-Container auszuführen.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** ist eine Open-Source-Community, die daran arbeitet, eine sichere Container-Laufzeitumgebung mit leichten virtuellen Maschinen zu erstellen, die sich wie Container anfühlen und verhalten, aber eine **stärkere Workload-Isolierung unter Verwendung der Hardware-Virtualisierungstechnologie** als zweite Verteidigungsebene bieten.

{% embed url="https://katacontainers.io/" %}

### Zusammenfassungstipps

* **Verwenden Sie nicht das `--privileged`-Flag oder binden Sie einen** [**Docker-Socket innerhalb des Containers ein**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Der Docker-Socket ermöglicht das Starten von Containern, daher ist es ein einfacher Weg, die volle Kontrolle über den Host zu übernehmen, beispielsweise durch das Ausführen eines anderen Containers mit dem `--privileged`-Flag.
* Führen Sie **nicht als Root innerhalb des Containers aus. Verwenden Sie einen** [**anderen Benutzer**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **und** [**Benutzernamensräume**](https://docs.docker.com/engine/security/userns-remap/)**.** Der Root im Container ist derselbe wie auf dem Host, es sei denn, er wird mit Benutzernamensräumen neu zugeordnet. Er wird nur leicht durch hauptsächlich Linux-Namespaces, Fähigkeiten und cgroups eingeschränkt.
* [**Verwerfen Sie alle Fähigkeiten**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) und aktivieren Sie nur die erforderlichen** (`--cap-add=...`). Viele Workloads benötigen keine Fähigkeiten, und das Hinzufügen von ihnen erhöht den Umfang eines potenziellen Angriffs.
* Verwenden Sie die Sicherheitsoption **“no-new-privileges”**, um zu verhindern, dass Prozesse mehr Berechtigungen erlangen, beispielsweise durch suid-Binärdateien.
* **Begrenzen Sie die Ressourcen, die dem Container zur Verfügung stehen**. Ressourcenbeschränkungen können die Maschine vor Denial-of-Service-Angriffen schützen.
* **Passen Sie** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(oder SELinux)**-Profile an, um die Aktionen und Systemaufrufe, die für den Container verfügbar sind, auf das erforderliche Minimum zu beschränken.
* **Verwenden Sie** [**offizielle Docker-Images**](https://docs.docker.com/docker-hub/official\_images/) **und verlangen Sie Signaturen** oder erstellen Sie Ihre eigenen darauf basierend. Vererben oder verwenden Sie keine [mit Hintertüren versehenen](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) Images. Speichern Sie auch Root-Schlüssel, Passphrasen an einem sicheren Ort. Docker plant, Schlüssel mit UCP zu verwalten.
* **Erstellen Sie regelmäßig** Ihre Images neu, um **Sicherheitspatches auf dem Host und den Images anzuwenden**.
* Verwalten Sie Ihre **Secrets klug**, damit es für den Angreifer schwierig ist, darauf zuzugreifen.
* Wenn Sie den Docker-Daemon **freigeben, verwenden Sie HTTPS** mit Client- und Serverauthentifizierung.
* In Ihrem Dockerfile **bevorzugen Sie COPY anstelle von ADD**. ADD extrahiert automatisch komprimierte Dateien und kann Dateien von URLs kopieren. COPY verfügt nicht über diese Funktionen. Vermeiden Sie nach Möglichkeit die Verwendung von ADD, um nicht anfällig für Angriffe über Remote-URLs und Zip-Dateien zu sein.
* Verwenden Sie **getrennte Container für jeden Mikrodienst**.
* **Fügen Sie kein ssh** in den Container ein, "docker exec" kann verwendet werden, um eine SSH-Verbindung zum Container herzustellen.
* Verwenden Sie **kleinere** Container-Images.

## Docker Ausbruch / Privilege Escalation

Wenn Sie **innerhalb eines Docker-Containers** sind oder Zugriff auf einen Benutzer in der **Docker-Gruppe** haben, könnten Sie versuchen, **auszubrechen und Berechtigungen zu eskalieren**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker-Authentifizierungsplugin-Umgehung

Wenn Sie Zugriff auf den Docker-Socket haben oder Zugriff auf einen Benutzer in der **Docker-Gruppe haben, aber Ihre Aktionen durch ein Docker-Authentifizierungsplugin eingeschränkt sind**, überprüfen Sie, ob Sie es **umgehen können**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Absicherung von Docker

* Das Tool [**docker-bench-security**](https://github.com/docker/docker-bench-security) ist ein Skript, das Dutzende gängiger Best Practices für das Bereitstellen von Docker-Containern in der Produktion überprüft. Die Tests sind alle automatisiert und basieren auf dem [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Sie müssen das Tool vom Host ausführen, auf dem Docker ausgeführt wird, oder von einem Container mit ausreichenden Berechtigungen. Erfahren Sie, **wie Sie es in der README ausführen:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referenzen

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins\_authorization](https://docs.docker.com/engine/extend/plugins\_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=docker-security), um mühelos Workflows zu erstellen und zu **automatisieren**, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-security" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:
* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**Die PEASS-Familie**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
