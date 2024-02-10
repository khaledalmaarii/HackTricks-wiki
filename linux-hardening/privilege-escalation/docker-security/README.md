# Docker-Sicherheit

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories senden.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Grundlegende Sicherheit des Docker-Engines**

Der **Docker-Engine** verwendet die **Namespaces** und **Cgroups** des Linux-Kernels, um Container zu isolieren und eine grundlegende Sicherheitsschicht zu bieten. Zusätzlicher Schutz wird durch **Capabilities-Dropping**, **Seccomp** und **SELinux/AppArmor** geboten, um die Container-Isolierung zu verbessern. Ein **Authentifizierungs-Plugin** kann die Benutzeraktionen weiter einschränken.

![Docker-Sicherheit](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Sicheren Zugriff auf die Docker-Engine

Die Docker-Engine kann entweder lokal über einen Unix-Socket oder remote über HTTP erreicht werden. Für den Remote-Zugriff ist es wichtig, HTTPS und **TLS** zu verwenden, um Vertraulichkeit, Integrität und Authentifizierung sicherzustellen.

Die Docker-Engine lauscht standardmäßig auf dem Unix-Socket unter `unix:///var/run/docker.sock`. Auf Ubuntu-Systemen werden die Startoptionen von Docker in `/etc/default/docker` definiert. Um den Remote-Zugriff auf die Docker-API und den Client zu ermöglichen, aktivieren Sie den Docker-Daemon über einen HTTP-Socket, indem Sie die folgenden Einstellungen hinzufügen:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Jedoch wird das Freigeben des Docker-Daemons über HTTP aufgrund von Sicherheitsbedenken nicht empfohlen. Es ist ratsam, Verbindungen mit HTTPS abzusichern. Es gibt zwei Hauptansätze zur Absicherung der Verbindung:
1. Der Client überprüft die Identität des Servers.
2. Sowohl der Client als auch der Server authentifizieren gegenseitig ihre Identität.

Zur Bestätigung der Identität eines Servers werden Zertifikate verwendet. Detaillierte Beispiele für beide Methoden finden Sie in [**dieser Anleitung**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sicherheit von Container-Images

Container-Images können entweder in privaten oder öffentlichen Repositories gespeichert werden. Docker bietet mehrere Speicheroptionen für Container-Images an:

* **[Docker Hub](https://hub.docker.com)**: Ein öffentlicher Registrierungsdienst von Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: Ein Open-Source-Projekt, das Benutzern ermöglicht, ihr eigenes Repository zu hosten.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Das kommerzielle Registrierungsangebot von Docker mit rollenbasierter Benutzerauthentifizierung und Integration mit LDAP-Verzeichnisdiensten.

### Image-Scanning

Container können **Sicherheitslücken** aufweisen, entweder aufgrund des Basisimages oder aufgrund der installierten Software auf dem Basisimage. Docker arbeitet an einem Projekt namens **Nautilus**, das Sicherheitsscans von Containern durchführt und die Sicherheitslücken auflistet. Nautilus vergleicht jedes Container-Image-Layer mit einem Repository für Sicherheitslücken, um Sicherheitslücken zu identifizieren.

Für weitere [**Informationen lesen Sie dies**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Der Befehl **`docker scan`** ermöglicht es Ihnen, vorhandene Docker-Images mithilfe des Image-Namens oder der ID zu scannen. Führen Sie beispielsweise den folgenden Befehl aus, um das hello-world-Image zu scannen:
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
trivy -q -f json <ontainer_name>:<tag>
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

- **Docker Content Trust** verwendet das Notary-Projekt, das auf dem The Update Framework (TUF) basiert, um die Bildsignierung zu verwalten. Weitere Informationen finden Sie unter [Notary](https://github.com/docker/notary) und [TUF](https://theupdateframework.github.io).
- Um Docker Content Trust zu aktivieren, setzen Sie `export DOCKER_CONTENT_TRUST=1`. Diese Funktion ist standardmäßig in Docker Version 1.10 und höher deaktiviert.
- Mit dieser Funktion können nur signierte Bilder heruntergeladen werden. Beim ersten Push des Bildes müssen Passphrasen für die Root- und Tagging-Schlüssel festgelegt werden. Docker unterstützt auch YubiKey für eine verbesserte Sicherheit. Weitere Details finden Sie [hier](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Wenn versucht wird, ein nicht signiertes Bild mit aktiviertem Content Trust herunterzuladen, wird ein Fehler "No trust data for latest" angezeigt.
- Für Bild-Pushes nach dem ersten fordert Docker die Passphrase des Repository-Schlüssels an, um das Bild zu signieren.

Verwenden Sie den Befehl, um Ihre privaten Schlüssel zu sichern:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Beim Wechseln von Docker-Hosts ist es notwendig, die Root- und Repository-Schlüssel zu verschieben, um den Betrieb aufrechtzuerhalten.


***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Sicherheitsfunktionen von Containern

<details>

<summary>Zusammenfassung der Sicherheitsfunktionen von Containern</summary>

### Hauptfunktionen zur Isolierung des Hauptprozesses

In containerisierten Umgebungen ist die Isolierung von Projekten und ihren Prozessen von entscheidender Bedeutung für Sicherheit und Ressourcenmanagement. Hier ist eine vereinfachte Erklärung der wichtigsten Konzepte:

#### **Namespaces**
- **Zweck**: Gewährleistung der Isolierung von Ressourcen wie Prozessen, Netzwerk und Dateisystemen. Insbesondere in Docker halten Namespaces die Prozesse eines Containers getrennt vom Host und anderen Containern.
- **Verwendung von `unshare`**: Der Befehl `unshare` (oder der zugrunde liegende Systemaufruf) wird verwendet, um neue Namespaces zu erstellen und eine zusätzliche Isolationsebene bereitzustellen. Während Kubernetes dies nicht von Natur aus blockiert, tut Docker dies.
- **Einschränkung**: Das Erstellen neuer Namespaces erlaubt es einem Prozess nicht, zu den Standard-Namespaces des Hosts zurückzukehren. Um auf die Namespaces des Hosts zuzugreifen, benötigt man in der Regel Zugriff auf das Verzeichnis `/proc` des Hosts und verwendet `nsenter` zum Einstieg.

#### **Control Groups (CGroups)**
- **Funktion**: Hauptsächlich zur Ressourcenzuweisung zwischen Prozessen verwendet.
- **Sicherheitsaspekt**: CGroups selbst bieten keine Isolationssicherheit, mit Ausnahme der Funktion `release_agent`, die bei falscher Konfiguration potenziell für unbefugten Zugriff ausgenutzt werden könnte.

#### **Capability Drop**
- **Bedeutung**: Es handelt sich um eine wichtige Sicherheitsfunktion zur Isolierung von Prozessen.
- **Funktionalität**: Es beschränkt die Aktionen, die ein Root-Prozess durch das Ablegen bestimmter Fähigkeiten ausführen kann. Selbst wenn ein Prozess mit Root-Rechten läuft, verhindert das Fehlen der erforderlichen Fähigkeiten das Ausführen privilegierter Aktionen, da die Systemaufrufe aufgrund unzureichender Berechtigungen fehlschlagen werden.

Dies sind die **verbleibenden Fähigkeiten**, nachdem der Prozess die anderen abgelegt hat:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Es ist standardmäßig in Docker aktiviert. Es hilft, die **Syscalls weiter einzuschränken**, die der Prozess aufrufen kann.\
Das **Standard-Docker-Seccomp-Profil** finden Sie unter [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker hat eine Vorlage, die Sie aktivieren können: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Dies ermöglicht es, die Fähigkeiten, Syscalls, den Zugriff auf Dateien und Ordner zu reduzieren...

</details>

### Namespaces

**Namespaces** sind eine Funktion des Linux-Kernels, die den Kernelressourcen so aufteilen, dass eine Gruppe von **Prozessen** einen Satz von **Ressourcen** sieht, während eine **andere** Gruppe von **Prozessen** einen **anderen** Satz von Ressourcen sieht. Die Funktion funktioniert so, dass für einen Satz von Ressourcen und Prozessen der gleiche Namespace vorhanden ist, aber diese Namespace beziehen sich auf unterschiedliche Ressourcen. Ressourcen können in mehreren Spaces existieren.

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

Das Linux-Kernel-Feature **cgroups** bietet die Möglichkeit, Ressourcen wie CPU, Speicher, IO und Netzwerkbandbreite für eine Gruppe von Prozessen einzuschränken. Docker ermöglicht die Erstellung von Containern mit der cgroup-Funktion, die eine Ressourcenkontrolle für den spezifischen Container ermöglicht.\
Im Folgenden wird ein Container erstellt, bei dem der Benutzerspeicher auf 500 MB begrenzt ist, der Kernelspeicher auf 50 MB, der CPU-Anteil auf 512 und das blkio-Gewicht auf 400. Der CPU-Anteil ist ein Verhältnis, das die CPU-Nutzung des Containers steuert. Es hat einen Standardwert von 1024 und einen Bereich zwischen 0 und 1024. Wenn drei Container den gleichen CPU-Anteil von 1024 haben, kann jeder Container bei CPU-Ressourcenkonflikten bis zu 33% der CPU nutzen. blkio-weight ist ein Verhältnis, das die IO des Containers steuert. Es hat einen Standardwert von 500 und einen Bereich zwischen 10 und 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Um den cgroup eines Containers zu erhalten, können Sie Folgendes tun:
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

Berechtigungen ermöglichen eine genauere Kontrolle über die Berechtigungen, die für den Root-Benutzer zugelassen werden können. Docker verwendet das Linux-Kernel-Fähigkeiten-Feature, um die Operationen, die innerhalb eines Containers durchgeführt werden können, unabhängig von der Art des Benutzers, einzuschränken.

Wenn ein Docker-Container ausgeführt wird, werden die sensiblen Berechtigungen, die der Prozess verwenden könnte, um aus der Isolation auszubrechen, verworfen. Dadurch wird sichergestellt, dass der Prozess keine sensiblen Aktionen durchführen und ausbrechen kann:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

Dies ist eine Sicherheitsfunktion, die Docker ermöglicht, die Systemaufrufe einzuschränken, die innerhalb des Containers verwendet werden können:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

AppArmor ist eine Kernel-Erweiterung, um Container auf eine begrenzte Menge von Ressourcen mit pro-Programm-Profilen einzuschränken:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

- **Labeling-System**: SELinux weist jedem Prozess und jedem Dateisystemobjekt ein eindeutiges Label zu.
- **Policy Enforcement**: Es setzt Sicherheitsrichtlinien durch, die festlegen, welche Aktionen ein Prozesslabel auf andere Labels im System ausführen kann.
- **Container-Prozess-Labels**: Wenn Container-Engines Container-Prozesse starten, erhalten sie in der Regel ein eingeschränktes SELinux-Label, üblicherweise `container_t`.
- **Datei-Labeling innerhalb von Containern**: Dateien innerhalb des Containers werden normalerweise als `container_file_t` gekennzeichnet.
- **Richtlinienregeln**: Die SELinux-Richtlinie stellt in erster Linie sicher, dass Prozesse mit dem Label `container_t` nur mit Dateien interagieren (lesen, schreiben, ausführen) können, die als `container_file_t` gekennzeichnet sind.

Dieser Mechanismus stellt sicher, dass selbst wenn ein Prozess innerhalb eines Containers kompromittiert ist, er nur mit Objekten interagieren kann, die die entsprechenden Labels haben, und begrenzt somit den potenziellen Schaden solcher Kompromittierungen erheblich.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker spielt ein Autorisierungsplugin eine entscheidende Rolle für die Sicherheit, indem es darüber entscheidet, ob Anfragen an den Docker-Daemon zugelassen oder blockiert werden. Diese Entscheidung wird durch die Prüfung von zwei Schlüsselkontexten getroffen:

- **Authentifizierungskontext**: Dies umfasst umfassende Informationen über den Benutzer, wie z.B. wer sie sind und wie sie sich authentifiziert haben.
- **Befehlskontext**: Dies umfasst alle relevanten Daten, die mit der gestellten Anfrage zusammenhängen.

Diese Kontexte gewährleisten, dass nur legitime Anfragen von authentifizierten Benutzern verarbeitet werden, was die Sicherheit der Docker-Operationen erhöht.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS aus einem Container

Wenn Sie die Ressourcen, die ein Container verwenden kann, nicht ordnungsgemäß begrenzen, kann ein kompromittierter Container den Host, auf dem er ausgeführt wird, DoS (Denial of Service) verursachen.

* CPU-DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
*Bandbreiten-DoS*

Ein Bandbreiten-DoS (Denial-of-Service) ist eine Art von Angriff, bei dem ein Angreifer versucht, die verfügbare Bandbreite eines Netzwerks oder einer bestimmten Verbindung zu überlasten, um den normalen Datenverkehr zu blockieren oder zu verlangsamen. Dies kann durch das Senden einer großen Anzahl von Datenpaketen oder das Ausnutzen von Schwachstellen in der Netzwerkinfrastruktur erreicht werden.

Ein Bandbreiten-DoS-Angriff kann schwerwiegende Auswirkungen haben, da er dazu führen kann, dass legitimer Datenverkehr nicht mehr durchkommt und Dienste oder Systeme nicht mehr erreichbar sind. Um sich vor einem solchen Angriff zu schützen, sollten Netzwerkadministratoren geeignete Sicherheitsmaßnahmen ergreifen, wie z.B. die Überwachung des Netzwerkverkehrs, die Begrenzung der Bandbreite für bestimmte Verbindungen und die Implementierung von Firewalls und Intrusion Detection Systemen.

Es ist auch wichtig, regelmäßig Sicherheitsupdates für die Netzwerkinfrastruktur durchzuführen, um bekannte Schwachstellen zu beheben und potenzielle Angriffsvektoren zu minimieren. Darüber hinaus können Netzwerkadministratoren den Datenverkehr überwachen und verdächtige Aktivitäten erkennen, um schnell auf einen Bandbreiten-DoS-Angriff reagieren zu können.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interessante Docker-Flags

### --privileged-Flag

Auf der folgenden Seite können Sie erfahren, **was das `--privileged`-Flag bedeutet**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Wenn Sie einen Container ausführen, in dem ein Angreifer Zugriff als Benutzer mit niedrigen Privilegien erhält. Wenn Sie eine **fehlerhaft konfigurierte SUID-Binärdatei** haben, kann der Angreifer diese missbrauchen und **Privilegien innerhalb** des Containers eskalieren. Dadurch kann er möglicherweise daraus entkommen.

Das Ausführen des Containers mit der aktivierten Option **`no-new-privileges`** wird **diese Art der Privilegieneskalation verhindern**.
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

Es ist entscheidend, Geheimnisse nicht direkt in Docker-Images einzubetten oder Umgebungsvariablen zu verwenden, da diese Methoden sensible Informationen für jeden freigeben, der über Befehle wie `docker inspect` oder `exec` auf den Container zugreifen kann.

**Docker-Volumes** sind eine sicherere Alternative, die empfohlen wird, um auf sensible Informationen zuzugreifen. Sie können als temporäres Dateisystem im Speicher genutzt werden, um die Risiken von `docker inspect` und Logging zu verringern. Allerdings können Root-Benutzer und solche mit `exec`-Zugriff auf den Container immer noch auf die Geheimnisse zugreifen.

**Docker-Secrets** bieten eine noch sicherere Methode zur Handhabung sensibler Informationen. Für Fälle, in denen während der Image-Build-Phase Geheimnisse benötigt werden, bietet **BuildKit** eine effiziente Lösung mit Unterstützung für Build-Zeit-Geheimnisse, die die Build-Geschwindigkeit verbessern und zusätzliche Funktionen bieten.

Um BuildKit zu nutzen, kann es auf drei Arten aktiviert werden:

1. Über eine Umgebungsvariable: `export DOCKER_BUILDKIT=1`
2. Durch Voranstellen von Befehlen: `DOCKER_BUILDKIT=1 docker build .`
3. Durch Aktivieren als Standard in der Docker-Konfiguration: `{ "features": { "buildkit": true } }`, gefolgt von einem Neustart von Docker.

BuildKit ermöglicht die Verwendung von Build-Zeit-Geheimnissen mit der `--secret`-Option, um sicherzustellen, dass diese Geheimnisse nicht im Image-Build-Cache oder im endgültigen Image enthalten sind. Verwenden Sie dazu einen Befehl wie:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Für in einem laufenden Container benötigte Geheimnisse bieten **Docker Compose und Kubernetes** robuste Lösungen. Docker Compose verwendet einen `secrets`-Schlüssel in der Service-Definition, um geheime Dateien anzugeben, wie im folgenden Beispiel einer `docker-compose.yml`-Datei gezeigt:
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

In Kubernetes-Umgebungen werden Secrets nativ unterstützt und können mit Tools wie [Helm-Secrets](https://github.com/futuresimple/helm-secrets) weiter verwaltet werden. Die Role Based Access Controls (RBAC) von Kubernetes verbessern die Sicherheit der Secret-Verwaltung, ähnlich wie bei Docker Enterprise.

### gVisor

**gVisor** ist ein Anwendungskernel, der in Go geschrieben ist und einen erheblichen Teil der Linux-Systemoberfläche implementiert. Er enthält eine [Open Container Initiative (OCI)](https://www.opencontainers.org)-Laufzeitumgebung namens `runsc`, die eine **Isolierungsgrenze zwischen der Anwendung und dem Host-Kernel** bereitstellt. Die `runsc`-Laufzeitumgebung integriert sich nahtlos mit Docker und Kubernetes, sodass es einfach ist, Sandbox-Container auszuführen.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** ist eine Open-Source-Community, die daran arbeitet, eine sichere Container-Laufzeitumgebung mit leichten virtuellen Maschinen zu entwickeln, die sich wie Container anfühlen und verhalten, aber durch die Verwendung von Hardware-Virtualisierungstechnologie eine **stärkere Workload-Isolierung** als zweite Verteidigungsebene bieten.

{% embed url="https://katacontainers.io/" %}

### Zusammenfassung und Tipps

* Verwenden Sie nicht die `--privileged`-Flagge oder mounten Sie nicht einen [Docker-Socket innerhalb des Containers](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). Der Docker-Socket ermöglicht das Starten von Containern und ist daher ein einfacher Weg, um die volle Kontrolle über den Host zu erlangen, z.B. durch das Ausführen eines anderen Containers mit der `--privileged`-Flagge.
* Führen Sie im Container nicht als Root aus. Verwenden Sie einen [anderen Benutzer](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) und [Benutzernamensräume](https://docs.docker.com/engine/security/userns-remap/). Der Root im Container ist derselbe wie auf dem Host, es sei denn, er wird mit Benutzernamensräumen umgeleitet. Er ist nur leicht eingeschränkt durch Linux-Namespaces, Fähigkeiten und cgroups.
* [Deaktivieren Sie alle Fähigkeiten](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) und aktivieren Sie nur diejenigen, die benötigt werden (`--cap-add=...`). Viele Workloads benötigen keine Fähigkeiten, und das Hinzufügen von Fähigkeiten erhöht den Umfang eines potenziellen Angriffs.
* Verwenden Sie die Sicherheitsoption "no-new-privileges", um zu verhindern, dass Prozesse weitere Privilegien erlangen, z.B. durch suid-Binärdateien.
* Begrenzen Sie die Ressourcen, die dem Container zur Verfügung stehen. Ressourcenbeschränkungen können die Maschine vor Denial-of-Service-Angriffen schützen.
* Passen Sie die Profile von [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (oder SELinux) an, um die Aktionen und Systemaufrufe, die für den Container verfügbar sind, auf das Minimum zu beschränken.
* Verwenden Sie offizielle Docker-Images und verlangen Sie Signaturen oder erstellen Sie eigene Images basierend auf ihnen. Vererben oder verwenden Sie keine [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)-Images. Speichern Sie auch Root-Schlüssel und Passphrase an einem sicheren Ort. Docker plant, Schlüssel mit UCP zu verwalten.
* Erstellen Sie regelmäßig Ihre Images neu, um Sicherheitspatches auf den Host und die Images anzuwenden.
* Verwalten Sie Ihre Secrets sorgfältig, damit es für den Angreifer schwierig ist, darauf zuzugreifen.
* Wenn Sie den Docker-Daemon freigeben, verwenden Sie HTTPS mit Client- und Serverauthentifizierung.
* Verwenden Sie in Ihrem Dockerfile bevorzugt COPY anstelle von ADD. ADD entpackt automatisch komprimierte Dateien und kann Dateien von URLs kopieren. COPY hat diese Funktionen nicht. Vermeiden Sie es, ADD zu verwenden, um nicht anfällig für Angriffe über Remote-URLs und Zip-Dateien zu sein.
* Verwenden Sie separate Container für jeden Mikrodienst.
* Fügen Sie kein SSH in den Container ein. "docker exec" kann verwendet werden, um eine SSH-Verbindung zum Container herzustellen.
* Verwenden Sie kleinere Container-Images.

## Docker Breakout / Privilege Escalation

Wenn Sie sich **innerhalb eines Docker-Containers** befinden oder Zugriff auf einen Benutzer in der **Docker-Gruppe** haben, können Sie versuchen, auszubrechen und Privilegien zu eskalieren:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker Authentication Plugin Bypass

Wenn Sie Zugriff auf den Docker-Socket haben oder Zugriff auf einen Benutzer in der **Docker-Gruppe haben, aber Ihre Aktionen durch ein Docker-Authentifizierungsplugin eingeschränkt sind**, überprüfen Sie, ob Sie es umgehen können:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Absicherung von Docker

* Das Tool [docker-bench-security](https://github.com/docker/docker-bench-security) ist ein Skript, das Dutzende von gängigen Best Practices für die Bereitstellung von Docker-Containern in der Produktion überprüft. Die Tests sind alle automatisiert und basieren auf dem [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Sie müssen das Tool auf dem Host ausführen, auf dem Docker läuft, oder in einem Container mit ausreichenden Berechtigungen. Erfahren Sie **in der README**, wie Sie es ausführen: [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referenzen

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
*
Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [offizielle PEASS & HackTricks-Merchandise](https://peass.creator-spring.com)
* Entdecken Sie [The PEASS Family](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [NFTs](https://opensea.io/collection/the-peass-family)
* Treten Sie der 💬 [Discord-Gruppe](https://discord.gg/hRep4RUj7f) oder der [Telegram-Gruppe](https://t.me/peass) bei oder folgen Sie uns auf Twitter 🐦 [@carlospolopm](https://twitter.com/hacktricks_live).
* Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die GitHub-Repositories [HackTricks](https://github.com/carlospolop/hacktricks) und [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) senden.

</details>
