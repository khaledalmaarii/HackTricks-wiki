# Docker-Forensik

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}

## Container-Modifikation

Es besteht der Verdacht, dass ein bestimmter Docker-Container kompromittiert wurde:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Sie können ganz einfach **die Änderungen finden, die an diesem Container im Vergleich zum Image vorgenommen wurden** mit:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Im vorherigen Befehl bedeutet **C** **Geändert** und **A,** **Hinzugefügt**.\
Wenn Sie feststellen, dass eine interessante Datei wie z. B. `/etc/shadow` geändert wurde, können Sie sie aus dem Container herunterladen, um auf bösartige Aktivitäten zu überprüfen:
```bash
docker cp wordpress:/etc/shadow.
```
Sie können es auch **mit dem Original vergleichen**, indem Sie einen neuen Container ausführen und die Datei daraus extrahieren:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Wenn Sie feststellen, dass **eine verdächtige Datei hinzugefügt wurde**, können Sie auf den Container zugreifen und diese überprüfen:
```bash
docker exec -it wordpress bash
```
## Bildmodifikationen

Wenn Ihnen ein exportiertes Docker-Image (wahrscheinlich im `.tar`-Format) zur Verfügung steht, können Sie [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) verwenden, um **eine Zusammenfassung der Modifikationen** zu extrahieren:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dann kannst du das Bild **dekomprimieren** und auf die **Blobs zugreifen**, um nach verdächtigen Dateien zu suchen, die du im Änderungsverlauf gefunden haben könntest:
```bash
tar -xf image.tar
```
### Grundlegende Analyse

Sie können **grundlegende Informationen** aus dem ausgeführten Image erhalten:
```bash
docker inspect <image>
```
Sie können auch eine Zusammenfassung der **Änderungshistorie** mit folgendem Befehl erhalten:
```bash
docker history --no-trunc <image>
```
Sie können auch ein **Dockerfile aus einem Image generieren** mit:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Tauchen

Um hinzugefügte/geänderte Dateien in Docker-Images zu finden, können Sie auch das [**dive**](https://github.com/wagoodman/dive) (laden Sie es von [**Releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) Dienstprogramm verwenden:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dies ermöglicht es Ihnen, **durch die verschiedenen Blöcke von Docker-Images zu navigieren** und zu überprüfen, welche Dateien geändert/hinzugefügt wurden. **Rot** bedeutet hinzugefügt und **gelb** bedeutet geändert. Verwenden Sie die **Tab**-Taste, um zur anderen Ansicht zu wechseln, und die **Leertaste**, um Ordner zu öffnen/schließen.

Damit können Sie nicht auf den Inhalt der verschiedenen Stufen des Images zugreifen. Um dies zu tun, müssen Sie **jede Schicht dekomprimieren und darauf zugreifen**.\
Sie können alle Schichten eines Images aus dem Verzeichnis, in dem das Image dekomprimiert wurde, dekomprimieren, indem Sie ausführen:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Anmeldeinformationen aus dem Speicher

Beachten Sie, dass wenn Sie einen Docker-Container innerhalb eines Hosts ausführen, **können Sie die Prozesse, die im Container ausgeführt werden, vom Host aus sehen**, indem Sie einfach `ps -ef` ausführen.

Daher können Sie (als Root) den Speicher der Prozesse vom Host aus **dumpen** und nach **Anmeldeinformationen** suchen, genau [**wie im folgenden Beispiel**](../../linux-hardening/privilege-escalation/#process-memory).
