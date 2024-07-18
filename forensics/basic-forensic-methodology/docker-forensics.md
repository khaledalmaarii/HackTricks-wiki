# Docker Forensics

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Container aanpassing

Daar is vermoedens dat 'n sekere docker-container gekompromitteer is:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Jy kan maklik **die wysigings wat aan hierdie houer gedoen is met betrekking tot die prent** vind met:
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
In die vorige bevel beteken **C** **Veranderd** en **A,** **Bygevoeg**.\
As jy vind dat 'n interessante lêer soos `/etc/shadow` gewysig is, kan jy dit van die houer aflaai om vir skadelike aktiwiteit te ondersoek met:
```bash
docker cp wordpress:/etc/shadow.
```
Jy kan dit ook **vergelyk met die oorspronklike een** deur 'n nuwe houer te hardloop en die lêer daaruit te onttrek:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Indien jy vind dat **'n verdagte lêer bygevoeg is** kan jy die houer toegang en dit nagaan:
```bash
docker exec -it wordpress bash
```
## Beeldwysigings

Wanneer jy 'n uitgevoerde docker-beeld (waarskynlik in `.tar`-formaat) ontvang, kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om **'n opsomming van die wysigings** te onttrek:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dan kan jy die prentjie **ontpak** en die blobs **toegang** om te soek na verdagte lêers wat jy dalk in die veranderingsgeskiedenis gevind het:
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** kry van die beeld wat loop:
```bash
docker inspect <image>
```
Jy kan ook 'n opsomming kry van die **geskiedenis van veranderinge** met:
```bash
docker history --no-trunc <image>
```
Jy kan ook 'n **dockerfile van 'n prent genereer** met:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Duik

Om bygevoegde/gewysigde lêers in Docker-beelde te vind, kan jy ook die [**duik**](https://github.com/wagoodman/dive) (laai dit af van [**vrystellings**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) nutsmiddel gebruik:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit stel jou in staat om **deur die verskillende blobs van docker-beelde te navigeer** en te kontroleer watter lêers gewysig/toegevoeg is. **Rooi** beteken toegevoeg en **geel** beteken gewysig. Gebruik **tab** om na die ander aansig te beweeg en **spasie** om vouers in/uit te klap.

Met dit sal jy nie in staat wees om toegang tot die inhoud van die verskillende fases van die beeld te verkry nie. Om dit te doen, sal jy **elke laag moet dekompresseer en toegang daartoe moet verkry**.\
Jy kan al die lêers van 'n beeld dekompresseer vanaf die gids waar die beeld gedekompresseer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Gelde vanaf geheue

Let daarop dat wanneer jy 'n docker houer binne 'n gasheer hardloop **jy die prosesse wat op die houer hardloop vanaf die gasheer kan sien** deur net `ps -ef` uit te voer

Daarom (as root) kan jy **die geheue van die prosesse dump** vanaf die gasheer en soek na **gelde** net [**soos in die volgende voorbeeld**](../../linux-hardening/privilege-escalation/#process-memory).
