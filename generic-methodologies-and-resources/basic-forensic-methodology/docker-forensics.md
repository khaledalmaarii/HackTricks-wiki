# Docker Forensika

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Houer-wysiging

Daar is vermoedens dat 'n sekere Docker-houer gekompromitteer is:
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
In die vorige opdrag beteken **C** **Veranderd** en **A,** **Bygevoeg**.\
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
As jy vind dat **'n verdagte lêer bygevoeg is**, kan jy toegang verkry tot die houer en dit nagaan:
```bash
docker exec -it wordpress bash
```
## Beeldwysigings

Wanneer jy 'n uitgevoerde docker-beeld (waarskynlik in `.tar`-formaat) ontvang, kan jy [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) gebruik om 'n opsomming van die wysigings te **onttrek**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Dan kan jy die prentjie **ontplooi** en **toegang verkry tot die blobs** om te soek na verdagte lêers wat jy dalk in die veranderingsgeskiedenis gevind het:
```bash
tar -xf image.tar
```
### Basiese Analise

Jy kan **basiese inligting** kry van die lopende prentjie:
```bash
docker inspect <image>
```
Jy kan ook 'n opsomming van die **geskiedenis van veranderinge** kry met:
```bash
docker history --no-trunc <image>
```
Jy kan ook 'n **dockerfile van 'n prentjie** genereer met:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Duik

Om bygevoegde/gewysigde lêers in Docker-beelde te vind, kan jy ook die [**duik**](https://github.com/wagoodman/dive) (laai dit af vanaf [**vrystellings**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) nut gebruik:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Dit stel jou in staat om **deur die verskillende blobs van Docker-beelde te blaai** en te kyk watter lêers gewysig/toegevoeg is. **Rooi** beteken toegevoeg en **geel** beteken gewysig. Gebruik **tab** om na die ander aansig te skuif en **spasie** om vouers in/uit te vou.

Met die sal jy nie toegang tot die inhoud van die verskillende fases van die beeld hê nie. Om dit te doen, sal jy elke laag moet dekomprimeer en toegang daartoe hê.\
Jy kan al die lae van 'n beeld dekomprimeer vanuit die gids waar die beeld gedekomprimeer is deur die volgende uit te voer:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Legitieme inligting uit geheue

Let daarop dat wanneer jy 'n docker-houer binne 'n gasheer uitvoer, **kan jy die prosesse wat op die houer loop vanaf die gasheer sien** deur eenvoudig `ps -ef` uit te voer.

Daarom kan jy (as root) **die geheue van die prosesse uit die gasheer dump** en soek na **legitieme inligting** net [**soos in die volgende voorbeeld**](../../linux-hardening/privilege-escalation/#process-memory).

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil hê jou **maatskappy geadverteer moet word in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
