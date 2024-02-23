# Docker-sekuriteit

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Basiese Docker-enjinsikuriteit**

Die **Docker-enjin** maak gebruik van die Linux-kernel se **Namespaces** en **Cgroups** om houers te isoleer, wat 'n basiese veiligheidslaag bied. Addisionele beskerming word gebied deur **Capabilities dropping**, **Seccomp**, en **SELinux/AppArmor**, wat houer-isolasie verbeter. 'n **Auth-plugin** kan verdere beperkings op gebruikersaksies plaas.

![Docker-sekuriteit](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Veilige Toegang tot die Docker-enjin

Die Docker-enjin kan óf plaaslik via 'n Unix-aansluiting óf op afstand deur middel van HTTP benader word. Vir afgeleë toegang is dit noodsaaklik om HTTPS en **TLS** te gebruik om vertroulikheid, integriteit, en outentisiteit te verseker.

Die Docker-enjin luister standaard na die Unix-aansluiting by `unix:///var/run/docker.sock`. Op Ubuntu-stelsels word Docker se aanvangsopsies in `/etc/default/docker` gedefinieer. Om afgeleë toegang tot die Docker-API en -klient moontlik te maak, stel die Docker-daemon bloot oor 'n HTTP-aansluiting deur die volgende instellings by te voeg:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Egter, die blootstelling van die Docker daemon oor HTTP word nie aanbeveel nie weens sekuriteitskwessies. Dit word aanbeveel om verbindings te beveilig deur HTTPS te gebruik. Daar is twee hoofbenaderings om die verbinding te beveilig:

1. Die klient verifieer die identiteit van die bediener.
2. Beide die klient en bediener verifieer mekaar se identiteit.

Sertifikate word gebruik om 'n bediener se identiteit te bevestig. Vir gedetailleerde voorbeelde van beide metodes, verwys na [**hierdie gids**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sekuriteit van Houverbeeldings

Houverbeeldings kan gestoor word in privaat of openbare repose. Docker bied verskeie stooropsies vir houverbeeldings:

* [**Docker Hub**](https://hub.docker.com): 'n Openbare registerdiens van Docker.
* [**Docker Registry**](https://github.com/docker/distribution): 'n oopbronprojek wat gebruikers toelaat om hul eie register te hê.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Docker se kommersiële registeraanbod, met rolgebaseerde gebruiker-verifikasie en integrasie met LDAP-gidsdienste.

### Beeldskandering

Houverhouers kan **sekuriteitskwessies** hê weens die basisbeeld of die sagteware wat bo-op die basisbeeld geïnstalleer is. Docker werk aan 'n projek genaamd **Nautilus** wat sekuriteitskandering van Houverhouers doen en die kwessies lys. Nautilus werk deur elke Houverbeeldlaag met die kwesbaarheidsrepositorium te vergelyk om sekuriteitsgate te identifiseer.

Vir meer [**inligting lees hierdie**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Die **`docker scan`** bevel stel jou in staat om bestaande Docker-beelde te skandeer deur die beeldnaam of ID te gebruik. Voer byvoorbeeld die volgende bevel uit om die hello-world beeld te skandeer:
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
### Docker Beeldondertekening

Docker beeldondertekening verseker die veiligheid en integriteit van beelde wat in houers gebruik word. Hier is 'n beknopte verduideliking:

* **Docker Inhoudsvertroue** maak gebruik van die Notary-projek, gebaseer op The Update Framework (TUF), om beeldondertekening te bestuur. Vir meer inligting, sien [Notary](https://github.com/docker/notary) en [TUF](https://theupdateframework.github.io).
* Om Docker inhoudsvertroue te aktiveer, stel `export DOCKER_CONTENT_TRUST=1` in. Hierdie funksie is standaard af in Docker weergawe 1.10 en later.
* Met hierdie funksie geaktiveer, kan slegs ondertekende beelde afgelaai word. Die aanvanklike beeldstoot vereis die instelling van wagwoorde vir die hoof- en etikettering sleutels, met Docker wat ook Yubikey ondersteun vir verbeterde veiligheid. Meer besonderhede kan hier gevind word [hier](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
* 'n Poging om 'n ondertekende beeld met inhoudsvertroue geaktiveer af te trek, lei tot 'n "Geen vertroue data vir die nuutste" fout.
* Vir beeldstote na die eerste, vra Docker vir die wagwoord van die stoor sleutel om die beeld te onderteken.

Om jou privaat sleutels te rugsteun, gebruik die bevel:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Wanneer jy oorskakel na Docker-gashere, is dit nodig om die hoof- en bewaarpleksleutels te skuif om werksaamhede te handhaaf.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkvloeie outomaties** aangedryf deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Kontainer Sekuriteitskenmerke

<details>

<summary>Opsomming van Kontainer Sekuriteitskenmerke</summary>

#### Hoofproses Isolasiekenmerke

In gekontainerde omgewings is die isolering van projekte en hul prosesse van uiterste belang vir sekuriteit en hulpbronbestuur. Hier is 'n vereenvoudigde verduideliking van sleutelkonsepte:

**Namespaces**

* **Doel**: Verseker isolasie van hulpbronne soos prosesse, netwerke en lêersisteme. Veral in Docker hou namespaces 'n kontainer se prosesse geskei van die gasheer en ander kontainers.
* **Gebruik van `unshare`**: Die `unshare`-bevel (of die onderliggende syscall) word gebruik om nuwe namespaces te skep, wat 'n bygevoegde laag van isolasie bied. Tog, terwyl Kubernetes dit nie inherent blokkeer nie, doen Docker dit.
* **Beperking**: Die skep van nuwe namespaces laat nie 'n proses toe om terug te keer na die gasheer se verstek-namespaces nie. Om deur te dring tot die gasheer-namespaces, sal 'n persoon tipies toegang tot die gasheer se `/proc`-gids benodig, deur `nsenter` vir toegang te gebruik.

**Beheergroepe (CGroups)**

* **Funksie**: Primêr gebruik vir die toekenning van hulpbronne onder prosesse.
* **Sekuriteitaspek**: CGroups self bied nie isolasiesekuriteit nie, behalwe vir die `release_agent`-kenmerk, wat, indien verkeerd geconfigureer, moontlik uitgebuit kan word vir ongemagtigde toegang.

**Bevoegdheidsverwerping**

* **Belangrikheid**: Dit is 'n kritieke sekuriteitskenmerk vir proses-isolasie.
* **Funksionaliteit**: Dit beperk die aksies wat 'n hoofproses kan uitvoer deur sekere bevoegdhede af te skakel. Selfs as 'n proses met hoofregte loop, verhoed die ontbrekende nodige bevoegdhede dat dit bevoorregte aksies kan uitvoer, aangesien die syscalls sal misluk as gevolg van ontoereikende toestemmings.

Dit is die **oorblywende bevoegdhede** nadat die proses die ander laat val:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Dit is standaard geaktiveer in Docker. Dit help om selfs meer die syscalls te beperk wat die proses kan aanroep.\
Die standaard Docker Seccomp profiel kan gevind word op [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker het 'n sjabloon wat jy kan aktiveer: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Dit sal toelaat om kapasiteite, syscalls, toegang tot lêers en vouers te verminder...

</details>

### Namespaces

**Namespaces** is 'n kenmerk van die Linux-kernel wat kernelbronne verdeel sodat een stel prosesse een stel bronne sien terwyl 'n ander stel prosesse 'n ander stel bronne sien. Die kenmerk werk deur dieselfde namespace vir 'n stel bronne en prosesse te hê, maar daardie namespaces verwys na afsonderlike bronne. Bronne kan in meervoudige ruimtes bestaan.

Docker maak gebruik van die volgende Linux-kernel Namespaces om houer-isolasie te bereik:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

Vir meer inligting oor die namespaces, besoek die volgende bladsy:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux-kernelkenmerk **cgroups** bied die vermoë om hulpbronne soos cpu, geheue, io, netwerkbandwydte te beperk onder 'n stel prosesse. Docker maak dit moontlik om Houers te skep deur die gebruik van die cgroup-funksie wat hulpbronbeheer vir die spesifieke Houer moontlik maak.\
Hierdie is 'n Houer wat geskep is met gebruikerspasgeheue beperk tot 500m, kernelgeheue beperk tot 50m, cpu-aandeel tot 512, blkioweight tot 400. CPU-aandeel is 'n verhouding wat die Houer se CPU-gebruik beheer. Dit het 'n verstekwaarde van 1024 en 'n reeks tussen 0 en 1024. As drie Houers dieselfde CPU-aandeel van 1024 het, kan elke Houer tot 33% van die CPU neem in geval van CPU-hulpbronstrydigheid. blkio-weight is 'n verhouding wat die Houer se IO beheer. Dit het 'n verstekwaarde van 500 en 'n reeks tussen 10 en 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Om die cgroup van 'n houer te kry, kan jy die volgende doen:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Vir meer inligting kyk:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Bevoegdhede

Bevoegdhede maak **fyn beheer vir die bevoegdhede wat aan die root-gebruiker toegelaat kan word**. Docker gebruik die Linux-kernel bevoegdheidseienskap om **die operasies wat binne 'n houer gedoen kan word te beperk** ongeag die tipe gebruiker.

Wanneer 'n Docker-houer uitgevoer word, **laat die proses sensitiewe bevoegdhede vall wat die proses kon gebruik om te ontsnap uit die isolasie**. Dit probeer verseker dat die proses nie sensitiewe aksies kan uitvoer en ontsnap nie:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

Dit is 'n sekuriteitskenmerk wat Docker toelaat om **die syscalls te beperk** wat binne die houer gebruik kan word:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

**AppArmor** is 'n kernel-verbetering om **houers** tot 'n **beperkte** stel **hulpbronne** met **per-program profiele** te beperk:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

* **Etiketteringstelsel**: SELinux ken 'n unieke etiket toe aan elke proses en lêersisteemobjek.
* **Beleidshandhawing**: Dit dwing sekuriteitsbeleide af wat bepaal watter aksies 'n prosesetiket op ander etikette binne die stelsel kan uitvoer.
* **Houerprosesetikette**: Wanneer houermasjiene houerprosesse inisieer, word hulle gewoonlik toegewys aan 'n beperkte SELinux-etiket, gewoonlik `container_t`.
* **Lêeretikettering binne Houers**: Lêers binne die houer word gewoonlik geëtiketteer as `container_file_t`.
* **Beleidreëls**: Die SELinux-beleid verseker hoofsaaklik dat prosesse met die `container_t`-etiket slegs kan interaksie hê (lees, skryf, uitvoer) met lêers wat geëtiketteer is as `container_file_t`.

Hierdie meganisme verseker dat selfs as 'n proses binne 'n houer gekompromitteer is, dit beperk is tot interaksie slegs met voorwerpe wat die ooreenstemmende etikette het, wat die potensiële skade van sulke kompromitterings aansienlik beperk.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker speel 'n outorisasie-inprop 'n kritieke rol in sekuriteit deur te besluit of versoek aan die Docker-daemon toegelaat of geblokkeer moet word. Hierdie besluit word geneem deur twee sleutelkontekste te ondersoek:

* **Outentiseringskonteks**: Dit sluit omvattende inligting oor die gebruiker in, soos wie hulle is en hoe hulle hulself geoutentiseer het.
* **Opdragkonteks**: Dit bestaan uit alle relevante data wat verband hou met die versoek wat gedoen word.

Hierdie kontekste help verseker dat slegs legitieme versoek van geoutentiseerde gebruikers verwerk word, wat die sekuriteit van Docker-operasies verbeter.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS vanuit 'n houer

As jy nie die hulpbronne wat 'n houer kan gebruik behoorlik beperk nie, kan 'n gekompromitteerde houer die gasheer waarop dit hardloop, DoS. 

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandwydte DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interessante Docker-vlakke

### --bevoorregte vlag

Op die volgende bladsy kan jy leer **wat impliseer die `--bevoorregte` vlag**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --sekuriteit-optie

#### geen-nuwe-voorregte

As jy 'n houer hardloop waar 'n aanvaller daarin slaag om toegang te kry as 'n lae-voorregte-gebruiker. As jy 'n **verkeerd ingestelde suid-binêre lêer** het, kan die aanvaller dit misbruik en **voorregte binne** die houer **verhoog**. Dit kan hom toelaat om daaruit te ontsnap.

Die houer hardloop met die **`geen-nuwe-voorregte`** opsie geaktiveer sal hierdie soort voorregverhoging **voorkom**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Ander
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
Vir meer **`--security-opt`**-opsies, kyk na: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Ander Sekuriteits-oorwegings

### Bestuur van Geheime: Beste Praktyke

Dit is noodsaaklik om te vermy om geheime direk in Docker-beelde in te sluit of om omgewingsveranderlikes te gebruik, aangesien hierdie metodes jou sensitiewe inligting blootstel aan enigiemand met toegang tot die houer deur opdragte soos `docker inspect` of `exec`.

**Docker volumes** is 'n veiliger alternatief, aanbeveel vir die benadering van sensitiewe inligting. Hulle kan gebruik word as 'n tydelike lêersisteem in geheue, wat die risiko's wat verband hou met `docker inspect` en logging verminder. Nietemin kan root-gebruikers en diegene met `exec`-toegang tot die houer steeds die geheime benader.

**Docker-geheime** bied 'n selfs veiliger metode vir die hantering van sensitiewe inligting. Vir gevalle waar geheime tydens die beeldboufase benodig word, bied **BuildKit** 'n doeltreffende oplossing met ondersteuning vir bou-tyd geheime, wat bou spoed verbeter en addisionele kenmerke bied.

Om van BuildKit gebruik te maak, kan dit op drie maniere geaktiveer word:

1. Deur 'n omgewingsveranderlike: `export DOCKER_BUILDKIT=1`
2. Deur opdragte te vooraf te gaan: `DOCKER_BUILDKIT=1 docker build .`
3. Deur dit standaard in die Docker-konfigurasie te aktiveer: `{ "features": { "buildkit": true } }`, gevolg deur 'n Docker-herlaai.

BuildKit maak die gebruik van bou-tyd geheime met die `--secret`-opsie moontlik, wat verseker dat hierdie geheime nie ingesluit word in die beeldbou-kas of die finale beeld nie, deur 'n opdrag soos die volgende te gebruik:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Vir geheime wat benodig word in 'n lopende houer, bied **Docker Compose en Kubernetes** robuuste oplossings. Docker Compose maak gebruik van 'n `secrets` sleutel in die diensdefinisie om geheime lêers te spesifiseer, soos in 'n `docker-compose.yml` voorbeeld:
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
Hierdie konfigurasie maak dit moontlik om geheime te gebruik wanneer dienste met Docker Compose begin.

In Kubernetes-omgewings word geheime ondersteun en kan verder bestuur word met gereedskap soos [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Kubernetes se Rol Gebaseerde Toegangsbeheer (RBAC) verbeter geheimbestuursekuriteit, soortgelyk aan Docker Enterprise.

### gVisor

**gVisor** is 'n aansoekkernel, geskryf in Go, wat 'n aansienlike deel van die Linux-sisteemoppervlak implementeer. Dit sluit 'n [Open Container Initiative (OCI)](https://www.opencontainers.org) uitvoertyd genaamd `runsc` in wat 'n **isoleringgrens tussen die aansoek en die gasheerkernel** bied. Die `runsc`-uitvoertyd integreer met Docker en Kubernetes, wat dit eenvoudig maak om gesandbokte houers te hardloop.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** is 'n oopbron-gemeenskap wat werk aan die bou van 'n veilige houeruitvoertyd met ligte virtuele masjiene wat soos houers voel en optree, maar **sterker werklas-isolering bied deur hardeware-virtualisasietegnologie as 'n tweede verdedigingslaag** te gebruik.

{% embed url="https://katacontainers.io/" %}

### Opsomming van Wenke

* **Moenie die `--privileged` vlag gebruik of 'n** [**Docker-aansluiting binne die houer koppel**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Die Docker-aansluiting maak dit moontlik om houers te skep, dus is dit 'n maklike manier om volle beheer oor die gasheer te neem, byvoorbeeld deur 'n ander houer met die `--privileged` vlag te hardloop.
* **Moenie as wortel binne die houer hardloop nie. Gebruik 'n** [**verskillende gebruiker**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **en** [**gebruikersnaamruimtes**](https://docs.docker.com/engine/security/userns-remap/)**.** Die wortel in die houer is dieselfde as op die gasheer tensy dit met gebruikersnaamruimtes herkartografeer word. Dit word slegs lig beperk deur, hoofsaaklik, Linux-naamruimtes, vermoëns en cgroups.
* [**Laat alle vermoëns vaar**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) en aktiveer slegs dié wat benodig word** (`--cap-add=...`). Baie werklaste benodig geen vermoëns nie en die byvoeging daarvan verhoog die omvang van 'n potensiële aanval.
* [**Gebruik die "no-new-privileges" veiligheidsoptie**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) om te voorkom dat prosesse meer vermoëns verwerf, byvoorbeeld deur suid-binêre lêers.
* [**Beperk hulpbronne wat aan die houer beskikbaar is**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Hulpbronlimiete kan die masjien teen ontkenning van diensaanvalle beskerm.
* **Pas** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(of SELinux)** profiele aan om die aksies en stelseloproepe wat vir die houer beskikbaar is, tot die minimum benodigde te beperk.
* **Gebruik** [**amptelike Docker-beelde**](https://docs.docker.com/docker-hub/official\_images/) **en vereis handtekeninge** of bou jou eie gebaseer daarop. Moet nie beelde erf of gebruik wat [agterdeur](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) bevat nie. Berg ook wortelsleutels, wagwoord op 'n veilige plek op. Docker het planne om sleutels met UCP te bestuur.
* **Herbou gereeld** jou beelde om **sekuriteitsopdaterings op die gasheer en beelde toe te pas.**
* Bestuur jou **geheime wyselik** sodat dit moeilik is vir die aanvaller om daartoe toegang te verkry.
* As jy **die Docker-daemon blootstel, gebruik HTTPS** met klient- en bedienerverifikasie.
* In jou Docker-lêer, **gee voorkeur aan KOPIEER eerder as BYVOEG.** BYVOEG onttrek outomaties gezipde lêers en kan lêers vanaf URL's kopieer. KOPIEER het nie hierdie vermoëns nie. Vermy waar moontlik die gebruik van BYVOEG sodat jy nie vatbaar is vir aanvalle deur afgeleë URL's en Zip-lêers nie.
* Het **afsonderlike houers vir elke mikrodiens**
* **Moenie ssh** binne die houer sit nie, "docker exec" kan gebruik word om na die houer te ssh.
* Het **kleiner** houer **beelde**

## Docker Uitbreek / Voorreg-escalasie

As jy **binne 'n Docker-houer is** of jy het toegang tot 'n gebruiker in die **docker-groep**, kan jy probeer om **te ontsnap en voorregte te eskaleer**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker-verifikasiepropbypass

As jy toegang het tot die Docker-aansluiting of toegang het tot 'n gebruiker in die **docker-groep maar jou aksies word beperk deur 'n Docker-verifikasieprop**, kyk of jy dit kan **verbygaan:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Verharding van Docker

* Die gereedskap [**docker-bench-security**](https://github.com/docker/docker-bench-security) is 'n skrip wat tientalle algemene beste praktyke ondersoek rakende die implementering van Docker-houers in produksie. Die toetse is almal geoutomatiseer en is gebaseer op die [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Jy moet die gereedskap vanaf die gasheer wat Docker hardloop of vanaf 'n houer met genoeg voorregte hardloop. Vind uit **hoe om dit in die README te hardloop:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Verwysings

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

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en te **outomatiseer** met behulp van die wêreld se **mees gevorderde** gemeenskapsgereedskap.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
