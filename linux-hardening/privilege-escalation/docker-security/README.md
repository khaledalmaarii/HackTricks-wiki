# Docker Sekuriteit

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en outomatiseer met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Basiese Docker Engine Sekuriteit**

Die **Docker-engine** maak gebruik van die Linux-kernel se **Namespaces** en **Cgroups** om houers te isoleer en bied 'n basiese vlak van sekuriteit. Addisionele beskerming word gebied deur **Capabilities dropping**, **Seccomp**, en **SELinux/AppArmor**, wat houer-isolasie verbeter. 'n **Auth plugin** kan verdere beperkings plaas op gebruikersaksies.

![Docker Sekuriteit](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Veilige Toegang tot Docker Engine

Die Docker-engine kan plaaslik benader word deur 'n Unix-aansluiting of op afstand deur middel van HTTP. Vir afstandsbenadering is dit noodsaaklik om HTTPS en **TLS** te gebruik om vertroulikheid, integriteit en outentisiteit te verseker.

Die Docker-engine luister standaard na die Unix-aansluiting by `unix:///var/run/docker.sock`. Op Ubuntu-stelsels word Docker se opstartopsies gedefinieer in `/etc/default/docker`. Om afstandsbenadering tot die Docker API en klient moontlik te maak, stel die Docker-daemon bloot oor 'n HTTP-aansluiting deur die volgende instellings by te voeg:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Nietemin, dit word nie aanbeveel om die Docker daemon oor HTTP bloot te stel nie as gevolg van sekuriteitskwessies. Dit is raadsaam om verbinding te beveilig deur gebruik te maak van HTTPS. Daar is twee hoofbenaderings om die verbinding te beveilig:
1. Die klient verifieer die identiteit van die bediener.
2. Beide die klient en bediener verifieer mekaar se identiteit.

Sertifikate word gebruik om die identiteit van 'n bediener te bevestig. Vir gedetailleerde voorbeelde van beide metodes, verwys na [**hierdie gids**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sekuriteit van Houderverspreidings

Houderverspreidings kan in private of openbare verspreidingsbewaarplekke gestoor word. Docker bied verskeie stooropsies vir houderverspreidings:

* **[Docker Hub](https://hub.docker.com)**: 'n Openbare registerdiens van Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: 'n Opensourceprojek wat gebruikers in staat stel om hul eie register te bedryf.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Docker se kommersiële registerdiens wat rolgebaseerde gebruikersverifikasie en integrasie met LDAP-gidsdienste bied.

### Beeldskandering

Houers kan **sekuriteitskwessies** hê as gevolg van die basisbeeld of as gevolg van die sagteware wat bo-op die basisbeeld geïnstalleer is. Docker werk aan 'n projek genaamd **Nautilus** wat sekuriteitskandering van Houers doen en die kwessies lys. Nautilus werk deur elke Houerbeeldlaag te vergelyk met 'n kwessierepositorium om sekuriteitslekke te identifiseer.

Vir meer [**inligting lees hierdie**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Die **`docker scan`** opdrag stel jou in staat om bestaande Docker-beelde te skandeer deur die beeldnaam of ID te gebruik. Voer byvoorbeeld die volgende opdrag uit om die hello-world beeld te skandeer:
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

- **Docker Inhoudsvertroue** maak gebruik van die Notary-projek, gebaseer op The Update Framework (TUF), om beeldondertekening te bestuur. Vir meer inligting, sien [Notary](https://github.com/docker/notary) en [TUF](https://theupdateframework.github.io).
- Om Docker inhoudsvertroue te aktiveer, stel `export DOCKER_CONTENT_TRUST=1` in. Hierdie funksie is standaard af in Docker weergawe 1.10 en later.
- Met hierdie funksie geaktiveer, kan slegs ondertekende beelde afgelaai word. Die aanvanklike beeldstoot vereis die instelling van wagwoorde vir die hoof- en etiketteringssleutels, terwyl Docker ook Yubikey ondersteun vir verbeterde veiligheid. Meer besonderhede kan [hier](https://blog.docker.com/2015/11/docker-content-trust-yubikey/) gevind word.
- As jy probeer om 'n ondertekende beeld met inhoudsvertroue geaktiveer af te trek, sal jy 'n "Geen vertroue data vir latest" fout kry.
- Vir beeldstote na die eerste, vra Docker vir die wagwoord van die stoor sleutel om die beeld te onderteken.

Om jou privaat sleutels te rugsteun, gebruik die opdrag:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Wanneer jy oorskakel na Docker-gashere, is dit nodig om die root- en bewaarpleksleutels te skuif om werksaamhede te behou.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werksvloeie te bou wat aangedryf word deur die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Kontainer Sekuriteitskenmerke

<details>

<summary>Oorsig van Kontainer Sekuriteitskenmerke</summary>

### Hoofproses Isolasiekenmerke

In gekontainerde omgewings is die isolasie van projekte en hul prosesse van uiterste belang vir sekuriteit en hulpbronbestuur. Hier is 'n vereenvoudigde verduideliking van sleutelkonsepte:

#### **Namespaces**
- **Doel**: Verseker isolasie van hulpbronne soos prosesse, netwerk en lêersisteme. Veral in Docker hou namespaces 'n kontainer se prosesse geskei van die gasheer en ander kontainers.
- **Gebruik van `unshare`**: Die `unshare`-opdrag (of die onderliggende stelseloproep) word gebruik om nuwe namespaces te skep, wat 'n bygevoegde laag van isolasie bied. Alhoewel Kubernetes dit nie inherent blokkeer nie, doen Docker dit wel.
- **Beperking**: Die skep van nuwe namespaces laat nie toe dat 'n proses terugkeer na die gasheer se verstek-namespaces nie. Om toegang tot die gasheer-namespaces te verkry, sal 'n persoon tipies toegang tot die gasheer se `/proc`-gids benodig en `nsenter` gebruik om in te gaan.

#### **Beheergroepe (CGroups)**
- **Funksie**: Primêr gebruik vir die toekenning van hulpbronne aan prosesse.
- **Sekuriteitsaspek**: CGroups self bied nie isolasie-sekuriteit nie, behalwe vir die `release_agent`-kenmerk wat, as dit verkeerd gekonfigureer is, potensieel uitgebuit kan word vir ongemagtigde toegang.

#### **Bevoegdheid Laat Vaar**
- **Belangrikheid**: Dit is 'n belangrike sekuriteitskenmerk vir prosesisolasie.
- **Funksionaliteit**: Dit beperk die aksies wat 'n rootproses kan uitvoer deur sekere bevoegdhede te laat vaar. Selfs as 'n proses met root-voorregte loop, sal dit nie bevoorregte aksies kan uitvoer nie, aangesien die stelseloproepe weens onvoldoende toestemmings sal misluk.

Dit is die **oorblywende bevoegdhede** nadat die proses die ander laat vaar:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Dit is standaard geaktiveer in Docker. Dit help om die syscalls wat die proses kan aanroep, nog meer te beperk.\
Die standaard Docker Seccomp profiel kan gevind word by [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker het 'n sjabloon wat jy kan aktiveer: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Dit sal toelaat om funksies, syscalls, toegang tot lêers en vouers te verminder...

</details>

### Namespaces

**Namespaces** is 'n kenmerk van die Linux-kernel wat die kernelbronne verdeel sodat een stel **prosesse** een stel **bronne sien**, terwyl 'n **ander** stel **prosesse** 'n **verskillende** stel bronne sien. Die kenmerk werk deur dieselfde namespace vir 'n stel bronne en prosesse te hê, maar daardie namespaces verwys na afsonderlike bronne. Bronne kan in meerdere ruimtes bestaan.

Docker maak gebruik van die volgende Linux-kernel Namespaces om kontainer-isolasie te bereik:

* pid-namespace
* mount-namespace
* netwerk-namespace
* ipc-namespace
* UTS-namespace

Vir **meer inligting oor die namespaces**, kyk na die volgende bladsy:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Die Linux-kernelkenmerk **cgroups** bied die vermoë om hulpbronne soos CPU, geheue, IO, netwerkbandwydte te beperk vir 'n stel prosesse. Docker maak dit moontlik om Kontainers te skep met behulp van die cgroup-funksie wat hulpbronbeheer vir die spesifieke Kontainer moontlik maak.\
Hieronder is 'n Kontainer wat geskep is met gebruikersruimte-geheue beperk tot 500m, kernelgeheue beperk tot 50m, CPU-aandeel tot 512, blkioweight tot 400. CPU-aandeel is 'n verhouding wat Kontainer se CPU-gebruik beheer. Dit het 'n verstekwaarde van 1024 en 'n reeks tussen 0 en 1024. As drie Kontainers dieselfde CPU-aandeel van 1024 het, kan elke Kontainer tot 33% van die CPU neem in geval van CPU-hulpbronkonflik. blkio-weight is 'n verhouding wat Kontainer se IO beheer. Dit het 'n verstekwaarde van 500 en 'n reeks tussen 10 en 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Om die cgroup van 'n houer te kry, kan jy die volgende doen:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Vir meer inligting, kyk na:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Bevoegdhede

Bevoegdhede maak dit moontlik om **fyn beheer oor die bevoegdhede wat toegelaat kan word** vir die root-gebruiker te hê. Docker maak gebruik van die Linux-kernel se bevoegdheidseienskapfunksie om **die operasies wat binne 'n houer gedoen kan word te beperk**, ongeag die tipe gebruiker.

Wanneer 'n Docker-houer uitgevoer word, **verloor die proses sensitiewe bevoegdhede wat die proses kan gebruik om uit die isolasie te ontsnap**. Dit probeer verseker dat die proses nie sensitiewe aksies kan uitvoer en ontsnap nie:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

Dit is 'n sekuriteitskenmerk wat Docker in staat stel om **die syscalls wat binne die houer gebruik kan word te beperk**:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

**AppArmor** is 'n kernel-verbetering om **houers** tot 'n **beperkte** stel **hulpbronne** met **per-program profiele** te beperk:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

- **Etiketteringstelsel**: SELinux ken 'n unieke etiket toe aan elke proses en lêerstelselobjek.
- **Beleidshandhawing**: Dit dwing sekuriteitsbeleide af wat bepaal watter aksies 'n prosesetiket binne die stelsel op ander etikette kan uitvoer.
- **Houerprosesetikette**: Wanneer houermotors houerprosesse inisieer, word hulle gewoonlik toegewys aan 'n beperkte SELinux-etiket, gewoonlik `container_t`.
- **Lêeretikettering binne houers**: Lêers binne die houer word gewoonlik geëtiketteer as `container_file_t`.
- **Beleidsreëls**: Die SELinux-beleid verseker hoofsaaklik dat prosesse met die `container_t`-etiket slegs kan interaksie hê (lees, skryf, uitvoer) met lêers wat geëtiketteer is as `container_file_t`.

Hierdie meganisme verseker dat selfs as 'n proses binne 'n houer gekompromitteer word, dit beperk is tot interaksie slegs met objekte wat die ooreenstemmende etikette het, wat die potensiële skade van sulke kompromitterings aansienlik beperk.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker speel 'n outorisasie-inprop 'n belangrike rol in sekuriteit deur te besluit of versoek aan die Docker-daemon toegelaat of geblokkeer moet word. Hierdie besluit word geneem deur twee sleutelkontekste te ondersoek:

- **Outentiseringskonteks**: Dit sluit omvattende inligting oor die gebruiker in, soos wie hulle is en hoe hulle hulself geoutentiseer het.
- **Opdragkonteks**: Dit bestaan uit alle relevante data wat verband hou met die gedane versoek.

Hierdie kontekste help verseker dat slegs legitieme versoek van geoutentiseerde gebruikers verwerk word, wat die sekuriteit van Docker-operasies verbeter.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS vanuit 'n houer

As jy nie die hulpbronne wat 'n houer kan gebruik behoorlik beperk nie, kan 'n gekompromitteerde houer die gasheer waarop dit uitgevoer word, DoS (versteurings van diens) gee.

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
## Interessante Docker-vlae

### --privileged-vlag

Op die volgende bladsy kan jy leer **wat impliseer die `--privileged`-vlag**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

As jy 'n houer hardloop waar 'n aanvaller toegang kry as 'n gebruiker met lae bevoegdhede. As jy 'n **verkeerd gekonfigureerde suid-binêre lêer** het, kan die aanvaller dit misbruik en **bevoegdhede binne die houer verhoog**. Dit kan hom in staat stel om daaruit te ontsnap.

Deur die houer met die **`no-new-privileges`**-opsie geaktiveer te hardloop, sal dit **hierdie soort bevoegdheidsverhoging voorkom**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Ander

---

### Docker Security

### Docker Sekuriteit

---

#### Docker Security Cheat Sheet

#### Docker Sekuriteit Spiekbriefie

---

#### Docker Security Best Practices

#### Docker Sekuriteit Beste Praktyke

---

#### Docker Security Tools

#### Docker Sekuriteit Gereedskap

---

#### Docker Security Vulnerabilities

#### Docker Sekuriteit Swakhede

---

#### Docker Security Resources

#### Docker Sekuriteit Hulpbronne

---

#### Docker Security Checklist

#### Docker Sekuriteit Kontrolelys

---

#### Docker Security Tips

#### Docker Sekuriteit Wenke

---

#### Docker Security Hardening

#### Docker Sekuriteit Verharding

---

#### Docker Security Auditing

#### Docker Sekuriteit Oudit

---

#### Docker Security Incident Response

#### Docker Sekuriteit Insident Reaksie

---

#### Docker Security Monitoring

#### Docker Sekuriteit Monitering

---

#### Docker Security Training

#### Docker Sekuriteit Opleiding

---

#### Docker Security Challenges

#### Docker Sekuriteit Uitdagings

---

#### Docker Security Best Practices for Developers

#### Docker Sekuriteit Beste Praktyke vir Ontwikkelaars

---

#### Docker Security Best Practices for Operations

#### Docker Sekuriteit Beste Praktyke vir Operasies

---

#### Docker Security Best Practices for DevOps

#### Docker Sekuriteit Beste Praktyke vir DevOps

---

#### Docker Security Best Practices for CI/CD

#### Docker Sekuriteit Beste Praktyke vir CI/CD

---

#### Docker Security Best Practices for Kubernetes

#### Docker Sekuriteit Beste Praktyke vir Kubernetes

---

#### Docker Security Best Practices for AWS

#### Docker Sekuriteit Beste Praktyke vir AWS

---

#### Docker Security Best Practices for Azure

#### Docker Sekuriteit Beste Praktyke vir Azure

---

#### Docker Security Best Practices for GCP

#### Docker Sekuriteit Beste Praktyke vir GCP

---

#### Docker Security Best Practices for DigitalOcean

#### Docker Sekuriteit Beste Praktyke vir DigitalOcean

---

#### Docker Security Best Practices for Alibaba Cloud

#### Docker Sekuriteit Beste Praktyke vir Alibaba Cloud

---

#### Docker Security Best Practices for IBM Cloud

#### Docker Sekuriteit Beste Praktyke vir IBM Cloud

---

#### Docker Security Best Practices for Oracle Cloud

#### Docker Sekuriteit Beste Praktyke vir Oracle Cloud

---

#### Docker Security Best Practices for Heroku

#### Docker Sekuriteit Beste Praktyke vir Heroku

---

#### Docker Security Best Practices for OpenShift

#### Docker Sekuriteit Beste Praktyke vir OpenShift

---

#### Docker Security Best Practices for Rancher

#### Docker Sekuriteit Beste Praktyke vir Rancher

---

#### Docker Security Best Practices for Nomad

#### Docker Sekuriteit Beste Praktyke vir Nomad

---

#### Docker Security Best Practices for Jenkins

#### Docker Sekuriteit Beste Praktyke vir Jenkins

---

#### Docker Security Best Practices for GitLab

#### Docker Sekuriteit Beste Praktyke vir GitLab

---

#### Docker Security Best Practices for Bitbucket

#### Docker Sekuriteit Beste Praktyke vir Bitbucket

---

#### Docker Security Best Practices for CircleCI

#### Docker Sekuriteit Beste Praktyke vir CircleCI

---

#### Docker Security Best Practices for Travis CI

#### Docker Sekuriteit Beste Praktyke vir Travis CI

---

#### Docker Security Best Practices for GitHub Actions

#### Docker Sekuriteit Beste Praktyke vir GitHub Actions

---

#### Docker Security Best Practices for Jenkins X

#### Docker Sekuriteit Beste Praktyke vir Jenkins X

---

#### Docker Security Best Practices for Spinnaker

#### Docker Sekuriteit Beste Praktyke vir Spinnaker

---

#### Docker Security Best Practices for TeamCity

#### Docker Sekuriteit Beste Praktyke vir TeamCity

---

#### Docker Security Best Practices for Bamboo

#### Docker Sekuriteit Beste Praktyke vir Bamboo

---

#### Docker Security Best Practices for GoCD

#### Docker Sekuriteit Beste Praktyke vir GoCD

---

#### Docker Security Best Practices for Drone

#### Docker Sekuriteit Beste Praktyke vir Drone

---

#### Docker Security Best Practices for Argo CD

#### Docker Sekuriteit Beste Praktyke vir Argo CD

---

#### Docker Security Best Practices for Harbor

#### Docker Sekuriteit Beste Praktyke vir Harbor

---

#### Docker Security Best Practices for Artifactory

#### Docker Sekuriteit Beste Praktyke vir Artifactory

---

#### Docker Security Best Practices for Nexus

#### Docker Sekuriteit Beste Praktyke vir Nexus

---

#### Docker Security Best Practices for Sonatype

#### Docker Sekuriteit Beste Praktyke vir Sonatype

---

#### Docker Security Best Practices for JFrog

#### Docker Sekuriteit Beste Praktyke vir JFrog

---

#### Docker Security Best Practices for Docker Hub

#### Docker Sekuriteit Beste Praktyke vir Docker Hub

---

#### Docker Security Best Practices for Quay

#### Docker Sekuriteit Beste Praktyke vir Quay

---

#### Docker Security Best Practices for Container Registry

#### Docker Sekuriteit Beste Praktyke vir Houderversameling

---

#### Docker Security Best Practices for Container Runtime

#### Docker Sekuriteit Beste Praktyke vir Houvertyd

---

#### Docker Security Best Practices for Container Orchestration

#### Docker Sekuriteit Beste Praktyke vir Houverorkestrering

---

#### Docker Security Best Practices for Container Networking

#### Docker Sekuriteit Beste Praktyke vir Houvernetwerking

---

#### Docker Security Best Practices for Container Storage

#### Docker Sekuriteit Beste Praktyke vir Houverstoor

---

#### Docker Security Best Practices for Container Monitoring

#### Docker Sekuriteit Beste Praktyke vir Houvermonitering

---

#### Docker Security Best Practices for Container Logging

#### Docker Sekuriteit Beste Praktyke vir Houverlog

---

#### Docker Security Best Practices for Container Tracing

#### Docker Sekuriteit Beste Praktyke vir Houvernaspeuring

---

#### Docker Security Best Practices for Container Vulnerability Scanning

#### Docker Sekuriteit Beste Praktyke vir Houverkwesbaarheidsskandering

---

#### Docker Security Best Practices for Container Image Scanning

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldskandering

---

#### Docker Security Best Practices for Container Image Signing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldondertekening

---

#### Docker Security Best Practices for Container Image Hardening

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldverharding

---

#### Docker Security Best Practices for Container Image Lifecycle Management

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldlewenssiklusbestuur

---

#### Docker Security Best Practices for Container Image Registry

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldregister

---

#### Docker Security Best Practices for Container Image Repository

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldbewaarplek

---

#### Docker Security Best Practices for Container Image Distribution

#### Docker Sekuriteit Beste Praktyke vir Houverbeelddistribusie

---

#### Docker Security Best Practices for Container Image Updates

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldopdaterings

---

#### Docker Security Best Practices for Container Image Versioning

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldweergawes

---

#### Docker Security Best Practices for Container Image Tagging

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldmerking

---

#### Docker Security Best Practices for Container Image Pulling

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldtrekking

---

#### Docker Security Best Practices for Container Image Pushing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldstoot

---

#### Docker Security Best Practices for Container Image Building

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldbou

---

#### Docker Security Best Practices for Container Image Packaging

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldverpakking

---

#### Docker Security Best Practices for Container Image Distribution

#### Docker Sekuriteit Beste Praktyke vir Houverbeelddistribusie

---

#### Docker Security Best Practices for Container Image Validation

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldgeldigheid

---

#### Docker Security Best Practices for Container Image Verification

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldverifikasie

---

#### Docker Security Best Practices for Container Image Deployment

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldimplementering

---

#### Docker Security Best Practices for Container Image Rollback

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldterugrol

---

#### Docker Security Best Practices for Container Image Cleanup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldopruiming

---

#### Docker Security Best Practices for Container Image Backup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldrugsteun

---

#### Docker Security Best Practices for Container Image Restore

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldherstel

---

#### Docker Security Best Practices for Container Image Migration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldmigrasie

---

#### Docker Security Best Practices for Container Image Replication

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldverdubbeling

---

#### Docker Security Best Practices for Container Image Scaling

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldskaling

---

#### Docker Security Best Practices for Container Image Load Balancing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldlasbalansering

---

#### Docker Security Best Practices for Container Image High Availability

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldhoë beskikbaarheid

---

#### Docker Security Best Practices for Container Image Fault Tolerance

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldfouttoleransie

---

#### Docker Security Best Practices for Container Image Disaster Recovery

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldrampherstel

---

#### Docker Security Best Practices for Container Image Auto Scaling

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese skaling

---

#### Docker Security Best Practices for Container Image Auto Healing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese genesing

---

#### Docker Security Best Practices for Container Image Auto Repair

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese herstel

---

#### Docker Security Best Practices for Container Image Auto Update

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese opdatering

---

#### Docker Security Best Practices for Container Image Auto Backup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rugsteun

---

#### Docker Security Best Practices for Container Image Auto Restore

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese herstel

---

#### Docker Security Best Practices for Container Image Auto Migration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese migrasie

---

#### Docker Security Best Practices for Container Image Auto Replication

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese verdubbeling

---

#### Docker Security Best Practices for Container Image Auto Scaling

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese skaling

---

#### Docker Security Best Practices for Container Image Auto Load Balancing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese lasbalansering

---

#### Docker Security Best Practices for Container Image Auto High Availability

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese hoë beskikbaarheid

---

#### Docker Security Best Practices for Container Image Auto Fault Tolerance

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese fouttoleransie

---

#### Docker Security Best Practices for Container Image Auto Disaster Recovery

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rampherstel

---

#### Docker Security Best Practices for Container Image Auto Orchestration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese orkestrering

---

#### Docker Security Best Practices for Container Image Auto Provisioning

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese voorsiening

---

#### Docker Security Best Practices for Container Image Auto Configuration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese konfigurasie

---

#### Docker Security Best Practices for Container Image Auto Deployment

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese implementering

---

#### Docker Security Best Practices for Container Image Auto Rollback

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese terugrol

---

#### Docker Security Best Practices for Container Image Auto Cleanup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese opruiming

---

#### Docker Security Best Practices for Container Image Auto Backup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rugsteun

---

#### Docker Security Best Practices for Container Image Auto Restore

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese herstel

---

#### Docker Security Best Practices for Container Image Auto Migration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese migrasie

---

#### Docker Security Best Practices for Container Image Auto Replication

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese verdubbeling

---

#### Docker Security Best Practices for Container Image Auto Scaling

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese skaling

---

#### Docker Security Best Practices for Container Image Auto Load Balancing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese lasbalansering

---

#### Docker Security Best Practices for Container Image Auto High Availability

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese hoë beskikbaarheid

---

#### Docker Security Best Practices for Container Image Auto Fault Tolerance

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese fouttoleransie

---

#### Docker Security Best Practices for Container Image Auto Disaster Recovery

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rampherstel

---

#### Docker Security Best Practices for Container Image Auto Orchestration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese orkestrering

---

#### Docker Security Best Practices for Container Image Auto Provisioning

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese voorsiening

---

#### Docker Security Best Practices for Container Image Auto Configuration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese konfigurasie

---

#### Docker Security Best Practices for Container Image Auto Deployment

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese implementering

---

#### Docker Security Best Practices for Container Image Auto Rollback

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese terugrol

---

#### Docker Security Best Practices for Container Image Auto Cleanup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese opruiming

---

#### Docker Security Best Practices for Container Image Auto Backup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rugsteun

---

#### Docker Security Best Practices for Container Image Auto Restore

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese herstel

---

#### Docker Security Best Practices for Container Image Auto Migration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese migrasie

---

#### Docker Security Best Practices for Container Image Auto Replication

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese verdubbeling

---

#### Docker Security Best Practices for Container Image Auto Scaling

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese skaling

---

#### Docker Security Best Practices for Container Image Auto Load Balancing

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese lasbalansering

---

#### Docker Security Best Practices for Container Image Auto High Availability

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese hoë beskikbaarheid

---

#### Docker Security Best Practices for Container Image Auto Fault Tolerance

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese fouttoleransie

---

#### Docker Security Best Practices for Container Image Auto Disaster Recovery

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rampherstel

---

#### Docker Security Best Practices for Container Image Auto Orchestration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese orkestrering

---

#### Docker Security Best Practices for Container Image Auto Provisioning

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese voorsiening

---

#### Docker Security Best Practices for Container Image Auto Configuration

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese konfigurasie

---

#### Docker Security Best Practices for Container Image Auto Deployment

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese implementering

---

#### Docker Security Best Practices for Container Image Auto Rollback

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese terugrol

---

#### Docker Security Best Practices for Container Image Auto Cleanup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese opruiming

---

#### Docker Security Best Practices for Container Image Auto Backup

#### Docker Sekuriteit Beste Praktyke vir Houverbeeldoutomatiese rugsteun

---

#### Docker Security Best Practices for Container Image Auto Restore

#### Docker Sekuriteit Beste Praktyke
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
Vir meer **`--security-opt`** opsies, kyk na: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Ander Sekuriteits-oorwegings

### Bestuur van Geheime: Beste Praktyke

Dit is noodsaaklik om te vermy dat geheime direk in Docker-beelde ingebed word of dat omgewingsveranderlikes gebruik word, aangesien hierdie metodes jou sensitiewe inligting blootstel aan enige persoon met toegang tot die houer deur bevele soos `docker inspect` of `exec`.

**Docker volumes** is 'n veiliger alternatief wat aanbeveel word vir die toegang tot sensitiewe inligting. Dit kan gebruik word as 'n tydelike lêersisteem in die geheue, wat die risiko's wat verband hou met `docker inspect` en logboekinskrywings verminder. Nietemin kan root-gebruikers en diegene met `exec`-toegang tot die houer steeds toegang verkry tot die geheime.

**Docker geheime** bied 'n selfs veiliger metode vir die hantering van sensitiewe inligting. Vir gevalle waar geheime tydens die beeldboufase benodig word, bied **BuildKit** 'n doeltreffende oplossing met ondersteuning vir geheime tydens die boufase, wat die bou spoed verbeter en addisionele funksies bied.

Om BuildKit te benut, kan dit op drie maniere geaktiveer word:

1. Deur 'n omgewingsveranderlike: `export DOCKER_BUILDKIT=1`
2. Deur bevele te voorvoeg: `DOCKER_BUILDKIT=1 docker build .`
3. Deur dit standaard in die Docker-konfigurasie te aktiveer: `{ "features": { "buildkit": true } }`, gevolg deur 'n herlaai van Docker.

BuildKit maak die gebruik van geheime tydens die boufase moontlik met die `--secret` opsie, wat verseker dat hierdie geheime nie ingesluit word in die beeldboukas of die finale beeld nie, deur 'n bevel soos die volgende te gebruik:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Vir geheime wat nodig is in 'n lopende houer, bied **Docker Compose en Kubernetes** robuuste oplossings. Docker Compose maak gebruik van 'n `secrets` sleutel in die diensdefinisie om geheime lêers te spesifiseer, soos getoon in 'n voorbeeld van 'n `docker-compose.yml`:

```yaml
services:
  myservice:
    secrets:
      - mysecret
secrets:
  mysecret:
    file: ./path/to/secret/file
```

In hierdie voorbeeld word 'n diens genaamd `myservice` gedefinieer wat 'n geheim genaamd `mysecret` gebruik. Die geheime lêer word gespesifiseer deur die `file` sleutel in die `secrets` afdeling.
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
Hierdie konfigurasie maak die gebruik van geheime moontlik wanneer dienste met Docker Compose begin word.

In Kubernetes-omgewings word geheime outomaties ondersteun en kan dit verder bestuur word met gereedskap soos [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Kubernetes se Rol Gebaseerde Toegangsbeheer (RBAC) verbeter die veiligheid van geheimbestuur, soortgelyk aan Docker Enterprise.

### gVisor

**gVisor** is 'n toepassingskernel, geskryf in Go, wat 'n groot gedeelte van die Linux-stelseloppervlak implementeer. Dit sluit 'n [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime genaamd `runsc` in wat 'n **isolasiegrens tussen die toepassing en die gasheerkernel** voorsien. Die `runsc` runtime integreer met Docker en Kubernetes, wat dit eenvoudig maak om gesandbokte houers te hardloop.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** is 'n oopbron-gemeenskap wat werk aan die bou van 'n veilige houer-runtime met ligte virtuele masjiene wat soos houers voel en optree, maar **sterker werklas-isolasie bied deur middel van hardeware-virtualisering** as 'n tweede verdedigingslaag.

{% embed url="https://katacontainers.io/" %}

### Opsomming van Wenke

* **Moenie die `--privileged` vlag gebruik of 'n** [**Docker-aansluiting binne die houer monteer**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Die Docker-aansluiting maak dit moontlik om houers te skep, dus is dit 'n maklike manier om volle beheer oor die gasheer te verkry, byvoorbeeld deur 'n ander houer met die `--privileged` vlag te hardloop.
* Moenie **as root binne die houer hardloop nie. Gebruik 'n** [**ander gebruiker**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **en** [**gebruikersnaamruimtes**](https://docs.docker.com/engine/security/userns-remap/)**.** Die root in die houer is dieselfde as op die gasheer tensy dit met gebruikersnaamruimtes herkartografeer word. Dit word slegs lig beperk deur Linux-naamruimtes, vermoëns en cgroups.
* [**Laat alle vermoëns vaar**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) en aktiveer slegs dié wat benodig word** (`--cap-add=...`). Baie werklaste benodig geen vermoëns nie en die byvoeging daarvan verhoog die omvang van 'n potensiële aanval.
* [**Gebruik die "no-new-privileges" veiligheidsoptie**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) om te voorkom dat prosesse meer vermoëns bekom, byvoorbeeld deur suid-binêre lêers.
* [**Beperk die hulpbronne wat beskikbaar is vir die houer**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Hulpbronbeperkings kan die masjien teen ontkenning-van-diens-aanvalle beskerm.
* **Pas** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(of SELinux)** profiele aan om die aksies en stelseloproepe wat vir die houer beskikbaar is, tot die minimum wat benodig word, te beperk.
* **Gebruik** [**amptelike Docker-beelde**](https://docs.docker.com/docker-hub/official\_images/) **en vereis handtekeninge** of bou jou eie beelde gebaseer daarop. Moenie beelde erf of gebruik wat [agterdeure](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) bevat nie. Berg ook wortelsleutels en wagwoord op 'n veilige plek op. Docker het planne om sleutels met UCP te bestuur.
* **Herbou jou beelde gereeld** om sekuriteitsopdaterings op die gasheer en beelde toe te pas.
* Bestuur jou **geheime verstandig** sodat dit moeilik is vir die aanvaller om toegang daartoe te verkry.
* As jy die Docker-daeemon blootstel, gebruik **HTTPS** met klient- en bedienerverifikasie.
* In jou Dockerfile, **gee voorkeur aan KOPIËRE in plaas van TOEVOEGEN**. TOEVOEGEN onttrek outomaties saamgepersde lêers en kan lêers vanaf URL's kopieer. KOPIËRE het nie hierdie vermoëns nie. Vermy waar moontlik die gebruik van TOEVOEGEN sodat jy nie vatbaar is vir aanvalle deur middel van afgeleë URL's en Zip-lêers nie.
* Het **afsonderlike houers vir elke mikrodiens**
* **Moenie ssh** binne die houer plaas nie, "docker exec" kan gebruik word om na die houer ssh.
* Het **kleiner** houerbeelde

## Docker Uitbreek / Voorregverhoging

As jy **binne 'n Docker-houer** is of toegang het tot 'n gebruiker in die **docker-groep**, kan jy probeer om **uit te breek en voorregte te verhoog**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker-verifikasieplugin-omseil

As jy toegang het tot die Docker-aansluiting of toegang het tot 'n gebruiker in die **docker-groep, maar jou aksies word beperk deur 'n Docker-verifikasieplugin**, kyk of jy dit kan **omseil:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Verharding van Docker

* Die gereedskap [**docker-bench-security**](https://github.com/docker/docker-bench-security) is 'n skrip wat tientalle algemene beste praktyke vir die implementering van Docker-houers in produksie nagaan. Die toetse is outomaties en is gebaseer op die [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Jy moet die gereedskap vanaf die gasheer wat Docker hardloop, of vanaf 'n houer met genoeg voorregte, hardloop. Vind **hoe om dit in die README te hardloop:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Verwysings

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container
Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
