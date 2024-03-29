# Usalama wa Docker

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa urahisi ikiwa na zana za **jamii za hali ya juu zaidi**.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Usalama wa Msingi wa Docker Engine**

**Docker engine** hutumia **Namespaces** na **Cgroups** ya kernel ya Linux kuisolate kontena, kutoa safu ya msingi ya usalama. Kinga zaidi hutolewa kupitia **Capabilities dropping**, **Seccomp**, na **SELinux/AppArmor**, ikiboresha kuisolishwa kwa kontena. **Plugin ya uthibitishaji** inaweza kuzuia vitendo vya mtumiaji zaidi.

![Usalama wa Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Upatikanaji Salama wa Docker Engine

Docker engine inaweza kupatikana kimtandao kupitia soketi ya Unix au kijijini kwa kutumia HTTP. Kwa upatikanaji wa kijijini, ni muhimu kutumia HTTPS na **TLS** kuhakikisha usiri, uadilifu, na uthibitisho.

Docker engine, kwa chaguo-msingi, husikiliza kwenye soketi ya Unix kwa `unix:///var/run/docker.sock`. Kwenye mifumo ya Ubuntu, chaguzi za kuanzisha Docker zinapatikana katika `/etc/default/docker`. Ili kuwezesha upatikanaji wa kijijini kwa API na mteja wa Docker, funua daemani ya Docker kupitia soketi ya HTTP kwa kuongeza mipangilio ifuatayo:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Hata hivyo, kufunua Docker daemon kupitia HTTP sio jambo linalopendekezwa kutokana na wasiwasi wa usalama. Ni vyema kusimamia uhusiano kwa kutumia HTTPS. Kuna njia mbili kuu za kusimamia uhusiano:

1. Mteja anathibitisha utambulisho wa seva.
2. Mteja na seva wanathibitisha utambulisho wao kwa kila mmoja.

Vyeti hutumiwa kuthibitisha utambulisho wa seva. Kwa mifano kamili ya njia zote mbili, tazama [**mwongozo huu**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Usalama wa Picha za Kontena

Picha za kontena zinaweza kuhifadhiwa kwenye hifadhi za kibinafsi au za umma. Docker inatoa chaguzi kadhaa za kuhifadhi picha za kontena:

* [**Docker Hub**](https://hub.docker.com): Huduma ya usajili wa umma kutoka Docker.
* [**Docker Registry**](https://github.com/docker/distribution): Mradi wa chanzo wazi unaoruhusu watumiaji kuhifadhi usajili wao wenyewe.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Usajili wa biashara wa Docker, ukiwa na uthibitishaji wa mtumiaji kulingana na jukumu na ushirikiano na huduma za saraka za LDAP.

### Uchunguzi wa Picha

Makontena yanaweza kuwa na **mapungufu ya usalama** kutokana na picha ya msingi au programu iliyosanikishwa juu ya picha ya msingi. Docker inafanya kazi kwenye mradi unaoitwa **Nautilus** ambao hufanya uchunguzi wa usalama wa Makontena na kuorodhesha mapungufu. Nautilus hufanya kazi kwa kulinganisha kila safu ya picha ya Kontena na hifadhi ya mapungufu ili kutambua mapengo ya usalama.

Kwa [**mashauri zaidi soma hii**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Amri ya **`docker scan`** inaruhusu uchunguzi wa picha za Docker zilizopo kwa kutumia jina au ID ya picha. Kwa mfano, endesha amri ifuatayo kuchunguza picha ya hello-world:
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
### Kusaini Picha za Docker

Kusaini picha za Docker hutoa uhakika na usahihi wa picha zinazotumiwa kwenye makontena. Hapa kuna maelezo mafupi:

- **Uaminifu wa Yaliyomo ya Docker** hutumia mradi wa Notary, uliojengwa kwenye The Update Framework (TUF), kusimamia usaini wa picha. Kwa maelezo zaidi, angalia [Notary](https://github.com/docker/notary) na [TUF](https://theupdateframework.github.io).
- Ili kuamsha uaminifu wa yaliyomo ya Docker, weka `export DOCKER_CONTENT_TRUST=1`. Kipengele hiki kimezimwa kwa chaguo-msingi kwenye Docker toleo 1.10 na baadaye.
- Kwa kipengele hiki kimezimwa, picha zilizosainiwa pekee ndizo zinaweza kupakuliwa. Kusukuma picha ya kwanza kunahitaji kuweka nywila za msingi na ufunguo wa alama, na Docker pia inaunga mkono Yubikey kwa usalama ulioboreshwa. Maelezo zaidi yanaweza kupatikana [hapa](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Kujaribu kupakua picha isiyosainiwa na uaminifu wa yaliyomo umewezeshwa husababisha kosa la "Hakuna data ya uaminifu kwa toleo la karibuni".
- Kwa kusukuma picha baada ya ya kwanza, Docker inauliza nywila ya ufunguo wa hifadhi ili kusaini picha.

Ili kuhifadhi nakala za kibinafsi za ufunguo wako, tumia amri:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Wakati wa kubadili wenyeji wa Docker, ni muhimu kuhamisha funguo za msingi na za hazina ili kudumisha shughuli.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mifumo ya kazi inayotumia zana za jamii za **juu kabisa** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vipengele vya Usalama wa Kontena

<details>

<summary>Maelezo ya Vipengele vya Usalama wa Kontena</summary>

**Vipengele Kuu vya Kufungwa kwa Mchakato**

Katika mazingira ya kontena, kufunga miradi na michakato yake ni muhimu kwa usalama na usimamizi wa rasilimali. Hapa kuna maelezo rahisi ya dhana muhimu:

**Namespaces**

* **Lengo**: Kuhakikisha kufungwa kwa rasilimali kama michakato, mtandao, na mfumo wa faili. Hasa katika Docker, namespaces huzuia michakato ya kontena kutoka kwa mwenyeji na kontena nyingine.
* **Matumizi ya `unshare`**: Amri ya `unshare` (au syscall inayofanana) hutumiwa kuunda namespaces mpya, kutoa safu ya ziada ya kufungwa. Hata hivyo, ingawa Kubernetes haizuili hili kwa asili, Docker inafanya.
* **Kizuizi**: Kuunda namespaces mpya haimruhusu mchakato kurejea kwa namespaces za msingi za mwenyeji. Kwa kawaida, ili kuingia kwenye namespaces za mwenyeji, mtu atahitaji ufikiaji wa saraka ya `/proc` ya mwenyeji, kutumia `nsenter` kwa kuingia.

**Vikundi vya Kudhibiti (CGroups)**

* **Kazi**: Hasa hutumiwa kwa kugawa rasilimali kati ya michakato.
* **Upande wa Usalama**: CGroups wenyewe hawatoi usalama wa kufungwa, isipokuwa kwa kipengele cha `release_agent`, ambacho, ikiwa hakijasakinishwa vizuri, kinaweza kutumiwa vibaya kwa ufikiaji usiohalali.

**Kupunguza Uwezo (Capability Drop)**

* **Umuhimu**: Ni kipengele muhimu cha usalama kwa kufunga michakato.
* **Utendaji**: Inazuia vitendo ambavyo mchakato wa msingi unaweza kufanya kwa kupunguza uwezo fulani. Hata kama mchakato unakimbia na mamlaka ya msingi, kukosa uwezo muhimu kunazuia utekelezaji wa vitendo vya mamlaka, kwani syscall zitashindwa kutokana na idhini duni.

Hizi ni **uwezo uliobaki** baada ya mchakato kupunguza wengine:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Imewezeshwa kwa chaguo-msingi kwenye Docker. Inasaidia **kupunguza zaidi wito wa syscalls** ambao mchakato unaweza kuita.\
**Profaili ya Seccomp ya chaguo-msingi ya Docker** inaweza kupatikana kwenye [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ina kiolesura ambacho unaweza kuamsha: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Hii itaruhusu kupunguza uwezo, syscalls, ufikiaji wa faili na folda...

</details>

### Namespaces

**Namespaces** ni kipengele cha kernel ya Linux ambacho **kinagawa rasilimali za kernel** hivi kwamba seti moja ya **mchakato** **inaona** seti moja ya **rasilimali** wakati **seti nyingine** ya **mchakato** inaona **seti tofauti** ya rasilimali. Kipengele hufanya kazi kwa kuwa na namespace ile ile kwa seti ya rasilimali na michakato, lakini hizo namespaces zinahusiana na rasilimali tofauti. Rasilimali inaweza kuwepo katika nafasi nyingi.

Docker hutumia Namespaces za kernel ya Linux zifuatazo kufikia kizuizi cha Kontena:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

Kwa **mashauri zaidi kuhusu namespaces** angalia ukurasa ufuatao:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Kipengele cha kernel ya Linux **cgroups** hutoa uwezo wa **kizuia rasilimali kama cpu, kumbukumbu, io, upana wa mtandao miongoni** mwa seti ya michakato. Docker inaruhusu kuunda Kontena kwa kutumia kipengele cha cgroup ambacho kinaruhusu kudhibiti rasilimali kwa Kontena maalum.\
Hapa chini ni Kontena iliyoundwa na kikomo cha kumbukumbu ya nafasi ya mtumiaji hadi 500m, kumbukumbu ya nafasi ya kernel hadi 50m, mgawo wa cpu hadi 512, blkioweight hadi 400. Mgawo wa CPU ni uwiano unaodhibiti matumizi ya CPU ya Kontena. Ina thamani ya chaguo-msingi ya 1024 na inaenea kati ya 0 na 1024. Ikiwa Kontena tatu zina mgawo sawa wa CPU wa 1024, kila Kontena inaweza kuchukua hadi 33% ya CPU katika kesi ya mgongano wa rasilimali ya CPU. blkio-weight ni uwiano unaodhibiti IO ya Kontena. Ina thamani ya chaguo-msingi ya 500 na inaenea kati ya 10 na 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Ili kupata cgroup ya kontena unaweza kufanya:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Kwa maelezo zaidi angalia:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Uwezo

Uwezo huruhusu **udhibiti mzuri wa uwezo unaoweza kuruhusiwa** kwa mtumiaji wa mizizi. Docker hutumia kipengele cha uwezo cha kernel ya Linux ili **izuie operesheni zinazoweza kufanywa ndani ya Kontena** bila kujali aina ya mtumiaji.

Wakati kontena ya docker inapoendeshwa, **mchakato hupunguza uwezo wenye hisia ambao mchakato unaweza kutumia kutoroka kutoka kwa kizuizi**. Hii inajaribu kuhakikisha kuwa mchakato hautaweza kutekeleza vitendo vyenye hisia na kutoroka:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp katika Docker

Hii ni kipengele cha usalama kinachoruhusu Docker **izuie syscalls** zinazoweza kutumika ndani ya kontena:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor katika Docker

**AppArmor** ni nyongeza ya kernel ya kizuizi **kizuia kontena** kwa seti **ndogo** ya **rasilimali** na **mipangilio ya programu**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux katika Docker

* **Mfumo wa Lebo**: SELinux inaainisha lebo ya kipekee kwa kila mchakato na kila kitu cha mfumo wa faili.
* **Utekelezaji wa Sera**: Inatekeleza sera za usalama ambazo hufafanua vitendo gani lebo ya mchakato inaweza kutekeleza kwenye lebo zingine ndani ya mfumo.
* **Lebo za Mchakato wa Kontena**: Wakati injini za kontena zinaanzisha michakato ya kontena, kawaida hupewa lebo iliyozuiwa ya SELinux, mara nyingi `container_t`.
* **Uainishaji wa Faili ndani ya Kontena**: Faili ndani ya kontena kawaida huwa na lebo kama `container_file_t`.
* **Sera za Sera**: Sera ya SELinux kimsingi inahakikisha kuwa michakato yenye lebo ya `container_t` inaweza kuingiliana (kusoma, kuandika, kutekeleza) tu na faili zilizopewa lebo kama `container_file_t`.

Mfumo huu unahakikisha kuwa hata kama mchakato ndani ya kontena unashambuliwa, umefungwa kuingiliana tu na vitu vilivyo na lebo zinazofanana, ikipunguza uharibifu unaoweza kutokea kutokana na mashambulizi kama hayo.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Katika Docker, programu ya idhini inacheza jukumu muhimu katika usalama kwa kuamua ikiwa itaruhusu au kuzuia maombi kwa daemon ya Docker. Uamuzi huu hufanywa kwa kuchunguza muktadha wa muhimu:

* **Muktadha wa Uthibitishaji**: Hii inajumuisha habari kamili kuhusu mtumiaji, kama ni nani na jinsi walivyothibitishwa.
* **Muktadha wa Amri**: Hii inajumuisha data yote inayohusiana na ombi linalofanywa.

Muktadha huu husaidia kuhakikisha kuwa maombi halali kutoka kwa watumiaji waliothibitishwa tu ndio yanashughulikiwa, ikiboresha usalama wa operesheni za Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS kutoka kwa kontena

Ikiwa hauruhusu ipasavyo rasilimali ambazo kontena inaweza kutumia, kontena iliyoshambuliwa inaweza kufanya DoS kwenye mwenyeji ambapo inaendeshwa.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* **Bandwidth DoS**  
  Bandwidth DoS ni aina ya shambulio la Denial of Service ambapo mtumiaji anajaribu kutumia kiasi kikubwa cha bandwidth ya mtandao ili kusababisha kukosekana kwa huduma kwa watumiaji wengine.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Bendera za Kuvutia za Docker

### Bendera ya --privileged

Kwenye ukurasa ufuatao unaweza kujifunza **maana ya bendera ya `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Ikiwa unatekeleza kontena ambapo mkaidi anafanikiwa kupata ufikivu kama mtumiaji wa mamlaka ya chini. Ikiwa una **binary ya suid iliyopangiliwa vibaya**, mkaidi anaweza kuitumia na **kupandisha mamlaka ndani** ya kontena. Hii, inaweza kumruhusu kutoroka kutoka humo.

Kutekeleza kontena na chaguo la **`no-new-privileges`** kuwezeshwa kutazuia **aina hii ya upandishaji mamlaka**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Nyingine
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
Kwa chaguo zaidi za **`--security-opt`** angalia: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Mambo Mengine ya Kuzingatia kuhusu Usalama

### Usimamizi wa Siri: Mbinu Bora

Ni muhimu kuepuka kuweka siri moja kwa moja kwenye picha za Docker au kutumia mazingira ya mazingira, kwani njia hizi zinaweka wazi habari zako nyeti kwa yeyote mwenye ufikiaji wa kontena kupitia amri kama vile `docker inspect` au `exec`.

**Vipimo vya Docker** ni mbadala salama, inapendekezwa kwa kupata habari nyeti. Wanaweza kutumika kama mfumo wa faili wa muda katika kumbukumbu, kupunguza hatari zinazohusiana na `docker inspect` na kuingia kwenye kumbukumbu. Walakini, watumiaji wa mizizi na wale wenye ufikiaji wa `exec` kwenye kontena wanaweza bado kupata siri.

**Siri za Docker** zinatoa njia salama zaidi ya kushughulikia habari nyeti. Kwa visa vinavyohitaji siri wakati wa hatua ya kujenga picha, **BuildKit** inatoa suluhisho lenye ufanisi na msaada kwa siri za wakati wa kujenga, kuboresha kasi ya ujenzi na kutoa huduma za ziada.

Ili kutumia BuildKit, inaweza kuamilishwa kwa njia tatu:

1. Kupitia mazingira ya mazingira: `export DOCKER_BUILDKIT=1`
2. Kwa kuongeza awali kwenye amri: `DOCKER_BUILDKIT=1 docker build .`
3. Kwa kuwezesha kwa chaguo-msingi katika usanidi wa Docker: `{ "vipengele": { "buildkit": kweli } }`, ikifuatiwa na kuanzisha upya kwa Docker.

BuildKit inaruhusu matumizi ya siri za wakati wa kujenga kwa chaguo la `--secret`, ikihakikisha siri hizi hazijumuishwi katika kache ya ujenzi wa picha au picha ya mwisho, kwa kutumia amri kama vile:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Kwa siri zinazohitajika katika kontena linaloendeshwa, **Docker Compose na Kubernetes** hutoa suluhisho imara. Docker Compose hutumia ufunguo wa `secrets` katika ufafanuzi wa huduma kwa kuelezea faili za siri, kama inavyoonyeshwa katika mfano wa `docker-compose.yml`:
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
Hii usanidi inaruhusu matumizi ya siri wakati wa kuanzisha huduma na Docker Compose.

Katika mazingira ya Kubernetes, siri zinasaidiwa kiasili na zinaweza kusimamiwa zaidi na zana kama [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Udhibiti wa Siri wa Kubernetes (RBAC) huimarisha usalama wa usimamizi wa siri, kama ilivyo kwa Docker Enterprise.

### gVisor

**gVisor** ni kiini cha programu, kilichoandikwa kwa Go, ambacho kinafuata sehemu kubwa ya uso wa mfumo wa Linux. Kina [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime kinachoitwa `runsc` ambacho hutoa **mpaka wa kujitenga kati ya programu na kiini cha mwenyeji**. Runtime ya `runsc` inashirikiana na Docker na Kubernetes, ikifanya iwe rahisi kuendesha kontena zilizofungwa.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** ni jumuiya ya chanzo wazi inayofanya kazi ya kujenga runtime salama wa kontena na mashine za kawaida zenye uzito ambazo hutoa **kujitenga kwa mzigo wenye nguvu kwa kutumia teknolojia ya kivirtuali kama safu ya pili ya ulinzi**.

{% embed url="https://katacontainers.io/" %}

### Vidokezo vya Muhtasari

* **Usitumie bendera ya `--privileged` au uweke soketi ya** [**Docker ndani ya kontena**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Soketi ya docker inaruhusu kuzalisha kontena, hivyo ni njia rahisi ya kuchukua udhibiti kamili wa mwenyeji, kwa mfano, kwa kuendesha kontena nyingine na bendera ya `--privileged`.
* Usiendeshe kama root ndani ya kontena. Tumia [mtumiaji tofauti](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) na [spazi za mtumiaji](https://docs.docker.com/engine/security/userns-remap/). Root ndani ya kontena ni sawa na kwenye mwenyeji isipokuwa imebadilishwa na spazi za mtumiaji. Inazuiliwa kidogo tu na, kimsingi, spazi za Linux, uwezo, na vikundi.
* [Tupa uwezo wote](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) na wezesha tu wale uliohitajika** (`--cap-add=...`). Mzigo mwingi hauhitaji uwezo wowote na kuongeza huongeza wigo wa shambulio la uwezekano.
* [Tumia chaguo la usalama la "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) kuzuia michakato kupata uwezo zaidi, kwa mfano kupitia programu za suid.
* [Zuia rasilimali zinazopatikana kwa kontena](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Vizuizi vya rasilimali vinaweza kulinda mashine kutokana na mashambulizi ya kukataa huduma.
* **Badilisha** [**seccomp**](https://docs.docker.com/engine/security/seccomp/), [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(au SELinux)** maelezo ya kikomo kuzuia hatua na syscalls zinazopatikana kwa kontena hadi kiwango cha chini kinachohitajika.
* **Tumia** [**picha rasmi za docker**](https://docs.docker.com/docker-hub/official_images/) **na hitaji saini** au jenga yako kulingana na hizo. Usirithi au kutumia picha zilizopitishwa. Pia hifadhi funguo za msingi, nywila mahali salama. Docker ina mipango ya kusimamia funguo na UCP.
* **Jenga upya mara kwa mara** picha zako ili **kuomba visasaisho vya usalama kwa mwenyeji na picha.**
* Simamia **siri zako kwa busara** ili iwe ngumu kwa mshambuliaji kuzipata.
* Ikiwa **unafunua kiini cha docker tumia HTTPS** na uthibitishaji wa mteja na mwenyeji.
* Katika Dockerfile yako, **pendekeza COPY badala ya ADD**. ADD inachambua faili zilizozipwa kiotomatiki na inaweza kunakili faili kutoka kwenye URL. COPY haina uwezo huu. Kadri inavyowezekana, epuka kutumia ADD ili usiwe katika hatari ya mashambulizi kupitia URL za mbali na faili za Zip.
* Kuwa na **kontena tofauti kwa kila huduma ndogo**
* **Usiweke ssh** ndani ya kontena, "docker exec" inaweza kutumika kuingia kwa ssh kwenye Kontena.
* Kuwa na **picha ndogo** za kontena

## Kuvunja / Kuongeza Mamlaka ya Docker

Ikiwa uko **ndani ya kontena la docker** au una ufikiaji kwa mtumiaji katika **kikundi cha docker**, unaweza kujaribu **kutoroka na kuongeza mamlaka**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Kupuuza Plugin ya Uthibitishaji wa Docker

Ikiwa una ufikiaji wa soketi ya docker au una ufikiaji kwa mtumiaji katika **kikundi cha docker lakini hatua zako zinazuiliwa na programu ya uthibitishaji wa docker**, angalia ikiwa unaweza **kuipuuza:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Kufanya Salama ya Docker

* Zana [**docker-bench-security**](https://github.com/docker/docker-bench-security) ni script inayochunguza mamia ya mazoea bora ya kawaida kuhusu kupeleka kontena za Docker kwa uzalishaji. Vipimo vyote ni vya kiotomatiki, na vimejengwa kwenye [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Unahitaji kuendesha zana kutoka kwa mwenyeji unaendesha docker au kutoka kwa kontena yenye mamlaka za kutosha. Pata **jinsi ya kuendesha katika README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Marejeo

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

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jumuiya za juu zaidi duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>
<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
