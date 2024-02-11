# Usalama wa Docker

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuendesha mchakato** kwa kutumia zana za jamii za **hali ya juu zaidi**.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Usalama wa Msingi wa Docker Engine**

**Docker engine** hutumia **Namespaces** na **Cgroups** ya kernel ya Linux kuweka kontena kwenye kizuizi, kutoa safu ya msingi ya usalama. Ulinzi zaidi unatolewa kupitia **Capabilities dropping**, **Seccomp**, na **SELinux/AppArmor**, kuimarisha kizuizi cha kontena. Plugin ya **uthibitishaji** inaweza kuzuia vitendo vya mtumiaji.

![Usalama wa Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Upatikanaji Salama wa Docker Engine

Docker engine inaweza kupatikana kwa njia ya soketi ya Unix kwa ndani au kijijini kwa kutumia HTTP. Kwa upatikanaji wa kijijini, ni muhimu kutumia HTTPS na **TLS** ili kuhakikisha usiri, uadilifu, na uthibitisho.

Docker engine, kwa chaguo-msingi, husikiliza soketi ya Unix kwenye `unix:///var/run/docker.sock`. Kwenye mifumo ya Ubuntu, chaguzi za kuanza za Docker zinapatikana katika `/etc/default/docker`. Ili kuwezesha upatikanaji wa kijijini kwa API na mteja wa Docker, weka mazingira yafuatayo:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Hata hivyo, kuweka wazi Docker daemon kupitia HTTP sio inapendekezwa kutokana na wasiwasi wa usalama. Ni vyema kusimamia uhusiano kwa kutumia HTTPS. Kuna njia mbili kuu za kusimamia uhusiano:
1. Mteja anathibitisha utambulisho wa seva.
2. Mteja na seva wanathibitishana utambulisho wao kwa kila mmoja.

Vyeti hutumiwa kuthibitisha utambulisho wa seva. Kwa mifano ya kina ya njia zote mbili, angalia [**mwongozo huu**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Usalama wa Picha za Kontena

Picha za kontena zinaweza kuhifadhiwa kwenye repositori za kibinafsi au za umma. Docker inatoa chaguzi kadhaa za uhifadhi wa picha za kontena:

* **[Docker Hub](https://hub.docker.com)**: Huduma ya usajili wa umma kutoka Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: Mradi wa chanzo wazi unaoruhusu watumiaji kuhudhuria usajili wao wenyewe.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Huduma ya usajili ya biashara ya Docker, ikijumuisha uthibitishaji wa mtumiaji kulingana na jukumu na ushirikiano na huduma za saraka za LDAP.

### Uchunguzi wa Picha

Kontena zinaweza kuwa na **mapungufu ya usalama** kutokana na picha ya msingi au programu iliyosanikishwa juu ya picha ya msingi. Docker inafanya kazi kwenye mradi unaoitwa **Nautilus** ambao hufanya uchunguzi wa usalama wa Kontena na kuorodhesha mapungufu ya usalama. Nautilus hufanya kazi kwa kulinganisha kila safu ya picha ya Kontena na hazina ya mapungufu ya usalama ili kutambua mapengo ya usalama.

Kwa maelezo zaidi [**soma hii**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Amri ya **`docker scan`** inakuwezesha kuchunguza picha za Docker zilizopo kwa kutumia jina au kitambulisho cha picha. Kwa mfano, tumia amri ifuatayo kuchunguza picha ya hello-world:
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
### Kusaini Picha za Docker

Kusaini picha za Docker huhakikisha usalama na ukamilifu wa picha zinazotumiwa kwenye kontena. Hapa kuna maelezo mafupi:

- **Docker Content Trust** hutumia mradi wa Notary, uliojengwa kwa kutumia The Update Framework (TUF), kusimamia usaini wa picha. Kwa maelezo zaidi, angalia [Notary](https://github.com/docker/notary) na [TUF](https://theupdateframework.github.io).
- Ili kuwezesha imani ya yaliyomo ya Docker, weka `export DOCKER_CONTENT_TRUST=1`. Kipengele hiki kimezimwa kwa chaguo-msingi katika toleo la Docker 1.10 na baadaye.
- Kwa kipengele hiki kimeamilishwa, picha zilizosainiwa tu zinaweza kupakuliwa. Kusukuma picha ya awali kunahitaji kuweka nywila kwa funguo za mzizi na lebo, na Docker pia inasaidia Yubikey kwa usalama ulioimarishwa. Maelezo zaidi yanaweza kupatikana [hapa](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Jaribio la kupakua picha isiyosainiwa na imani ya yaliyomo imeamilishwa husababisha kosa la "Hakuna data ya imani kwa toleo la karibuni".
- Kwa kusukuma picha baada ya ya kwanza, Docker inauliza nywila ya funguo la hazina ili kusaini picha.

Ili kuhifadhi nakala rudufu ya funguo zako za kibinafsi, tumia amri:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Wakati wa kubadili watumishi wa Docker, ni muhimu kuhamisha funguo za mizizi na hazina ili kuendeleza shughuli.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na kutekeleza kwa urahisi mchakato wa kazi ulioendeshwa na zana za jamii za juu zaidi duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vipengele vya Usalama wa Kontena

<details>

<summary>Maelezo ya Vipengele vya Usalama wa Kontena</summary>

### Vipengele vya Kufunga Mchakato Mkuu

Katika mazingira ya kontena, kufunga miradi na michakato yake ni muhimu kwa usalama na usimamizi wa rasilimali. Hapa kuna maelezo rahisi ya dhana muhimu:

#### **Namespaces**
- **Lengo**: Kuhakikisha kufungwa kwa rasilimali kama michakato, mtandao, na mfumo wa faili. Hasa katika Docker, namespaces huzuia michakato ya kontena kutoka kwa mwenyeji na kontena nyingine.
- **Matumizi ya `unshare`**: Amri ya `unshare` (au syscall inayofanana) hutumiwa kuunda namespaces mpya, ikitoa safu ya ziada ya kufungwa. Walakini, wakati Kubernetes haizuiliwi kwa asili hii, Docker inafanya hivyo.
- **Kizuizi**: Kuunda namespaces mpya hakiruhusu mchakato kurudi kwenye namespaces za chaguo-msingi za mwenyeji. Kwa kawaida, ili kuingia kwenye namespaces za mwenyeji, mtu anahitaji ufikiaji wa saraka ya `/proc` ya mwenyeji, kwa kutumia `nsenter` kwa kuingia.

#### **Vikundi vya Kudhibiti (CGroups)**
- **Kazi**: Hutumiwa kwa kugawanya rasilimali kati ya michakato.
- **Upande wa Usalama**: Vikundi vya Kudhibiti wenyewe havitoi usalama wa kufungwa, isipokuwa kwa kipengele cha `release_agent`, ambacho, ikiwa hakijasakinishwa vizuri, kinaweza kutumiwa vibaya kwa ufikiaji usiohalali.

#### **Kupunguza Uwezo**
- **Umuhimu**: Ni kipengele muhimu cha usalama kwa kufunga mchakato.
- **Ufanisi**: Inazuia hatua ambazo mchakato wa mizizi anaweza kutekeleza kwa kupunguza uwezo fulani. Hata kama mchakato unafanya kazi na mamlaka ya mizizi, kukosa uwezo muhimu kunazuia utekelezaji wa hatua za mamlaka, kwani syscalls zitashindwa kutokana na idhini duni.

Hizi ni **uwezo uliobaki** baada ya mchakato kupunguza uwezo mwingine:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Inawezeshwa kwa chaguo-msingi katika Docker. Inasaidia **kupunguza hata zaidi syscalls** ambazo mchakato unaweza kuita.\
**Profaili ya Seccomp ya Docker ya chaguo-msingi** inaweza kupatikana katika [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ina kigezo ambacho unaweza kuamsha: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Hii itaruhusu kupunguza uwezo, syscalls, upatikanaji wa faili na folda...

</details>

### Namespaces

**Namespaces** ni kipengele cha kernel ya Linux ambacho **kinagawanya rasilimali za kernel** ili seti moja ya **mchakato** iona seti moja ya **rasilimali** wakati seti nyingine ya **mchakato** inaona seti tofauti ya rasilimali. Kipengele hiki kinafanya kazi kwa kuwa na jina sawa la nafasi kwa seti ya rasilimali na michakato, lakini hizo nafasi zinahusu rasilimali tofauti. Rasilimali inaweza kuwepo katika nafasi nyingi.

Docker hutumia Namespaces za kernel ya Linux zifuatazo kufikia kujitenga kwa Kontena:

* nafasi ya pid
* nafasi ya kufunga
* nafasi ya mtandao
* nafasi ya ipc
* nafasi ya UTS

Kwa **mashauri zaidi kuhusu namespaces**, angalia ukurasa ufuatao:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Kipengele cha kernel ya Linux kinachoitwa **cgroups** kinatoa uwezo wa **kuzuia rasilimali kama cpu, kumbukumbu, io, kasi ya mtandao kati** ya seti ya michakato. Docker inaruhusu kuunda Kontena kwa kutumia kipengele cha cgroup ambacho kinaruhusu udhibiti wa rasilimali kwa Kontena maalum.\
Hapa chini ni mfano wa Kontena iliyoumbwa na kikomo cha kumbukumbu ya nafasi ya mtumiaji hadi 500m, kikomo cha kumbukumbu ya kernel hadi 50m, mgawo wa cpu hadi 512, na uzito wa blkioweight hadi 400. Mgawo wa CPU ni uwiano unaodhibiti matumizi ya CPU ya Kontena. Ina thamani ya chaguo-msingi ya 1024 na ina kiwango kati ya 0 na 1024. Ikiwa Kontena tatu zina mgawo sawa wa CPU wa 1024, kila Kontena inaweza kuchukua hadi 33% ya CPU katika kesi ya mzozo wa rasilimali ya CPU. Blkio-weight ni uwiano unaodhibiti IO ya Kontena. Ina thamani ya chaguo-msingi ya 500 na ina kiwango kati ya 10 na 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Ili kupata cgroup ya kontena, unaweza kufanya yafuatayo:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Kwa habari zaidi angalia:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Uwezo

Uwezo unaruhusu **udhibiti bora wa uwezo ambao unaweza kuruhusiwa** kwa mtumiaji wa mizizi. Docker hutumia kipengele cha uwezo cha kernel ya Linux ili **kupunguza shughuli zinazoweza kufanywa ndani ya Kontena** bila kujali aina ya mtumiaji.

Wakati kontena ya docker inapoendeshwa, **mchakato hupunguza uwezo wa nyeti ambao mchakato unaweza kutumia kutoroka kutoka kwenye kizuizi**. Hii inajaribu kuhakikisha kuwa mchakato hautaweza kutekeleza hatua nyeti na kutoroka:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp kwenye Docker

Hii ni kipengele cha usalama kinachoruhusu Docker **kupunguza syscalls** ambazo zinaweza kutumika ndani ya kontena:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor kwenye Docker

**AppArmor** ni uboreshaji wa kernel ambao unazuia **kontena** kwa seti **mdogo** ya **rasilimali** na **mipangilio ya programu**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux kwenye Docker

- **Mfumo wa Lebo**: SELinux inaweka lebo ya kipekee kwa kila mchakato na kifaa cha mfumo wa faili.
- **Utekelezaji wa Sera**: Inatekeleza sera za usalama ambazo zinafafanua hatua gani lebo ya mchakato inaweza kutekeleza kwenye lebo zingine ndani ya mfumo.
- **Lebo za Mchakato wa Kontena**: Wakati injini za kontena zinaanzisha michakato ya kontena, kawaida hupewa lebo iliyozuiwa ya SELinux, kawaida `container_t`.
- **Lebo za Faili ndani ya Kontena**: Faili ndani ya kontena kawaida huwa na lebo kama `container_file_t`.
- **Sera za Sera**: Sera ya SELinux kimsingi inahakikisha kuwa michakato yenye lebo ya `container_t` inaweza tu kuingiliana (kusoma, kuandika, kutekeleza) na faili zilizopewa lebo kama `container_file_t`.

Mfumo huu unahakikisha kuwa hata kama mchakato ndani ya kontena unashambuliwa, unazuiwa kuingiliana na vitu vyenye lebo husika, ikipunguza kwa kiasi kikubwa uharibifu unaoweza kusababishwa na mashambulizi kama hayo.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Kwenye Docker, programu ya idhini inacheza jukumu muhimu katika usalama kwa kuamua ikiwa itaruhusu au kuzuia maombi kwa daemon ya Docker. Uamuzi huu unafanywa kwa kuchunguza muktadha muhimu mawili:

- **Muktadha wa Uthibitishaji**: Hii ni pamoja na habari kamili kuhusu mtumiaji, kama vile ni nani na jinsi walivyothibitisha utambulisho wao.
- **Muktadha wa Amri**: Hii inajumuisha data zote muhimu zinazohusiana na ombi linalofanywa.

Muktadha huu husaidia kuhakikisha kuwa maombi halali kutoka kwa watumiaji waliothibitishwa tu ndio yanayosindika, kuimarisha usalama wa shughuli za Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS kutoka kwenye kontena

Ikiwa hauzuili rasilimali ambazo kontena inaweza kutumia kwa usahihi, kontena iliyoshambuliwa inaweza kusababisha DoS kwenye mwenyeji ambapo inaendeshwa.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandwidth DoS

Bandwidth DoS ni aina ya shambulio la kukataa huduma ambapo mtu mwenye nia mbaya anajaribu kusababisha kukosekana kwa huduma kwa kuzidiwa kwa uwezo wa mtandao wa lengo. Shambulio hili linahusisha kutuma kiasi kikubwa cha trafiki kwenye mtandao wa lengo ili kusababisha msongamano na kusababisha huduma kuwa haipatikani kwa watumiaji wengine.

Kuna njia kadhaa za kutekeleza shambulio la Bandwidth DoS, ikiwa ni pamoja na kutumia botnets, amplification attacks, na kutumia programu maalum za kushambulia. Shambulio hili linaweza kuathiri vibaya shughuli za biashara na huduma za mtandao, na kusababisha hasara kubwa kwa waathirika.

Kwa kuzuia shambulio la Bandwidth DoS, ni muhimu kutekeleza hatua za usalama kama vile kudhibiti trafiki, kufuatilia matumizi ya mtandao, na kuanzisha mipaka ya kasi ya uhamishaji wa data. Pia, kuhakikisha kuwa miundombinu ya mtandao ina nguvu ya kutosha na inaweza kushughulikia mzigo mkubwa wa trafiki ni muhimu katika kuzuia shambulio hili.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Vielelezo Vizuri vya Docker

### Bendi ya --privileged

Katika ukurasa ufuatao unaweza kujifunza **maana ya bendera ya `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Ikiwa unatumia chombo cha kuhifadhi ambapo mshambuliaji anafanikiwa kupata ufikiaji kama mtumiaji wa hali ya chini. Ikiwa una **binary ya suid iliyowekwa vibaya**, mshambuliaji anaweza kuitumia na **kuongeza mamlaka ndani** ya chombo cha kuhifadhi. Hii inaweza kumruhusu kutoroka kutoka chombo hicho.

Kuendesha chombo cha kuhifadhi na chaguo la **`no-new-privileges`** kuwezeshwa kutazuia aina hii ya kuongeza mamlaka.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Nyingine

In this section, we will explore some additional security measures that can be implemented to enhance the security of Docker containers.

##### 1. Limit Container Capabilities

By default, Docker containers inherit the capabilities of the host system. However, it is possible to limit the capabilities available to containers, thereby reducing the potential attack surface. This can be achieved by using the `--cap-drop` flag when running containers.

For example, to drop the `SYS_ADMIN` capability, you can run the container with the following command:

```bash
docker run --cap-drop SYS_ADMIN <image>
```

##### 2. Use Read-Only Filesystems

To prevent unauthorized modifications to the container's filesystem, you can mount it as read-only. This can be done by adding the `--read-only` flag when running the container.

```bash
docker run --read-only <image>
```

##### 3. Enable AppArmor or SELinux

AppArmor and SELinux are security modules that can be used to enforce access control policies on Docker containers. By enabling and configuring these modules, you can further restrict the actions that containers can perform.

To enable AppArmor, you can add the `--security-opt apparmor=profile_name` flag when running the container.

```bash
docker run --security-opt apparmor=profile_name <image>
```

To enable SELinux, you can add the `--security-opt label=type:label_value` flag when running the container.

```bash
docker run --security-opt label=type:label_value <image>
```

##### 4. Monitor Container Activity

Monitoring the activity of Docker containers can help detect any suspicious or malicious behavior. Tools like Docker Bench for Security and Sysdig Falco can be used to monitor and alert on container activity.

##### 5. Regularly Update Docker and Containers

Keeping Docker and its containers up to date is crucial for maintaining security. Regularly check for updates and apply them to ensure that any security vulnerabilities are patched.

##### 6. Implement Network Segmentation

To minimize the impact of a potential container compromise, it is recommended to implement network segmentation. By isolating containers into separate networks, you can limit the lateral movement of an attacker within your infrastructure.

##### 7. Use Docker Bench for Security

Docker Bench for Security is a script that provides a set of best practices for securing Docker containers. It can be used to assess the security of your Docker installation and identify any potential vulnerabilities.

To use Docker Bench for Security, you can run the following command:

```bash
docker run -it --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /var/lib:/var/lib \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /usr/lib/systemd:/usr/lib/systemd \
    -v /etc:/etc --label docker_bench_security \
    docker/docker-bench-security
```

These additional security measures can help strengthen the security of your Docker containers and protect them from potential attacks.
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
Kwa chaguo zaidi za **`--security-opt`**, angalia: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Mambo Mengine ya Kuzingatia Kuhusu Usalama

### Usimamizi wa Siri: Mbinu Bora

Ni muhimu kuepuka kuweka siri moja kwa moja kwenye picha za Docker au kutumia mazingira ya mazingira, kwani njia hizi zinafunua habari nyeti kwa yeyote aliye na ufikiaji wa chombo kupitia amri kama vile `docker inspect` au `exec`.

**Docker volumes** ni mbadala salama, inapendekezwa kwa kupata habari nyeti. Wanaweza kutumika kama mfumo wa faili wa muda katika kumbukumbu, kupunguza hatari zinazohusiana na `docker inspect` na kuingia kwenye kumbukumbu. Walakini, watumiaji wa mizizi na wale walio na ufikiaji wa `exec` kwenye chombo bado wanaweza kupata siri.

**Docker secrets** hutoa njia salama zaidi ya kushughulikia habari nyeti. Kwa hali zinazohitaji siri wakati wa hatua ya ujenzi wa picha, **BuildKit** inatoa suluhisho lenye ufanisi na msaada kwa siri za wakati wa ujenzi, kuongeza kasi ya ujenzi na kutoa huduma za ziada.

Ili kutumia BuildKit, inaweza kuwezeshwa kwa njia tatu:

1. Kupitia mazingira ya mazingira: `export DOCKER_BUILDKIT=1`
2. Kwa kuongeza awali kwenye amri: `DOCKER_BUILDKIT=1 docker build .`
3. Kwa kuwezesha kwa chaguo-msingi katika usanidi wa Docker: `{ "features": { "buildkit": true } }`, ikifuatiwa na kuanzisha upya kwa Docker.

BuildKit inaruhusu matumizi ya siri za wakati wa ujenzi na chaguo la `--secret`, ikihakikisha siri hizi hazijumuishwi katika hifadhi ya ujenzi wa picha au picha ya mwisho, kwa kutumia amri kama:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Kwa siri zinazohitajika katika chombo kinachotumika, **Docker Compose na Kubernetes** hutoa suluhisho imara. Docker Compose hutumia ufunguo wa `secrets` katika ufafanuzi wa huduma ili kubainisha faili za siri, kama inavyoonyeshwa katika mfano wa `docker-compose.yml` hapa chini:
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
Hii usanidi inaruhusu matumizi ya siri wakati wa kuanza huduma na Docker Compose.

Katika mazingira ya Kubernetes, siri zinasaidiwa kwa asili na zinaweza kusimamiwa zaidi na zana kama [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Mfumo wa Ufikiaji wa Majukumu (RBAC) wa Kubernetes huongeza usalama wa usimamizi wa siri, kama vile Docker Enterprise.

### gVisor

**gVisor** ni kiini cha programu, kilichoandikwa kwa Go, ambacho kinautekeleza sehemu kubwa ya uso wa mfumo wa Linux. Inajumuisha [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime inayoitwa `runsc` ambayo hutoa **kizuizi cha kubadilishana kati ya programu na kiini cha mwenyeji**. Runtime ya `runsc` inashirikiana na Docker na Kubernetes, hivyo kuifanya iwe rahisi kuendesha kontena zilizofungwa.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** ni jumuiya ya chanzo wazi inayofanya kazi ya kujenga runtime salama ya kontena na mashine za kawaida za kivitualize ambazo zinaonekana na kufanya kazi kama kontena, lakini zinatoa **kizuizi imara cha kazi kwa kutumia teknolojia ya kivitualize ya vifaa** kama safu ya pili ya ulinzi.

{% embed url="https://katacontainers.io/" %}

### Vidokezo vifupi

* **Usitumie bendera ya `--privileged` au kufunga** [**socket ya Docker ndani ya kontena**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Socket ya Docker inaruhusu kuundwa kwa kontena, hivyo ni njia rahisi ya kuchukua udhibiti kamili wa mwenyeji, kwa mfano, kwa kuendesha kontena nyingine na bendera ya `--privileged`.
* Usiendeshe kama mtumiaji mkuu ndani ya kontena. Tumia [mtumiaji tofauti](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) na [nafasi za mtumiaji](https://docs.docker.com/engine/security/userns-remap/)**.** Mtumiaji mkuu ndani ya kontena ni sawa na kwenye mwenyeji isipokuwa imebadilishwa na nafasi za mtumiaji. Inazuiliwa kidogo tu na, kwa kiasi kikubwa, nafasi za Linux, uwezo, na vikundi vya kudhibiti.
* [**Acha uwezo wote**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) na wezesha tu wale wanaohitajika** (`--cap-add=...`). Kazi nyingi hazihitaji uwezo wowote na kuongeza uwezo huongeza wigo wa shambulio la uwezekano.
* [**Tumia chaguo la usalama "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) ili kuzuia michakato kupata uwezo zaidi, kwa mfano kupitia programu za suid.
* [**Punguza rasilimali zinazopatikana kwa kontena**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Vizuizi vya rasilimali vinaweza kulinda mashine kutokana na mashambulizi ya kukataa huduma.
* **Badilisha** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(au SELinux)** maelezo ya kikomo ili kuzuia hatua na syscalls zinazopatikana kwa kontena kuwa chini ya kiwango kinachohitajika.
* **Tumia** [**picha rasmi za Docker**](https://docs.docker.com/docker-hub/official\_images/) **na hitaji saini** au jenga yako mwenyewe kwa kuzingatia hizo. Usirithi au tumia picha zilizo na mlango wa nyuma. Pia weka funguo za mizizi, nywila mahali salama. Docker ina mipango ya kusimamia funguo na UCP.
* **Jenga upya mara kwa mara** picha zako ili **kuomba visasaisho vya usalama kwa mwenyeji na picha**.
* Simamia **siri zako kwa busara** ili iwe ngumu kwa mshambuliaji kuzipata.
* Ikiwa **unafichua daemon ya Docker tumia HTTPS** na uwakilishi wa wateja na seva.
* Katika Dockerfile yako, **pendelea COPY badala ya ADD**. ADD inafungua faili zilizopakiwa kiotomatiki na inaweza kunakili faili kutoka kwenye URL. COPY haina uwezo huu. Kadri inavyowezekana, epuka kutumia ADD ili usiweze kushambuliwa kupitia URL za mbali na faili za Zip.
* Kuwa na **kontena tofauti kwa kila huduma ndogo**.
* **Usiweke ssh** ndani ya kontena, "docker exec" inaweza kutumika kama ssh kwa Kontena.
* Kuwa na **picha ndogo** za kontena

## Kuvunja Usalama wa Docker / Kuongeza Mamlaka

Ikiwa uko **ndani ya kontena ya Docker** au una ufikiaji kwa mtumiaji katika **kikundi cha docker**, unaweza kujaribu **kutoroka na kuongeza mamlaka**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Kupitisha Plugin ya Uthibitishaji wa Docker

Ikiwa una ufikiaji wa soketi ya docker au una ufikiaji kwa mtumiaji katika **kikundi cha docker lakini hatua zako zinazuiliwa na programu ya uthibitishaji wa docker**, angalia ikiwa unaweza **kupitisha**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Kufanya Docker Kuwa Imara

* Zana [**docker-bench-security**](https://github.com/docker/docker-bench-security) ni skripti ambayo inachunguza mamia ya mazoea bora ya kawaida kuhusu kupeleka kontena za Docker kwa uzalishaji. Vipimo vyote ni vya kiotomatiki, na vimejengwa kwenye [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Unahitaji kuendesha zana hiyo kutoka kwenye mwenyeji unaoendesha docker au kutoka kwenye kontena na mamlaka ya kutosha. Pata **jinsi ya kuendesha katika README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Marejeo

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https
Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
