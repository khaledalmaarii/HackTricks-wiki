# Uchunguzi wa Docker

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kubadilisha Kontena

Kuna tuhuma kwamba kontena fulani la docker limeingiliwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza **kupata mabadiliko yaliyofanywa kwenye kontena hiki kuhusiana na picha** kwa urahisi kwa kutumia:
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
Katika amri iliyotangulia **C** inamaanisha **Kimebadilika** na **A,** **Kimeongezwa**.\
Ikiwa utagundua kuwa faili fulani ya kuvutia kama vile `/etc/shadow` imebadilishwa, unaweza kuipakua kutoka kwenye kontena ili uchunguze shughuli za uovu kwa:
```bash
docker cp wordpress:/etc/shadow.
```
Unaweza pia **kulilinganisha na ile ya awali** kwa kukimbia kontena mpya na kuchukua faili kutoka kwake:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ikiwa utagundua kuwa **faili fulani ya shaka imeongezwa**, unaweza kufikia chombo na kuichunguza:
```bash
docker exec -it wordpress bash
```
## Kubadilisha Picha

Unapopewa picha ya docker iliyohamishiwa (labda katika muundo wa `.tar`), unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) ili **kutoa muhtasari wa mabadiliko**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **kufungua** picha na **kupata blobs** ili kutafuta faili za shaka ambazo unaweza kuzipata katika historia ya mabadiliko:
```bash
tar -xf image.tar
```
### Uchambuzi Msingi

Unaweza kupata **habari msingi** kutoka kwa picha inayotumika:
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kwa kutumia:
```bash
docker history --no-trunc <image>
```
Unaweza pia kuzalisha **dockerfile kutoka kwa picha** kwa kutumia:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Chukua

Ili kupata faili zilizoongezwa/kubadilishwa kwenye picha za docker unaweza pia kutumia chombo cha [**chukua**](https://github.com/wagoodman/dive) (pakua kutoka [**toleo**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) cha matumizi:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii inakuwezesha **kuvinjari kupitia blobs tofauti za picha za docker** na kuangalia ni faili zipi zilizobadilishwa/kuongezwa. **Nyekundu** inamaanisha kuongezwa na **njano** inamaanisha kubadilishwa. Tumia **tab** kuhamia kwenye mtazamo mwingine na **nafasi** kufunga/fungua folda.

Kwa die hautaweza kupata maudhui ya hatua tofauti za picha. Ili kufanya hivyo, utahitaji **kupunguza kila safu na kufikia**.\
Unaweza kupunguza safu zote kutoka kwenye picha kutoka kwenye saraka ambapo picha ilipunguzwa kwa kutekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Vitambulisho kutoka kwenye kumbukumbu

Tafadhali kumbuka kuwa unapofanya kazi na chombo cha docker ndani ya mwenyeji **unaweza kuona michakato inayofanya kazi kwenye chombo kutoka kwenye mwenyeji** kwa kutekeleza tu `ps -ef`

Kwa hivyo (kama mtumiaji mkuu) unaweza **kuchota kumbukumbu ya michakato** kutoka kwenye mwenyeji na kutafuta **vitambulisho** kama [**inavyoonyeshwa katika mfano ufuatao**](../../linux-hardening/privilege-escalation/#process-memory).

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
