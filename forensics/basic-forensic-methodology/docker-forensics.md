# Uchunguzi wa Docker

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Kubadilisha Kontena

Kuna mashaka kwamba kontena fulani la docker lilidukuliwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza **kwa urahisi **kupata marekebisho yaliyofanywa kwenye kontena hili kuhusiana na picha** na:
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
Katika amri iliyotangulia **C** inamaanisha **Kilichobadilika** na **A,** **Ongeza**.\
Ikiwa utagundua kwamba faili fulani ya kuvutia kama vile `/etc/shadow` ilibadilishwa unaweza kuipakua kutoka kwenye kontena ili uchunguze shughuli za uovu kwa:
```bash
docker cp wordpress:/etc/shadow.
```
Unaweza pia **kulilinganisha na asili yake** kwa kukimbia kontena mpya na kuchambua faili kutoka humo:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ikiwa unagundua kwamba **faili fulani ya shaka imeongezwa** unaweza kufikia chombo na kuichunguza:
```bash
docker exec -it wordpress bash
```
## Kubadilisha Picha

Unapopewa picha ya docker iliyohamishiwa (labda katika muundo wa `.tar`) unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) **kuchambua muhtasari wa mabadiliko**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **kudekompresi** picha na **kufikia blobs** kutafuta faili za shaka ambazo unaweza kuzipata katika historia ya mabadiliko:
```bash
tar -xf image.tar
```
### Uchambuzi wa Msingi

Unaweza kupata **taarifa za msingi** kutoka kwa picha inayoendeshwa:
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kwa:
```bash
docker history --no-trunc <image>
```
Unaweza pia kuzalisha **dockerfile kutoka kwa picha** kwa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Zama ndani

Ili kupata faili zilizoongezwa/kubadilishwa kwenye picha za docker unaweza pia kutumia [**dive**](https://github.com/wagoodman/dive) (ipakue kutoka [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) kama chombo:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii inakuruhusu **kupitia blobs tofauti za picha za docker** na kuangalia ni faili zipi zilizobadilishwa/kuongezwa. **Nyekundu** inamaanisha imeongezwa na **manjano** inamaanisha imebadilishwa. Tumia **tab** kuhamia maoni mengine na **nafasi** kufunga/kufungua folda.

Kwa die hutaweza kupata maudhui ya hatua tofauti za picha. Ili kufanya hivyo, utahitaji **kudecompress kila safu na kufikia**.\
Unaweza kudecompress safu zote kutoka kwa picha kutoka kwenye saraka ambapo picha ilikuwa imekudecompress kwa kutekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Vitambulisho kutoka kumbukumbu

Tafadhali kumbuka kwamba unapotekeleza chombo cha docker ndani ya mwenyeji **unaweza kuona michakato inayoendeshwa kwenye chombo kutoka kwa mwenyeji** kwa kutekeleza tu `ps -ef`

Hivyo (kama mtumiaji wa mizizi) unaweza **kudondosha kumbukumbu ya michakato** kutoka kwa mwenyeji na kutafuta **vitambulisho** kama [**ilivyo kwenye mfano ufuatao**](../../linux-hardening/privilege-escalation/#process-memory).
