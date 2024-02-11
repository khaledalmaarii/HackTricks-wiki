# CGroups

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

**Linux-beheergroepe**, of **cgroups**, is 'n kenmerk van die Linux-kernel wat die toekenning, beperking en prioritisering van stelselhulpbronne soos CPU, geheue en skyf-I/O aan prosesgroepe moontlik maak. Dit bied 'n meganisme vir die **bestuur en isolering van die hulpbronverbruik** van prosesversamelings, wat voordelig is vir doeleindes soos hulpbronbeperking, werklastisolering en hulpbronprioritisering tussen verskillende prosesgroepe.

Daar is **twee weergawes van cgroups**: weergawe 1 en weergawe 2. Beide kan gelyktydig op 'n stelsel gebruik word. Die primêre onderskeid is dat **cgroups weergawe 2** 'n **hiërargiese, boomagtige struktuur** inbring wat meer genuanseerde en gedetailleerde hulpbronverspreiding tussen prosesgroepe moontlik maak. Daarbenewens bring weergawe 2 verskeie verbeterings, insluitend:

Naas die nuwe hiërargiese organisasie het cgroups weergawe 2 ook **verskeie ander veranderinge en verbeterings** ingevoer, soos ondersteuning vir **nuwe hulpbronbeheerders**, beter ondersteuning vir oudtydse toepassings en verbeterde prestasie.

Oor die algemeen bied cgroups **weergawe 2 meer funksies en beter prestasie** as weergawe 1, maar laasgenoemde kan steeds in sekere scenario's gebruik word waar verenigbaarheid met oudere stelsels 'n oorweging is.

Jy kan die v1- en v2-cgroups vir enige proses lys deur na sy cgroup-lêer in /proc/\<pid> te kyk. Jy kan begin deur na jou skel se cgroups te kyk met hierdie opdrag:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Die uitsetstruktuur is as volg:

- **Nommers 2-12**: cgroups v1, met elke lyn wat 'n verskillende cgroup verteenwoordig. Kontroleerders vir hierdie cgroups word langs die nommer gespesifiseer.
- **Nommer 1**: Ook cgroups v1, maar slegs vir bestuursdoeleindes (deur bv. systemd ingestel), en het nie 'n kontroleerder nie.
- **Nommer 0**: Verteenwoordig cgroups v2. Geen kontroleerders word gelys nie, en hierdie lyn is eksklusief vir stelsels wat slegs cgroups v2 gebruik.
- Die **name is hiërargies**, soos lêerpaadjies, wat die struktuur en verhouding tussen verskillende cgroups aandui.
- **Name soos /user.slice of /system.slice** spesifiseer die kategorisering van cgroups, met user.slice tipies vir aanmeldsessies wat deur systemd bestuur word en system.slice vir stelseldienste.

### Sien cgroups

Die lêersisteem word tipies gebruik om toegang tot **cgroups** te verkry, wat afwyk van die Unix-stelseloproepkoppelvlak wat tradisioneel gebruik word vir kernelinteraksies. Om 'n skulp se cgroup-konfigurasie te ondersoek, moet jy die **/proc/self/cgroup**-lêer ondersoek, wat die skulp se cgroup onthul. Daarna kan jy deur na die **/sys/fs/cgroup** (of **`/sys/fs/cgroup/unified`**) gids te navigeer en 'n gids te vind wat die naam van die cgroup deel, verskeie instellings en hulpbronverbruiksinligting wat relevant is vir die cgroup, waarneem.

![Cgroup-lêersisteem](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Die sleutelkoppelvlaklêers vir cgroups het die voorvoegsel **cgroup**. Die **cgroup.procs**-lêer, wat met standaardopdragte soos cat bekyk kan word, lys die prosesse binne die cgroup. 'n Ander lêer, **cgroup.threads**, bevat draadinligting.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Cgroups wat skulpe bestuur, omvat tipies twee kontroleerders wat geheugengebruik en prosessetelling reguleer. Om met 'n kontroleerder te kommunikeer, moet lêers met die voorvoegsel van die kontroleerder geraadpleeg word. Byvoorbeeld, **pids.current** sal geraadpleeg word om die telling van drade in die cgroup te bepaal.

![Cgroup-geheue](../../../.gitbook/assets/image%20(3)%20(5).png)

Die aanduiding van **max** in 'n waarde dui op die afwesigheid van 'n spesifieke limiet vir die cgroup. Tog, as gevolg van die hiërargiese aard van cgroups, kan limiete opgelê word deur 'n cgroup op 'n laer vlak in die gidshiërargie.

### Manipulering en Skepping van cgroups

Prosesse word aan cgroups toegewys deur **hul Proses-ID (PID) na die `cgroup.procs`-lêer te skryf**. Dit vereis root-voorregte. Byvoorbeeld, om 'n proses by te voeg:
```bash
echo [pid] > cgroup.procs
```
Op soortgelyke wyse word **cgroup-eienskappe gewysig, soos die instelling van 'n PID-limiet**, deur die gewenste waarde na die betrokke lêer te skryf. Om 'n maksimum van 3,000 PIDs vir 'n cgroup in te stel:
```bash
echo 3000 > pids.max
```
**Die skep van nuwe cgroups** behels die skep van 'n nuwe subgids binne die cgroup-hierargie, wat die kernel aanmoedig om outomaties die nodige interfeeslêers te genereer. Alhoewel cgroups sonder aktiewe prosesse met `rmdir` verwyder kan word, moet daar bewus wees van sekere beperkings:

- **Prosesse kan slegs in blaar-cgroups geplaas word** (d.w.s. die mees geneste in 'n hiërargie).
- **'n Cgroup kan nie 'n beheerder besit wat afwesig is in sy ouer nie**.
- **Beheerders vir kind-cgroups moet eksplisiet verklaar word** in die `cgroup.subtree_control`-lêer. Byvoorbeeld, om die CPU- en PID-beheerders in 'n kind-cgroup te aktiveer:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Die **root cgroup** is 'n uitsondering op hierdie reëls en maak direkte prosesplasing moontlik. Dit kan gebruik word om prosesse uit systemd-bestuur te verwyder.

**Monitering van CPU-gebruik** binne 'n cgroup is moontlik deur die `cpu.stat` lêer, wat die totale CPU-tyd wat verbruik is, vertoon. Dit is nuttig om gebruik oor 'n diens se subprosesse te volg:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>CPU-gebruikstatistieke soos vertoon in die cpu.stat lêer</figcaption></figure>

## Verwysings
* **Boek: How Linux Works, 3rd Edition: What Every Superuser Should Know deur Brian Ward**

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
