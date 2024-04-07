# CGroups

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

**Linux Beheergroepe**, of **cgroups**, is 'n kenmerk van die Linux-kernel wat die toekenning, beperking, en prioritisering van stelselbronne soos CPU, geheue, en skyf I/O onder prosesgroepe moontlik maak. Hulle bied 'n meganisme vir **die bestuur en isolering van die hulpbruggebruik** van prosesversamelings, voordelig vir doeleindes soos hulpbrugbeperking, werklas-isolering, en hulpbrugprioritisering tussen verskillende prosesgroepe.

Daar is **twee weergawes van cgroups**: weergawe 1 en weergawe 2. Beide kan gelyktydig op 'n stelsel gebruik word. Die primêre onderskeid is dat **cgroups weergawe 2** 'n **hiërargiese, boomagtige struktuur** introduceer, wat meer genuanseerde en gedetailleerde hulpbrugverdeling tussen prosesgroepe moontlik maak. Daarbenewens bring weergawe 2 verskeie verbeterings, insluitend:

Benewens die nuwe hiërargiese organisasie het cgroups weergawe 2 ook **veral ander veranderinge en verbeterings** ingevoer, soos ondersteuning vir **nuwe hulpbrugbeheerders**, beter ondersteuning vir oudtydse toepassings, en verbeterde prestasie.

Oor die algemeen bied cgroups **weergawe 2 meer kenmerke en beter prestasie** as weergawe 1, maar die laasgenoemde kan steeds in sekere scenarios gebruik word waar verenigbaarheid met ouer stelsels 'n bekommernis is.

Jy kan die v1 en v2 cgroups vir enige proses lys deur na sy cgroup-lêer in /proc/\<pid> te kyk. Jy kan begin deur na jou skul se cgroups te kyk met hierdie bevel:
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
Die uitvoerstruktuur is as volg:

* **Nommers 2–12**: cgroups v1, met elke lyn wat 'n verskillende cgroup voorstel. Kontroleerders vir hierdie is aangrensend aan die nommer.
* **Nommer 1**: Ook cgroups v1, maar slegs vir bestuursdoeleindes (ingestel deur bv. systemd), en ontbreek 'n kontroleerder.
* **Nommer 0**: Verteenwoordig cgroups v2. Geen kontroleerders word gelys nie, en hierdie lyn is eksklusief op stelsels wat slegs cgroups v2 hardloop.
* Die **name is hiërargies**, lyk soos lêerpaadjies, wat die struktuur en verhouding tussen verskillende cgroups aandui.
* **Name soos /user.slice of /system.slice** dui die kategorisering van cgroups aan, met user.slice tipies vir aanmeldsessies wat deur systemd bestuur word en system.slice vir stelseldienste.

### Besigtiging van cgroups

Die lêersisteem word tipies gebruik vir die toegang tot **cgroups**, wat afwyk van die Unix-stelseloproepkoppelvlak wat tradisioneel gebruik word vir kernelinteraksies. Om 'n skul se cgroup-konfigurasie te ondersoek, moet 'n mens die **/proc/self/cgroup**-lêer ondersoek, wat die skul se cgroup onthul. Daarna, deur te navigeer na die **/sys/fs/cgroup** (of **`/sys/fs/cgroup/unified`**) gids en 'n gids te vind wat die cgroup se naam deel, kan 'n mens verskeie instellings en hulpbruggebruiksinligting wat relevant is vir die cgroup, waarneem.

![Cgroup-lêersisteem](<../../../.gitbook/assets/image (1125).png>)

Die sleutelkoppelvlaklêers vir cgroups is voorafgegaan deur **cgroup**. Die **cgroup.procs**-lêer, wat met standaardopdragte soos cat bekyk kan word, lys die prosesse binne die cgroup. 'n Ander lêer, **cgroup.threads**, sluit draadinligting in.

![Cgroup Procs](<../../../.gitbook/assets/image (278).png>)

Cgroups wat skul beheer, omvat tipies twee kontroleerders wat geheugengebruik en prosesgetal reguleer. Om met 'n kontroleerder te interaksie, moet lêers wat die voorvoegsel van die kontroleerder dra, geraadpleeg word. Byvoorbeeld, **pids.current** sou geraadpleeg word om die telling van drade in die cgroup te bepaal.

![Cgroup-geheue](<../../../.gitbook/assets/image (674).png>)

Die aanduiding van **max** in 'n waarde dui op die afwesigheid van 'n spesifieke limiet vir die cgroup. Tog, as gevolg van die hiërargiese aard van cgroups, kan limiete opgelê word deur 'n cgroup op 'n laer vlak in die gidshiërargie.

### Manipulering en Skepping van cgroups

Prosesse word aan cgroups toegewys deur **hul Proses-ID (PID) na die `cgroup.procs`-lêer te skryf**. Dit vereis wortelpriviliges. Byvoorbeeld, om 'n proses by te voeg:
```bash
echo [pid] > cgroup.procs
```
Op dieselfde manier word **die wysiging van cgroup-eienskappe, soos die instelling van 'n PID-limiet**, gedoen deur die gewenste waarde na die relevante lêer te skryf. Om 'n maksimum van 3,000 PIDs vir 'n cgroup in te stel:
```bash
echo 3000 > pids.max
```
**Skep nuwe cgroups** behels die skep van 'n nuwe subgids binne die cgroup-hierargie, wat die kernel aanmoedig om outomaties die nodige koppelvlaklêers te genereer. Alhoewel cgroups sonder aktiewe prosesse met `rmdir` verwyder kan word, moet daar bewus wees van sekere beperkings:

* **Prosesse kan slegs in blaar-cgroups geplaas word** (m.a.w., die mees geneste in 'n hiërargie).
* **'n Cgroup kan nie 'n beheerder besit wat afwesig is in sy ouer nie**.
* **Beheerders vir kind-cgroups moet eksplisiet verklaar word** in die `cgroup.subtree_control`-lêer. Byvoorbeeld, om die CPU- en PID-beheerders in 'n kind-cgroup te aktiveer:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Die **root cgroup** is 'n uitsondering op hierdie reëls, wat direkte prosesplasing toelaat. Dit kan gebruik word om prosesse uit systemd-bestuur te verwyder.

**Monitering van CPU-gebruik** binne 'n cgroup is moontlik deur die `cpu.stat` lêer, wat die totale CPU-tyd verbruik aandui, nuttig vir die opsporing van gebruik oor 'n diens se subprosesse:

<figure><img src="../../../.gitbook/assets/image (905).png" alt=""><figcaption><p>CPU-gebruikstatistieke soos in die cpu.stat lêer vertoon</p></figcaption></figure>

## Verwysings

* **Boek: How Linux Works, 3de Uitgawe: Wat Elke Supergebruiker Behoort te Weet Deur Brian Ward**
