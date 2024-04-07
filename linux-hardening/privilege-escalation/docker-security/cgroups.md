# CGroups

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

**Linux Control Groups**, ili **cgroups**, su funkcija Linux kernela koja omogućava dodelu, ograničenje i prioritizaciju resursa sistema poput CPU-a, memorije i disk I/O među grupama procesa. Pružaju mehanizam za **upravljanje i izolaciju korišćenja resursa** kolekcija procesa, korisnih za svrhe poput ograničenja resursa, izolacije radnog opterećenja i prioritizacije resursa među različitim grupama procesa.

Postoje **dve verzije cgroups-a**: verzija 1 i verzija 2. Obe mogu biti korišćene istovremeno na sistemu. Osnovna razlika je što **cgroups verzija 2** uvodi **hijerarhijsku, stablo-sličnu strukturu**, omogućavajući detaljniju distribuciju resursa među grupama procesa. Pored toga, verzija 2 donosi različita poboljšanja, uključujući:

Pored nove hijerarhijske organizacije, cgroups verzija 2 takođe je uvela **nekoliko drugih promena i poboljšanja**, kao što su podrška za **nove kontrolere resursa**, bolja podrška za legacy aplikacije i poboljšana performansa.

Ukupno, cgroups **verzija 2 nudi više funkcija i bolju performansu** od verzije 1, ali ova poslednja se i dalje može koristiti u određenim scenarijima gde je kompatibilnost sa starijim sistemima od značaja.

Možete videti v1 i v2 cgroups za bilo koji proces gledanjem njegovog cgroup fajla u /proc/\<pid>. Možete početi sa pregledom cgroups-a vaše ljuske ovom komandom:
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
### Pregled cgroups

Struktura izlaza je kako sledi:

* **Brojevi 2–12**: cgroups v1, pri čemu svaka linija predstavlja različiti cgroup. Kontroleri za ove su navedeni pored broja.
* **Broj 1**: Takođe cgroups v1, ali isključivo za svrhe upravljanja (postavljen od strane, npr., systemd-a), i nedostaje kontroler.
* **Broj 0**: Predstavlja cgroups v2. Kontroleri nisu navedeni, i ova linija je ekskluzivna na sistemima koji koriste samo cgroups v2.
* **Imena su hijerarhijska**, slična putanjama datoteka, ukazujući na strukturu i odnos između različitih cgroups.
* **Imena poput /user.slice ili /system.slice** specificiraju kategorizaciju cgroups, pri čemu je user.slice obično za sesije prijavljivanja koje upravlja systemd, a system.slice za sistemski servis.

Slika sistema datoteka se obično koristi za pristupanje **cgroups**, odstupajući od tradicionalnog Unix sistemskog poziva koji se obično koristi za interakcije sa jezgrom. Da biste istražili konfiguraciju cgroup-a ljuske, trebalo bi da pregledate datoteku **/proc/self/cgroup**, koja otkriva cgroup ljuske. Zatim, navigiranjem do direktorijuma **/sys/fs/cgroup** (ili **`/sys/fs/cgroup/unified`**) i pronalaženjem direktorijuma koji deli ime cgroup-a, možete posmatrati različite postavke i informacije o korišćenju resursa relevantne za cgroup.

Ključne datoteke interfejsa za cgroups imaju prefiks **cgroup**. Datoteka **cgroup.procs**, koja se može pregledati standardnim komandama poput cat, nabraja procese unutar cgroup-a. Druga datoteka, **cgroup.threads**, uključuje informacije o nitima.

Cgroup-ovi koji upravljaju ljuskama obično obuhvataju dva kontrolera koji regulišu upotrebu memorije i broj procesa. Da biste interagovali sa kontrolerom, treba da se konsultuju datoteke koje nose prefiks kontrolera. Na primer, **pids.current** bi se koristio da bi se utvrdio broj niti u cgroup-u.

Indikacija **max** u vrednosti sugeriše odsustvo specifičnog ograničenja za cgroup. Međutim, zbog hijerarhijske prirode cgroup-ova, ograničenja mogu biti nametnuta od strane cgroup-a na nižem nivou u hijerarhiji direktorijuma.

### Manipulacija i Kreiranje cgroup-a

Procesi se dodeljuju cgroup-ovima **upisivanjem njihovog ID procesa (PID) u datoteku `cgroup.procs`**. Za ovo su potrebne administratorske privilegije. Na primer, da biste dodali proces:
```bash
echo [pid] > cgroup.procs
```
Slično tome, **izmena cgroup atributa, poput postavljanja PID ograničenja**, vrši se upisivanjem željene vrednosti u odgovarajući fajl. Da biste postavili maksimalno 3.000 PID-ova za cgroup:
```bash
echo 3000 > pids.max
```
**Kreiranje novih cgroups** uključuje pravljenje novog poddirektorijuma unutar hijerarhije cgroup-a, što podstiče kernel da automatski generiše neophodne interfejs fajlove. Iako cgroups bez aktivnih procesa mogu biti uklonjeni sa `rmdir`, budite svesni određenih ograničenja:

* **Procesi mogu biti smešteni samo u listne cgroups** (tj. najugnježdenije u hijerarhiji).
* **Cgroup ne može imati kontroler koji nedostaje u svom roditelju**.
* **Kontroleri za pod-cgroups moraju biti eksplicitno deklarisani** u fajlu `cgroup.subtree_control`. Na primer, da omogućite CPU i PID kontrolere u pod-cgroup-u:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Root cgroup** je izuzetak od ovih pravila, omogućavajući direktno postavljanje procesa. Ovo se može koristiti za uklanjanje procesa iz systemd upravljanja.

**Pratiti korišćenje CPU-a** unutar cgroup-a je moguće putem fajla `cpu.stat`, koji prikazuje ukupno vreme CPU-a koje je potrošeno, korisno za praćenje korišćenja preko podprocesa servisa:

<figure><img src="../../../.gitbook/assets/image (905).png" alt=""><figcaption><p>Statistika korišćenja CPU-a prikazana u fajlu cpu.stat</p></figcaption></figure>

## Reference

* **Knjiga: Kako Linux funkcioniše, 3. izdanje: Šta svaki superkorisnik treba da zna, autor Brian Ward**
