# CGroups

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne Informacije

**Linux Control Groups**, ili **cgroups**, su funkcija Linux jezgra koja omogućava dodelu, ograničavanje i prioritizaciju resursa sistema poput CPU-a, memorije i disk I/O među grupama procesa. Pružaju mehanizam za **upravljanje i izolaciju korišćenja resursa** kolekcija procesa, korisnih za svrhe poput ograničavanja resursa, izolacije radnog opterećenja i prioritizacije resursa među različitim grupama procesa.

Postoje **dve verzije cgroups-a**: verzija 1 i verzija 2. Obe mogu biti korišćene istovremeno na sistemu. Osnovna razlika je što **cgroups verzija 2** uvodi **hijerarhijsku, stablo-sličnu strukturu**, omogućavajući detaljniju distribuciju resursa među grupama procesa. Pored toga, verzija 2 donosi različita poboljšanja, uključujući:

Pored nove hijerarhijske organizacije, cgroups verzija 2 takođe je uvela **nekoliko drugih promena i poboljšanja**, kao što su podrška za **nove kontrolere resursa**, bolja podrška za legacy aplikacije i poboljšana performansa.

Ukupno, cgroups **verzija 2 nudi više funkcija i bolju performansu** od verzije 1, ali ova poslednja se i dalje može koristiti u određenim scenarijima gde je kompatibilnost sa starijim sistemima od značaja.

Možete videti v1 i v2 cgroups za bilo koji proces gledanjem njegovog cgroup fajla u /proc/\<pid>. Možete početi tako što ćete pogledati cgroups vaše ljuske ovom komandom:
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
### Pregledanje cgroups

Struktura izlaza je kako slijedi:

* **Brojevi 2–12**: cgroups v1, pri čemu svaka linija predstavlja drugačiji cgroup. Kontroleri za ove su navedeni pored broja.
* **Broj 1**: Takođe cgroups v1, ali isključivo za upravljačke svrhe (postavljen od strane, npr., systemd), i nedostaje kontroler.
* **Broj 0**: Predstavlja cgroups v2. Kontroleri nisu navedeni, i ova linija je ekskluzivna za sisteme koji koriste samo cgroups v2.
* **Imena su hijerarhijska**, slična putanjama datoteka, ukazujući na strukturu i odnos između različitih cgroups.
* **Imena poput /user.slice ili /system.slice** specificiraju kategorizaciju cgroups, pri čemu je user.slice obično za sesije prijave upravljane od strane systemd-a, a system.slice za sistemski servis.

Slika: ![Cgroup Filesystem](<../../../.gitbook/assets/image (1128).png>)

Ključne datoteke interfejsa za cgroups imaju prefiks **cgroup**. Datoteka **cgroup.procs**, koja se može pregledati standardnim komandama poput cat, nabraja procese unutar cgroup-a. Druga datoteka, **cgroup.threads**, uključuje informacije o nitima.

Slika: ![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

Cgroups koji upravljaju ljuskama obično obuhvataju dva kontrolera koji regulišu upotrebu memorije i broj procesa. Za interakciju s kontrolerom, treba se konsultovati datoteke koje nose prefiks kontrolera. Na primjer, **pids.current** bi se koristio za utvrđivanje broja niti u cgroup-u.

Slika: ![Cgroup Memory](<../../../.gitbook/assets/image (677).png>)

Indikacija **max** u vrijednosti sugerira odsustvo specifičnog ograničenja za cgroup. Međutim, zbog hijerarhijske prirode cgroups-a, ograničenja mogu biti nametnuta od strane cgroup-a na nižem nivou u hijerarhiji direktorijuma.

### Manipulacija i Kreiranje cgroups

Procesi se dodjeljuju cgroups-ima **upisivanjem njihovog ID procesa (PID) u datoteku `cgroup.procs`**. Za ovo su potrebne administratorske privilegije. Na primjer, za dodavanje procesa:
```bash
echo [pid] > cgroup.procs
```
Slično tome, **izmena cgroup atributa, poput postavljanja PID ograničenja**, vrši se upisivanjem željene vrednosti u odgovarajući fajl. Da biste postavili maksimum od 3.000 PID-ova za cgroup:
```bash
echo 3000 > pids.max
```
**Kreiranje novih cgroups** uključuje pravljenje nove poddirektorijuma unutar hijerarhije cgroup-a, što podstiče jezgro da automatski generiše neophodne interfejs fajlove. Iako se cgroups bez aktivnih procesa mogu ukloniti pomoću `rmdir`, budite svesni određenih ograničenja:

* **Procesi mogu biti smešteni samo u listne cgroups** (tj. najugnježdenije u hijerarhiji).
* **Cgroup ne može imati kontroler koji nedostaje u svom roditelju**.
* **Kontroleri za poddirektorijume moraju biti eksplicitno navedeni** u fajlu `cgroup.subtree_control`. Na primer, da biste omogućili kontrolere za CPU i PID u poddirektorijumu:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Root cgroup** je izuzetak od ovih pravila, omogućavajući direktno postavljanje procesa. Ovo se može koristiti za uklanjanje procesa iz systemd upravljanja.

**Pratiti upotrebu CPU-a** unutar cgroup-a je moguće putem datoteke `cpu.stat`, koja prikazuje ukupno utrošeno vreme CPU-a, korisno za praćenje upotrebe preko podprocesa servisa:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>Statistika upotrebe CPU-a prikazana u datoteci cpu.stat</p></figcaption></figure>

## Reference

* **Knjiga: Kako Linux funkcioniše, 3. izdanje: Šta svaki superkorisnik treba da zna, autor Brian Ward**
