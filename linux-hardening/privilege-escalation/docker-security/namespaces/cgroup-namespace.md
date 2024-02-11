# CGroup-namespace

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

'n Cgroup-namespace is 'n Linux-kernelkenmerk wat **afsondering van cgroup-hierargieë vir prosesse wat binne 'n namespace loop, bied**. Cgroups, afkorting vir **beheergroepe**, is 'n kernelkenmerk wat dit moontlik maak om prosesse in hiërargiese groepe te organiseer om **grense op stelselhulpbronne** soos CPU, geheue en I/O te bestuur en af te dwing.

Alhoewel cgroup-namespaces nie 'n aparte tipe namespace is soos die ander wat ons vroeër bespreek het (PID, berg, netwerk, ens.), is hulle verwant aan die konsep van namespace-afsondering. **Cgroup-namespaces virtualiseer die siening van die cgroup-hierargie**, sodat prosesse wat binne 'n cgroup-namespace loop, 'n ander siening van die hierargie het in vergelyking met prosesse wat in die gasheer of ander namespaces loop.

### Hoe dit werk:

1. Wanneer 'n nuwe cgroup-namespace geskep word, **begin dit met 'n siening van die cgroup-hierargie gebaseer op die cgroup van die skeppende proses**. Dit beteken dat prosesse wat in die nuwe cgroup-namespace loop, slegs 'n subset van die volledige cgroup-hierargie sal sien, beperk tot die cgroup-subboom wat wortel by die skeppende proses se cgroup.
2. Prosesse binne 'n cgroup-namespace sal **hul eie cgroup as die wortel van die hierargie sien**. Dit beteken dat, vanuit die perspektief van prosesse binne die namespace, hul eie cgroup as die wortel voorkom, en hulle kan nie cgroups buite hul eie subboom sien of toegang daartoe verkry nie.
3. Cgroup-namespaces bied nie direkte afsondering van hulpbronne nie; **hulle bied slegs afsondering van die siening van die cgroup-hierargie**. **Hulpbronbeheer en afsondering word steeds afgedwing deur die cgroup-subsisteme (bv. cpu, geheue, ens.) self.

Vir meer inligting oor CGroups, kyk na:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratorium:

### Skep verskillende Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc`-lêersisteem te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe berg-namespace 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespace** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` uitgevoer word sonder die `-f`-opsie, word 'n fout aangetref as gevolg van die manier waarop Linux nuwe PID (Proses-ID) namespaces hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverduideliking**:
- Die Linux-kernel maak dit moontlik vir 'n proses om nuwe namespaces te skep deur die `unshare`-sisteemaanroep te gebruik. Die proses wat die skepping van 'n nuwe PID-namespace inisieer (bekend as die "unshare"-proses) betree egter nie die nuwe namespace nie; slegs sy kinderprosesse doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kinderprosesse in die oorspronklike PID-namespace.
- Die eerste kinderproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, veroorsaak dit die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kernel sal dan PID-toekenning in daardie namespace deaktiveer.

2. **Gevolg**:
- Die afsluiting van PID 1 in 'n nuwe namespace lei tot die skoonmaak van die `PIDNS_HASH_ADDING`-vlag. Dit veroorsaak dat die `alloc_pid`-funksie nie 'n nuwe PID kan toeken by die skep van 'n nuwe proses nie, wat die "Kan nie geheue toewys nie" -fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f`-opsie saam met `unshare` te gebruik. Hierdie opsie maak `unshare` 'n nuwe proses na die skepping van die nuwe PID-namespace.
- Deur `%unshare -fp /bin/bash%` uit te voer, verseker jy dat die `unshare`-opdrag self PID 1 in die nuwe namespace word. `/bin/bash` en sy kinderprosesse word dan veilig binne hierdie nuwe namespace gehou, wat die voortydige afsluiting van PID 1 voorkom en normale PID-toekenning moontlik maak.

Deur te verseker dat `unshare` met die `-f`-vlag uitgevoer word, word die nuwe PID-namespace korrek onderhou, sodat `/bin/bash` en sy subprosesse kan werk sonder om die geheue-toewysingsfout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Kyk watter namespace jou proses is

Om te bepaal in watter namespace jou proses is, kan jy die volgende opdrag gebruik:

```bash
cat /proc/$$/cgroup
```

Hierdie opdrag sal die inhoud van die `cgroup`-lêer vir jou huidige proses (`$$`) vertoon. Die `cgroup`-lêer bevat inligting oor die groepe waaraan jou proses behoort, insluitend die namespace-inligting.

As jy die uitset van hierdie opdrag sien, sal jy 'n pad sien wat die woord "namespace" bevat. Byvoorbeeld:

```
11:memory:/user.slice/user-1000.slice/session-1.scope
10:devices:/user.slice/user-1000.slice/session-1.scope
9:pids:/user.slice/user-1000.slice/session-1.scope
8:cpu,cpuacct:/user.slice/user-1000.slice/session-1.scope
7:net_cls,net_prio:/user.slice/user-1000.slice/session-1.scope
6:freezer:/user.slice/user-1000.slice/session-1.scope
5:perf_event:/user.slice/user-1000.slice/session-1.scope
4:blkio:/user.slice/user-1000.slice/session-1.scope
3:rdma:/
2:cpuset:/user.slice/user-1000.slice/session-1.scope
1:name=systemd:/user.slice/user-1000.slice/session-1.scope
```

In hierdie voorbeeld is die proses in die `session-1.scope`-namespace.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Vind alle CGroup-ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Betree 'n CGroup-namespace

Om toegang te verkry tot 'n CGroup-namespace, kan jy die volgende stappe volg:

1. Identifiseer die proses ID (PID) van die teikenproses waarin jy wil binnekom.
2. Voer die volgende opdrag uit om die PID van die proses te bekom:
   ```
   ps aux | grep <prosesnaam>
   ```
3. Identifiseer die CGroup-vlak waarin die proses bestaan. Jy kan dit doen deur die inhoud van die `/proc/<PID>/cgroup`-lêer te ondersoek.
4. Voer die volgende opdrag uit om binne die CGroup-namespace van die proses in te gaan:
   ```
   nsenter -t <PID> -m
   ```
   Hiermee sal jy binne die CGroup-namespace van die proses ingaan en toegang verkry tot die verbandhoudende hulpbronne en beperkings.

Dit is belangrik om te onthou dat jy oor voldoende bevoorregting moet beskik om hierdie stappe uit te voer.
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **toegang verkry tot 'n ander proses-namespace as jy root is**. En jy **kan nie** **toegang kry** tot 'n ander namespace **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/cgroup`).

## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
