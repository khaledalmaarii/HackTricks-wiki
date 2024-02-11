# UTS-namespace

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

'n UTS (UNIX Time-Sharing System)-naamruimte is 'n Linux-kernelkenmerk wat **isolering van twee stelselidentifiseerders** bied: die **gasheernaam** en die **NIS** (Network Information Service) domeinnaam. Hierdie isolering maak dit moontlik dat elke UTS-naamruimte sy **eie onafhanklike gasheernaam en NIS-domeinnaam** het, wat veral nuttig is in konteinerisasiescenarios waar elke kontainer as 'n aparte stelsel met sy eie gasheernaam moet voorkom.

### Hoe dit werk:

1. Wanneer 'n nuwe UTS-naamruimte geskep word, begin dit met 'n **kopie van die gasheernaam en NIS-domeinnaam van sy ouernaamruimte**. Dit beteken dat die nuwe naamruimte by skepping **dieselfde identifiseerders as sy ouer deel**. Enige latere veranderinge aan die gasheernaam of NIS-domeinnaam binne die naamruimte sal egter nie ander naamruimtes beïnvloed nie.
2. Prosesse binne 'n UTS-naamruimte **kan die gasheernaam en NIS-domeinnaam verander** deur die `sethostname()` en `setdomainname()` stelseloproepe onderskeidelik te gebruik. Hierdie veranderinge is plaaslik vir die naamruimte en beïnvloed nie ander naamruimtes of die gasheerstelsel nie.
3. Prosesse kan tussen naamruimtes beweeg deur die `setns()` stelseloproep te gebruik of nuwe naamruimtes te skep deur die `unshare()` of `clone()` stelseloproepe met die `CLONE_NEWUTS` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die gasheernaam en NIS-domeinnaam wat met daardie naamruimte geassosieer word, te gebruik.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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
- Die probleem kan opgelos word deur die `-f`-opsie saam met `unshare` te gebruik. Hierdie opsie maak dit vir `unshare` moontlik om 'n nuwe proses te vork nadat die nuwe PID-namespace geskep is.
- Deur `%unshare -fp /bin/bash%` uit te voer, verseker jy dat die `unshare`-opdrag self PID 1 in die nuwe namespace word. `/bin/bash` en sy kinderprosesse word dan veilig binne hierdie nuwe namespace gehou, wat die voortydige afsluiting van PID 1 voorkom en normale PID-toekenning moontlik maak.

Deur te verseker dat `unshare` met die `-f`-vlag uitgevoer word, word die nuwe PID-namespace korrek onderhou, sodat `/bin/bash` en sy subprosesse kan werk sonder om die geheue-toewysingsfout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Kyk watter namespace jou proses in is

Om te bepaal in watter namespace jou proses tans is, kan jy die volgende opdrag gebruik:

```bash
cat /proc/$$/ns/uts
```

Hier is die betekenis van die opdrag:

- `cat`: Die opdrag om die inhoud van 'n lêer te vertoon.
- `/proc/$$/ns/uts`: Die pad na die UTS-namespace-lêer van die huidige proses.

Die uitset van hierdie opdrag sal die inode-nommer van die UTS-namespace-lêer wees.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Vind alle UTS-ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betree 'n UTS-namespace

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **toegang verkry tot 'n ander proses-namespace as jy root is**. En jy kan **nie** **toegang kry tot 'n ander namespace sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/uts`). 

### Verander gasheernaam
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
