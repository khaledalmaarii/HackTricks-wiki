# Tyd-Namespace

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

Die tyd-namespace in Linux maak dit moontlik om per-namespace verskuiwings na die stelsel se monotone en opstarttydklokke te hê. Dit word algemeen gebruik in Linux-houers om die datum/tyd binne 'n houer te verander en klokke aan te pas nadat dit van 'n kontrolepunt of afskakeling herstel is.

## Laboratorium:

### Skep verskillende Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc`-lêersisteem te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe berg-namespace 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespace** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` uitgevoer word sonder die `-f`-opsie, word 'n fout aangetref as gevolg van die manier waarop Linux nuwe PID (Proses-ID) namespaces hanteer. Die sleuteldetails en die oplossing word hieronder uiteengesit:

1. **Probleemverduideliking**:
- Die Linux-kernel maak dit moontlik vir 'n proses om nuwe namespaces te skep deur die `unshare`-stelseloproep te gebruik. Die proses wat die skepping van 'n nuwe PID-namespace inisieer (bekend as die "unshare"-proses) betree egter nie die nuwe namespace nie; slegs sy kinderprosesse doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kinderprosesse in die oorspronklike PID-namespace.
- Die eerste kinderproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, veroorsaak dit die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kernel sal dan PID-toekenning in daardie namespace deaktiveer.

2. **Gevolg**:
- Die afsluiting van PID 1 in 'n nuwe namespace lei tot die skoonmaak van die `PIDNS_HASH_ADDING`-vlag. Dit veroorsaak dat die `alloc_pid`-funksie misluk om 'n nuwe PID toe te ken wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" -fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f`-opsie saam met `unshare` te gebruik. Hierdie opsie maak `unshare` 'n nuwe proses na die skepping van die nuwe PID-namespace.
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
cat /proc/$$/ns/pid
```

Hier is 'pid' die identifikasienommer van die proses waarvoor jy die namespace wil bepaal.
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Vind alle Tyd namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Betree binne 'n Tyd-namespace

Om binne 'n Tyd-namespace in te gaan, kan jy die volgende stappe volg:

1. Identifiseer die PID van die proses waarin jy wil binnekom.
2. Voer die volgende opdrag uit om die proses binne die Tyd-namespace te betree:

```bash
nsenter --time=/proc/<PID>/ns/time /bin/bash
```

Vervang `<PID>` met die regte proses-ID.

Nadat jy die opdrag uitgevoer het, sal jy binne die Tyd-namespace wees en kan jy die funksies en hulpbronne binne daardie namespace manipuleer.
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **toegang verkry tot 'n ander proses-namespace as jy root is**. En jy **kan nie** **toegang kry** tot 'n ander namespace **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/net`).

## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
* [https://www.phoronix.com/news/Linux-Time-Namespace-Coming](https://www.phoronix.com/news/Linux-Time-Namespace-Coming)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
