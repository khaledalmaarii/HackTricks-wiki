# IPC-namespace

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

'n IPC (Inter-Process Communication)-naamruimte is 'n Linux-kernelkenmerk wat **afsondering** van System V IPC-voorwerpe bied, soos boodskaprye, gedeelde geheue-segmente en semafore. Hierdie afsondering verseker dat prosesse in **verskillende IPC-naamruimtes nie direk toegang tot of wysiging van mekaar se IPC-voorwerpe kan hê nie**, wat 'n addisionele laag van veiligheid en privaatheid tussen prosesgroepe bied.

### Hoe dit werk:

1. Wanneer 'n nuwe IPC-naamruimte geskep word, begin dit met 'n **volledig afgesonderde stel System V IPC-voorwerpe**. Dit beteken dat prosesse wat in die nuwe IPC-naamruimte loop, nie standaard toegang tot of inmenging met die IPC-voorwerpe in ander naamruimtes of die gasheerstelsel kan hê nie.
2. IPC-voorwerpe wat binne 'n naamruimte geskep word, is slegs sigbaar en **toeganklik vir prosesse binne daardie naamruimte**. Elke IPC-voorwerp word geïdentifiseer deur 'n unieke sleutel binne sy naamruimte. Alhoewel die sleutel dieselfde kan wees in verskillende naamruimtes, is die voorwerpe self afgesonderd en kan nie oor naamruimtes heen toegang verkry nie.
3. Prosesse kan tussen naamruimtes beweeg deur die `setns()`-sisteemaanroep te gebruik of nuwe naamruimtes te skep deur die `unshare()`- of `clone()`-sisteemaanroep met die `CLONE_NEWIPC`-vlag te gebruik. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, begin dit die IPC-voorwerpe wat met daardie naamruimte geassosieer word, gebruik.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc`-lêersisteem te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe berg-namespace 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespace** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` uitgevoer word sonder die `-f`-opsie, word 'n fout aangetref as gevolg van die manier waarop Linux nuwe PID (Proses-ID) namespaces hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverduideliking**:
- Die Linux-kernel maak dit moontlik vir 'n proses om nuwe namespaces te skep deur die `unshare`-sisteemaanroep te gebruik. Die proses wat die skepping van 'n nuwe PID-namespace inisieer (bekend as die "unshare"-proses) betree egter nie die nuwe namespace nie; slegs sy kinderprosesse doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kinderprosesse in die oorspronklike PID-namespace.
- Die eerste kinderproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, veroorsaak dit die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weesouerprosesse aan te neem. Die Linux-kernel sal dan PID-toekenning in daardie namespace deaktiveer.

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
### &#x20;Kyk watter namespace jou proses in is

Om te bepaal in watter namespace jou proses tans is, kan jy die volgende opdrag gebruik:

```bash
ls -l /proc/$$/ns/ipc
```

Hier is die betekenis van die opdrag:

- `ls -l`: Gee 'n gedetailleerde lys van die spesifiseerde lêer.
- `/proc/$$/ns/ipc`: Die pad na die IPC-namespace van die huidige proses.

As die uitset van die opdrag 'n simboliese skakel na 'n lêer in die `/proc`-sisteem is, beteken dit dat jou proses in daardie spesifieke namespace is.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Vind alle IPC-ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betree binne 'n IPC-namespace

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **toegang verkry tot 'n ander proses-namespace as jy root is**. En jy kan **nie** **toegang kry tot 'n ander namespace sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/net`).

### Skep IPC-voorwerp
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
