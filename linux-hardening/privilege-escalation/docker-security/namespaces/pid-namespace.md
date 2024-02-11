# PID Naamruimte

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

Die PID (Process IDentifier) naamruimte is 'n kenmerk in die Linux-kernel wat proses-isolasie bied deur 'n groep prosesse te voorsien van hul eie stel unieke PIDs, afsonderlik van die PIDs in ander naamruimtes. Dit is veral nuttig in konteinering, waar proses-isolasie noodsaaklik is vir sekuriteit en hulpbronbestuur.

Wanneer 'n nuwe PID-naamruimte geskep word, word die eerste proses in daardie naamruimte toegewys aan PID 1. Hierdie proses word die "init" proses van die nuwe naamruimte en is verantwoordelik vir die bestuur van ander prosesse binne die naamruimte. Elke volgende proses wat binne die naamruimte geskep word, sal 'n unieke PID binne daardie naamruimte hê, en hierdie PIDs sal onafhanklik wees van PIDs in ander naamruimtes.

Vanuit die perspektief van 'n proses binne 'n PID-naamruimte kan dit slegs ander prosesse in dieselfde naamruimte sien. Dit is nie bewus van prosesse in ander naamruimtes nie, en dit kan nie met hulle interaksie hê deur gebruik te maak van tradisionele prosesbestuurstelsels (bv. `kill`, `wait`, ens.). Dit bied 'n vlak van isolasie wat help voorkom dat prosesse mekaar versteur.

### Hoe dit werk:

1. Wanneer 'n nuwe proses geskep word (bv. deur die `clone()` stelseloproep te gebruik), kan die proses toegewys word aan 'n nuwe of bestaande PID-naamruimte. **As 'n nuwe naamruimte geskep word, word die proses die "init" proses van daardie naamruimte**.
2. Die **kernel** handhaaf 'n **koppeling tussen die PIDs in die nuwe naamruimte en die ooreenstemmende PIDs** in die ouer-naamruimte (dit wil sê die naamruimte waaruit die nuwe naamruimte geskep is). Hierdie koppeling **stel die kernel in staat om PIDs te vertaal wanneer dit nodig is**, soos wanneer seine tussen prosesse in verskillende naamruimtes gestuur word.
3. **Prosesse binne 'n PID-naamruimte kan slegs ander prosesse in dieselfde naamruimte sien en daarmee interaksie hê**. Hulle is nie bewus van prosesse in ander naamruimtes nie, en hul PIDs is uniek binne hul naamruimte.
4. Wanneer 'n **PID-naamruimte vernietig word** (bv. wanneer die "init" proses van die naamruimte afsluit), **word alle prosesse binne daardie naamruimte beëindig**. Dit verseker dat alle hulpbronne wat met die naamruimte verband hou, behoorlik skoongemaak word.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` uitgevoer word sonder die `-f` opsie, word 'n fout aangetref as gevolg van die manier waarop Linux nuwe PID (Process ID) namespaces hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverduideliking**:
- Die Linux-kernel maak dit moontlik vir 'n proses om nuwe namespaces te skep deur die `unshare` stelseloproep te gebruik. Die proses wat die skepping van 'n nuwe PID-namespace inisieer (bekend as die "unshare" proses) betree egter nie die nuwe namespace nie; slegs sy kinderprosesse doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kinderprosesse in die oorspronklike PID-namespace.
- Die eerste kinderproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, veroorsaak dit die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kernel sal dan PID-toekenning in daardie namespace deaktiveer.

2. **Gevolg**:
- Die afsluiting van PID 1 in 'n nuwe namespace lei tot die skoonmaak van die `PIDNS_HASH_ADDING` vlag. Dit veroorsaak dat die `alloc_pid`-funksie nie 'n nuwe PID kan toeken wanneer 'n nuwe proses geskep word nie, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak `unshare` 'n nuwe proses na die skepping van die nuwe PID-namespace.
- Deur `%unshare -fp /bin/bash%` uit te voer, verseker jy dat die `unshare`-opdrag self PID 1 in die nuwe namespace word. `/bin/bash` en sy kinderprosesse word dan veilig binne hierdie nuwe namespace gehou, wat die vroeë afsluiting van PID 1 voorkom en normale PID-toekenning moontlik maak.

Deur te verseker dat `unshare` met die `-f` vlag uitgevoer word, word die nuwe PID-namespace korrek onderhou, sodat `/bin/bash` en sy subprosesse kan werk sonder om die geheue-toewysingsfout te ondervind.

</details>

Deur 'n nuwe instansie van die `/proc`-lêersisteem te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe bergnamespace 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespace** het.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Kyk watter namespace jou proses in is

Om te bepaal in watter namespace jou proses tans is, kan jy die volgende opdrag gebruik:

```bash
cat /proc/$$/status | grep NSpid
```

Hierdie opdrag sal die PID (Process ID) van die proses toon, tesame met die namespace waarin dit bestaan.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Vind alle PID-ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Let daarop dat die root-gebruiker van die aanvanklike (standaard) PID-naamruimte al die prosesse kan sien, selfs diegene in nuwe PID-naamruimtes. Dit is hoekom ons al die PID-naamruimtes kan sien.

### Betree 'n PID-naamruimte
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Wanneer jy binne 'n PID-namespace gaan vanaf die verstek-namespace, sal jy steeds al die prosesse kan sien. En die proses van daardie PID-ns sal die nuwe bash op die PID-ns kan sien.

Jy kan ook slegs **binne 'n ander proses-PID-namespace gaan as jy root is**. En jy **kan nie** **binne** 'n ander namespace **ingaan sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/pid`)

## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
