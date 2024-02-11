# Monteer Naamruimte

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

'n Monteer-naamruimte is 'n Linux-kernelkenmerk wat isolasie van die lêerstelsel-monteerpunte wat deur 'n groep prosesse gesien word, bied. Elke monteer-naamruimte het sy eie stel lêerstelsel-monteerpunte, en **veranderings aan die monteerpunte in een naamruimte beïnvloed nie ander naamruimtes nie**. Dit beteken dat prosesse wat in verskillende monteer-naamruimtes loop, verskillende sienings van die lêerstelsel-hierargie kan hê.

Monteer-naamruimtes is veral nuttig in konteinerisering, waar elke konteiner sy eie lêerstelsel en konfigurasie moet hê, geïsoleer van ander konteinere en die gasheerstelsel.

### Hoe dit werk:

1. Wanneer 'n nuwe monteer-naamruimte geskep word, word dit geïnisialiseer met 'n **kopie van die monteerpunte van sy ouer-naamruimte**. Dit beteken dat, by skepping, die nuwe naamruimte dieselfde siening van die lêerstelsel deel as sy ouer. Tog sal enige volgende veranderinge aan die monteerpunte binne die naamruimte nie die ouer of ander naamruimtes beïnvloed nie.
2. Wanneer 'n proses 'n monteerpunt binne sy naamruimte wysig, soos die monteer of ontmonteer van 'n lêerstelsel, is die **verandering plaaslik in daardie naamruimte** en beïnvloed dit nie ander naamruimtes nie. Dit maak dit moontlik dat elke naamruimte sy eie onafhanklike lêerstelsel-hierargie het.
3. Prosesse kan tussen naamruimtes beweeg deur die `setns()`-sisteemaanroep te gebruik, of nuwe naamruimtes skep deur die `unshare()`- of `clone()`-sisteemaanroep met die `CLONE_NEWNS`-vlag te gebruik. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die monteerpunte wat met daardie naamruimte geassosieer word, te gebruik.
4. **Lêerbeskrywers en inodes word oor naamruimtes gedeel**, wat beteken dat as 'n proses in een naamruimte 'n oop lêerbeskrywer het wat na 'n lêer wys, kan dit **daardie lêerbeskrywer** aan 'n proses in 'n ander naamruimte oordra, en **beide prosesse sal toegang tot dieselfde lêer hê**. Die lêer se pad mag egter nie dieselfde wees in beide naamruimtes as gevolg van verskille in monteerpunte nie.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc`-lêersisteem te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe berg-namespace 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespace** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` uitgevoer word sonder die `-f`-opsie, word 'n fout aangetref as gevolg van die manier waarop Linux nuwe PID (Proses-ID)-namespaces hanteer. Die sleuteldetails en die oplossing word hieronder uiteengesit:

1. **Probleemverduideliking**:
- Die Linux-kernel maak dit moontlik vir 'n proses om nuwe namespaces te skep deur die `unshare`-sisteemaanroep te gebruik. Die proses wat die skepping van 'n nuwe PID-namespace inisieer (bekend as die "unshare"-proses) betree egter nie die nuwe namespace nie; slegs sy kinderprosesse doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kinderprosesse in die oorspronklike PID-namespace.
- Die eerste kinderproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, veroorsaak dit die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weesouerprosesse aan te neem. Die Linux-kernel sal dan PID-toekenning in daardie namespace deaktiveer.

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
cat /proc/$$/mountinfo | grep "ns"
```

Hierdie opdrag sal die `mountinfo`-lêer van jou huidige proses (`$$`) lees en die reëls filter wat die woord "ns" bevat. Die uitset sal die namespace-identifiseerders vir jou proses toon.
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Vind alle Monteer-ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betree binne 'n Monteer-namespace

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **toegang verkry tot 'n ander proses-namespace as jy root is**. En jy kan **nie** **toegang verkry** tot 'n ander namespace **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/mnt`).

Omdat nuwe bergings slegs binne die namespace toeganklik is, is dit moontlik dat 'n namespace sensitiewe inligting bevat wat slegs daarvandaan toeganklik is.

### Monteer iets
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
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
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
