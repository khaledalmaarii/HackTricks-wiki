# Netwerk-namespace

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

'n Netwerk-namespace is 'n Linux-kernelkenmerk wat isolasie van die netwerkstapel bied, wat **elke netwerk-namespace in staat stel om sy eie onafhanklike netwerk-konfigurasie**, koppelvlakke, IP-adresse, roetetabelle en vuremuur-reëls te hê. Hierdie isolasie is nuttig in verskeie scenario's, soos konteinerisasie, waar elke konteiner sy eie netwerk-konfigurasie moet hê, onafhanklik van ander konteinere en die gasheerstelsel.

### Hoe dit werk:

1. Wanneer 'n nuwe netwerk-namespace geskep word, begin dit met 'n **volledig geïsoleerde netwerkstapel**, met **geen netwerkkoppelvlakke** behalwe die lusback-koppelvlak (lo). Dit beteken dat prosesse wat in die nuwe netwerk-namespace loop, nie standaard kan kommunikeer met prosesse in ander namespaces of die gasheerstelsel nie.
2. **Virtuele netwerkkoppelvlakke**, soos veth-pare, kan geskep word en tussen netwerk-namespaces geskuif word. Dit maak dit moontlik om netwerkverbinding tussen namespaces of tussen 'n namespace en die gasheerstelsel te vestig. Byvoorbeeld, een einde van 'n veth-paar kan in 'n konteiner se netwerk-namespace geplaas word, en die ander einde kan aangesluit word op 'n **brug** of 'n ander netwerkkoppelvlak in die gasheer-namespace, wat netwerkverbinding aan die konteiner bied.
3. Netwerkkoppelvlakke binne 'n namespace kan hul **eie IP-adresse, roetetabelle en vuremuur-reëls** hê, onafhanklik van ander namespaces. Dit maak dit moontlik vir prosesse in verskillende netwerk-namespaces om verskillende netwerk-konfigurasies te hê en te werk asof hulle op afsonderlike netwerkstelsels loop.
4. Prosesse kan tussen namespaces beweeg deur die `setns()`-sisteemaanroep te gebruik, of nuwe namespaces kan geskep word deur die `unshare()`- of `clone()`-sisteemaanroep met die `CLONE_NEWNET`-vlag te gebruik. Wanneer 'n proses na 'n nuwe namespace beweeg of een skep, sal dit begin om die netwerk-konfigurasie en koppelvlakke wat met daardie namespace geassosieer is, te gebruik.

## Laboratorium:

### Skep verskillende Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
# Run ifconfig or ip -a
```
### &#x20;Kyk watter namespace jou proses in is

Om te bepaal in watter namespace jou proses tans is, kan jy die volgende opdrag gebruik:

```bash
ls -l /proc/$$/ns
```

Hier is die betekenis van die vlags in die uitset:

- `mnt`: Die bergingsnamespace
- `pid`: Die prosesnamespace
- `net`: Die netwerknamespace
- `ipc`: Die interproseskommunikasienamespace
- `uts`: Die stelselidentiteitsnamespace
- `user`: Die gebruikersnamespace

As jy die uitset van die opdrag sien, kan jy bepaal in watter namespace jou proses tans is deur te kyk na die simboliese skakels wat na die aktiewe namespaces verwys.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Vind alle Netwerk namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Betree 'n Netwerk-namespace

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **toegang verkry tot 'n ander proses-namespace as jy root is**. En jy **kan nie** **toegang kry** tot 'n ander namespace **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/net`).

## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
