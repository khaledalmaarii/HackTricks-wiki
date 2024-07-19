# Netwerk Naamruimte

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basiese Inligting

'n Netwerk naamruimte is 'n Linux-kernfunksie wat isolasie van die netwerkstapel bied, wat toelaat dat **elke netwerk naamruimte sy eie onafhanklike netwerk konfigurasie**, interfaces, IP adresse, routeringstabelle, en firewall reëls kan hê. Hierdie isolasie is nuttig in verskeie scenario's, soos containerisering, waar elke container sy eie netwerk konfigurasie moet hê, onafhanklik van ander containers en die gasheerstelsel.

### Hoe dit werk:

1. Wanneer 'n nuwe netwerk naamruimte geskep word, begin dit met 'n **heeltemal geïsoleerde netwerkstapel**, met **geen netwerkinterfaces** behalwe vir die loopback interface (lo). Dit beteken dat prosesse wat in die nuwe netwerk naamruimte loop nie met prosesse in ander naamruimtes of die gasheerstelsel kan kommunikeer nie, behalwe as 'n standaard.
2. **Virtuele netwerkinterfaces**, soos veth pare, kan geskep en tussen netwerk naamruimtes beweeg word. Dit maak dit moontlik om netwerkverbinding te vestig tussen naamruimtes of tussen 'n naamruimte en die gasheerstelsel. Byvoorbeeld, een kant van 'n veth paar kan in 'n container se netwerk naamruimte geplaas word, en die ander kant kan aan 'n **brug** of 'n ander netwerkinterface in die gasheer naamruimte gekoppel word, wat netwerkverbinding aan die container bied.
3. Netwerkinterfaces binne 'n naamruimte kan hul **eie IP adresse, routeringstabelle, en firewall reëls** hê, onafhanklik van ander naamruimtes. Dit laat prosesse in verskillende netwerk naamruimtes toe om verskillende netwerk konfigurasies te hê en te werk asof hulle op aparte netwerkstelsels loop.
4. Prosesse kan tussen naamruimtes beweeg deur die `setns()` stelselkroep te gebruik, of nuwe naamruimtes te skep deur die `unshare()` of `clone()` stelselkroepe met die `CLONE_NEWNET` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die netwerk konfigurasie en interfaces wat met daardie naamruimte geassosieer is, te gebruik.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:
- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) betree egter nie die nuwe naamruimte nie; slegs sy kindproses doen.
- Om `%unshare -p /bin/bash%` te loop, begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, aktiveer dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:
- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Om `%unshare -fp /bin/bash%` uit te voer, verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse kan werk sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Vind alle Netwerk name ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Gaan binne 'n Netwerk-namespace in
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **in** 'n ander naamruimte **ingaan sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/net`).

## Verwysings
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
