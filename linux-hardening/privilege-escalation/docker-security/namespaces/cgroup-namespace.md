# CGroup Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

'n cgroup namespace is 'n Linux-kernfunksie wat **isolasie van cgroup hiërargieë vir prosesse wat binne 'n namespace loop** bied. Cgroups, kort vir **kontrole groepe**, is 'n kernfunksie wat toelaat dat prosesse in hiërargiese groepe georganiseer word om **grense op stelselhulpbronne** soos CPU, geheue en I/O te bestuur en af te dwing.

Terwyl cgroup namespaces nie 'n aparte namespace tipe is soos die ander wat ons vroeër bespreek het nie (PID, mount, netwerk, ens.), is hulle verwant aan die konsep van namespace-isolasie. **Cgroup namespaces virtualiseer die uitsig van die cgroup hiërargie**, sodat prosesse wat binne 'n cgroup namespace loop 'n ander uitsig van die hiërargie het in vergelyking met prosesse wat in die gasheer of ander namespaces loop.

### How it works:

1. Wanneer 'n nuwe cgroup namespace geskep word, **begin dit met 'n uitsig van die cgroup hiërargie gebaseer op die cgroup van die skepende proses**. Dit beteken dat prosesse wat in die nuwe cgroup namespace loop slegs 'n subset van die hele cgroup hiërargie sal sien, beperk tot die cgroup subboom wat op die skepende proses se cgroup gegrond is.
2. Prosesse binne 'n cgroup namespace sal **hulle eie cgroup as die wortel van die hiërargie sien**. Dit beteken dat, vanuit die perspektief van prosesse binne die namespace, hulle eie cgroup as die wortel verskyn, en hulle kan nie cgroups buite hulle eie subboom sien of toegang daartoe kry nie.
3. Cgroup namespaces bied nie direk isolasie van hulpbronne nie; **hulle bied slegs isolasie van die cgroup hiërargie uitsig**. **Hulpbronbeheer en isolasie word steeds afgedwing deur die cgroup** subsisteme (bv., cpu, geheue, ens.) self.

For more information about CGroups check:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:
- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe naamruimte in nie; slegs sy kindproses gaan.
- Om `%unshare -p /bin/bash%` uit te voer, begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, veroorsaak dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:
- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Om `%unshare -fp /bin/bash%` uit te voer, verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse funksioneer sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Vind alle CGroup-namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Gaan binne in 'n CGroup naamruimte
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **in** 'n ander naamruimte **ingaan sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/cgroup`).

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
