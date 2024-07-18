# DDexec / EverythingExec

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Konteks

In Linux moet 'n program as 'n lêer bestaan om uitgevoer te word, dit moet op een of ander manier toeganklik wees deur die lêersisteemhiërargie (dit is net hoe `execve()` werk). Hierdie lêer kan op die skyf of in ram (tmpfs, memfd) wees, maar jy het 'n lêerpad nodig. Dit maak dit baie maklik om te beheer wat op 'n Linux-sisteem uitgevoer word, dit maak dit maklik om bedreigings en aanvaller se gereedskap op te spoor of te voorkom dat hulle probeer om enigiets van hulle uit te voer (_bv._ nie toelaat dat onbevoorregte gebruikers uitvoerbare lêers oral plaas nie).

Maar hierdie tegniek is hier om dit alles te verander. As jy nie die proses wat jy wil begin nie kan begin nie... **dan kaap jy een wat reeds bestaan**.

Hierdie tegniek maak dit moontlik om **gewone beskermingstegnieke soos slegs-lees, noexec, lêernaam-witlysing, has-witlysing...** te omseil.

## Afhanklikhede

Die finale skrip hang af van die volgende gereedskap om te werk, hulle moet toeganklik wees in die sisteem wat jy aanval (standaard sal jy almal oral vind):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Die tegniek

Indien jy in staat is om arbitrair die geheue van 'n proses te wysig, kan jy dit oorneem. Dit kan gebruik word om 'n reeds bestaande proses te kap en dit met 'n ander program te vervang. Ons kan dit bereik deur die `ptrace()` stelseloproep te gebruik (wat vereis dat jy die vermoë het om stelseloproepe uit te voer of om gdb beskikbaar te hê op die stelsel) of, meer interessant, deur te skryf na `/proc/$pid/mem`.

Die lêer `/proc/$pid/mem` is 'n een-tot-een kartering van die hele adresruimte van 'n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat lees vanaf of skryf na hierdie lêer by 'n skuif `x` dieselfde is as lees vanaf of die inhoud by die virtuele adres `x` wysig.

Nou het ons vier basiese probleme om te hanteer:

* In die algemeen kan slegs die root en die program-eienaar van die lêer dit wysig.
* ASLR.
* As ons probeer om te lees of te skryf na 'n adres wat nie gekarteer is in die adresruimte van die program nie, sal ons 'n I/O-fout kry.

Hierdie probleme het oplossings wat, alhoewel hulle nie perfek is nie, goed is:

* Die meeste skilinterpreteerders maak die skepping van lêerbeskrywers moontlik wat dan deur kinderprosesse geërf sal word. Ons kan 'n fd skep wat na die `mem`-lêer van die skil wys met skryfregte... sodat kinderprosesse wat daardie fd gebruik, in staat sal wees om die skil se geheue te wysig.
* ASLR is nie eers 'n probleem nie, ons kan die skil se `maps`-lêer of enige ander van die procfs ondersoek om inligting oor die adresruimte van die proses te verkry.
* Dus moet ons oor die lêer `lseek()` beweeg. Vanuit die skil kan dit nie gedoen word tensy deur die berugte `dd` te gebruik nie.

### Meer inligting

Die stappe is relatief maklik en vereis geen soort van kundigheid om hulle te verstaan nie:

* Ontleed die binêre lêer wat ons wil hardloop en die laaier om uit te vind watter karterings hulle benodig. Skep dan 'n "skil"kode wat, breed gesproke, dieselfde stappe sal uitvoer as wat die kernel doen met elke oproep na `execve()`:
* Skep genoemde karterings.
* Lees die binêre lêers daarin.
* Stel toestemmings op.
* Inisieer uiteindelik die stok met die argumente vir die program en plaas die hulplêer (benodig deur die laaier).
* Spring in die laaier en laat dit die res doen (laai biblioteke wat deur die program benodig word).
* Kry van die `stelseloproep`-lêer die adres waarna die proses sal terugkeer na die stelseloproep wat dit uitvoer.
* Skryf daardie plek oor, wat uitvoerbaar sal wees, met ons skilkode (deur `mem` kan ons onskryfbare bladsye wysig).
* Gee die program wat ons wil hardloop aan die stdin van die proses (sal deur genoemde "skil"kode `lees()` word).
* Op hierdie punt is dit aan die laaier om die nodige biblioteke vir ons program te laai en daarin te spring.

**Kyk na die instrument op** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Daar is verskeie alternatiewe vir `dd`, een waarvan, `tail`, tans die verstekprogram is wat gebruik word om deur die `mem`-lêer te `lseek()` (wat die enigste doel was vir die gebruik van `dd`). Genoemde alternatiewe is:
```bash
tail
hexdump
cmp
xxd
```
Deur die veranderlike `SEEKER` in te stel, kan jy die gebruikte soeker verander, _bv._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Indien jy 'n ander geldige soeker vind wat nie geïmplementeer is in die skrips nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS` veranderlike in te stel:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blok dit, EDRs.

## Verwysings
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
