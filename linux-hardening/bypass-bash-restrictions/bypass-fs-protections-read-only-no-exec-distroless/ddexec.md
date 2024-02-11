# DDexec / AllesUitvoer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Konteks

In Linux moet 'n program as 'n lêer bestaan om uitgevoer te word, dit moet op een of ander manier toeganklik wees deur die lêersisteemhiërargie (dit is net hoe `execve()` werk). Hierdie lêer kan op die skyf of in die RAM wees (tmpfs, memfd), maar jy het 'n lêerpad nodig. Dit maak dit baie maklik om te beheer wat op 'n Linux-stelsel uitgevoer word, dit maak dit maklik om bedreigings en aanvallers se gereedskap op te spoor of te voorkom dat hulle enigiets van hulle probeer uitvoer (_bv._ om onbevoorregte gebruikers nie toe te laat om uitvoerbare lêers oral te plaas nie).

Maar hierdie tegniek is hier om dit alles te verander. As jy nie die proses kan begin wat jy wil nie... **dan kaap jy een wat al bestaan**.

Hierdie tegniek stel jou in staat om algemene beskermingstegnieke soos slegs-lees, geen-uitvoer, lêernaam-witlysing, has-witlysing te **omseil**.

## Afhanklikhede

Die finale skripsie is afhanklik van die volgende gereedskap om te werk, hulle moet toeganklik wees in die stelsel wat jy aanval (standaard sal jy almal oral vind):
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

As jy arbitrêr die geheue van 'n proses kan wysig, kan jy dit oorneem. Dit kan gebruik word om 'n bestaande proses te kap en te vervang met 'n ander program. Ons kan dit bereik deur óf die `ptrace()` syscall te gebruik (wat vereis dat jy die vermoë het om syscalls uit te voer of om gdb beskikbaar te hê op die stelsel) óf, meer interessant, deur te skryf na `/proc/$pid/mem`.

Die lêer `/proc/$pid/mem` is 'n een-tot-een kartering van die hele adresruimte van 'n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat lees vanaf of skryf na hierdie lêer by 'n offset `x` dieselfde is as om te lees vanaf of die inhoud by die virtuele adres `x` te wysig.

Nou, ons het vier basiese probleme om te hanteer:

* In die algemeen mag slegs die root en die program-eienaar van die lêer dit wysig.
* ASLR.
* As ons probeer lees of skryf na 'n adres wat nie in die adresruimte van die program gekaart is nie, sal ons 'n I/O-fout kry.

Hierdie probleme het oplossings wat, alhoewel hulle nie perfek is nie, goed is:

* Die meeste skulduitvoerders maak die skepping van lêerbeskrywers moontlik wat dan deur kinderprosesse geërf sal word. Ons kan 'n fd skep wat na die `mem`-lêer van die skulduitvoerder wys met skryfregte... sodat kinderprosesse wat daardie fd gebruik, die geheue van die skulduitvoerder kan wysig.
* ASLR is nie eers 'n probleem nie, ons kan die `maps`-lêer van die skulduitvoerder of enige ander van die procfs ondersoek om inligting oor die adresruimte van die proses te verkry.
* Ons moet dus `lseek()` oor die lêer doen. Vanuit die skulduitvoerder kan dit nie gedoen word tensy ons die berugte `dd` gebruik nie.

### In meer detail

Die stappe is relatief maklik en vereis geen spesifieke kundigheid om hulle te verstaan nie:

* Ontleed die binêre lêer wat ons wil uitvoer en die laaier om uit te vind watter karterings hulle nodig het. Skep dan 'n "skulp"kode wat, in breë terme, dieselfde stappe sal uitvoer as wat die kernel doen by elke oproep na `execve()`:
* Skep genoemde karterings.
* Lees die binêre lêers daarin.
* Stel toestemmings op.
* Inisialiseer uiteindelik die stapel met die argumente vir die program en plaas die bykomende vektor (wat deur die laaier benodig word).
* Spring in die laaier en laat dit die res doen (laai biblioteke wat deur die program benodig word).
* Kry die adres waarheen die proses sal terugkeer na die syscall wat dit uitvoer.
* Skryf daardie plek, wat uitvoerbaar sal wees, oor met ons skulpkode (deur `mem` kan ons onskryfbare bladsye wysig).
* Gee die program wat ons wil uitvoer aan die stdin van die proses (sal deur genoemde "skulp"kode `read()` word).
* Op hierdie punt is dit aan die laaier om die nodige biblioteke vir ons program te laai en daarin te spring.

**Kyk na die instrument in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Daar is verskeie alternatiewe vir `dd`, waarvan een, `tail`, tans die verstekprogram is wat gebruik word om deur die `mem`-lêer te `lseek()` (wat die enigste doel was om `dd` te gebruik). Genoemde alternatiewe is:
```bash
tail
hexdump
cmp
xxd
```
Deur die veranderlike `SEEKER` te stel, kan jy die soeker wat gebruik word, verander, _bv._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
As jy 'n ander geldige soeker vind wat nie in die skripsie geïmplementeer is nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS` veranderlike in te stel:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blok dit, EDRs.

## Verwysings
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
