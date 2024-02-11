# macOS Apple-skripsies

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Apple-skripsies

Dit is 'n skripsietaal wat gebruik word vir taakoutomatisering **deur te skakel met afgeleë prosesse**. Dit maak dit baie maklik om **ander prosesse te vra om sekere aksies uit te voer**. **Malware** kan hierdie funksies misbruik om funksies wat deur ander prosesse uitgevoer word, te misbruik.\
Byvoorbeeld, 'n malware kan **willekeurige JS-kode inspuit in blaaier-geopende bladsye**. Of **outomaties kliek** op toestemmings wat aan die gebruiker gevra word.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier is 'n paar voorbeelde: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Vind meer inligting oor malware wat Apple-scripts gebruik [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple-scripts kan maklik "**gekompileer**" word. Hierdie weergawes kan maklik "**gedekompileer**" word met `osadecompile`.

Hierdie skripte kan egter ook uitgevoer word as "Slegs lees" (via die "Uitvoer..." opsie):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
En in hierdie geval kan die inhoud selfs nie met `osadecompile` gedekomponeer word nie.

Daar is egter steeds gereedskap wat gebruik kan word om hierdie soort uitvoerbare lêers te verstaan, [**lees hierdie navorsing vir meer inligting**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Die gereedskap [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) met [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) sal baie nuttig wees om te verstaan hoe die skrip werk.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
