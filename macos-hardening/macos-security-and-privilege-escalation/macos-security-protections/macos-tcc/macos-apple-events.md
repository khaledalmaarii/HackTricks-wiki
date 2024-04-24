# macOS Apple-gebeure

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

**Apple-gebeure** is 'n kenmerk in Apple se macOS wat programme in staat stel om met mekaar te kommunikeer. Dit is deel van die **Apple-gebeurbestuurder**, wat 'n komponent van die macOS-bedryfstelsel is wat verantwoordelik is vir die hanteer van interproseskommunikasie. Hierdie stelsel maak dit moontlik vir een toepassing om 'n boodskap na 'n ander toepassing te stuur om te versoek dat dit 'n spesifieke operasie uitvoer, soos die oopmaak van 'n lêer, die herwinning van data, of die uitvoering van 'n bevel.

Die mina-daemon is `/System/Library/CoreServices/appleeventsd` wat die diens `com.apple.coreservices.appleevents` registreer.

Elke toepassing wat gebeure kan ontvang, sal met hierdie daemon kontroleer deur sy Apple-gebeur Mach-poort te voorsien. En wanneer 'n toepassing 'n gebeurtenis daarna wil stuur, sal die toepassing hierdie poort van die daemon aanvra.

Ingeslote toepassings vereis voorregte soos `allow appleevent-send` en `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` om in staat te wees om gebeure te stuur. Let daarop dat toekennings soos `com.apple.security.temporary-exception.apple-events` kan beperk wie toegang het om gebeure te stuur wat toekennings soos `com.apple.private.appleevents` benodig.

{% hint style="success" %}
Dit is moontlik om die omgewingsveranderlike **`AEDebugSends`** te gebruik om inligting oor die gestuurde boodskap te log:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
