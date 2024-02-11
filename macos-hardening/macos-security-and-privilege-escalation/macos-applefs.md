# macOS AppleFS

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Apple Propietary-lêersisteem (APFS)

**Apple-lêersisteem (APFS)** is 'n moderne lêersisteem wat ontwerp is om die Hierargiese Lêersisteem Plus (HFS+) te vervang. Die ontwikkeling daarvan is gedryf deur die behoefte aan **verbeterde prestasie, sekuriteit en doeltreffendheid**.

Enkele noemenswaardige kenmerke van APFS sluit in:

1. **Spasie-deling**: APFS maak dit moontlik dat verskeie volumes die **gelyke onderliggende vry stoorplek** op 'n enkele fisiese toestel deel. Dit maak doeltreffender spasiebenutting moontlik, aangesien die volumes dinamies kan groei en krimp sonder die nodigheid van handmatige vergroting of herverdeling.
1. Dit beteken, in vergelyking met tradisionele partisies in lêerdiske, **dat in APFS verskillende partisies (volumes) al die skyfspasie deel**, terwyl 'n gewone partisie gewoonlik 'n vaste grootte gehad het.
2. **Momentopnames**: APFS ondersteun die **skep van momentopnames**, wat **alleen-lees**, punt-in-tyd instansies van die lêersisteem is. Momentopnames maak doeltreffende rugsteun en maklike stelselherstel moontlik, aangesien hulle minimaal bykomende stoorplek gebruik en vinnig geskep of teruggesit kan word.
3. **Klone**: APFS kan **lêer- of gidsklone skep wat dieselfde stoorplek as die oorspronklike deel** totdat óf die kloon óf die oorspronklike lêer gewysig word. Hierdie kenmerk bied 'n doeltreffende manier om kopieë van lêers of gidse te skep sonder om die stoorplek te dupliseer.
4. **Versleuteling**: APFS ondersteun **volledige skyfversleuteling** asook per-lêer en per-gids versleuteling, wat data-sekuriteit in verskillende gevalle verbeter.
5. **Kragonderbrekingbeskerming**: APFS gebruik 'n **kopie-op-skryf metadata-skema wat verseker dat die lêersisteem konsistent bly**, selfs in gevalle van skielike kragonderbreking of stelselonderbrekings, wat die risiko van datakorrupsie verminder.

Oor die algemeen bied APFS 'n meer moderne, buigsame en doeltreffende lêersisteem vir Apple-toestelle, met die fokus op verbeterde prestasie, betroubaarheid en sekuriteit.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Die `Data` volume is gemonteer in **`/System/Volumes/Data`** (jy kan dit nagaan met `diskutil apfs list`).

Die lys van firmlinks kan gevind word in die **`/usr/share/firmlinks`** lêer.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
Aan die **linkerkant** is die gidspad op die **Stelselvolume**, en aan die **regterkant** is die gidspad waar dit op die **Datavolume** afbeeld. So, `/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
