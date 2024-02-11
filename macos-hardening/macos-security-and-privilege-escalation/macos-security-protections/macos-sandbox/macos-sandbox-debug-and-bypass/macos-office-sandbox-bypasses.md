# macOS Office Sandboksontduiking

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

### Woordsandboksontduiking via Lancering Agente

Die toepassing maak gebruik van 'n **aangepaste Sandboks** met die toekenning **`com.apple.security.temporary-exception.sbpl`** en hierdie aangepaste sandboks maak dit moontlik om enige plek lêers te skryf solank die lêernaam begin met `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daarom was ontsnapping so maklik soos om 'n `plist` LanceringAgent te skryf in `~/Library/LaunchAgents/~$escape.plist`.

Kyk na die [**oorspronklike verslag hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Woordsandboksontduiking via Aanmeldingsitems en zip

Onthou dat vanaf die eerste ontsnapping kan Word arbitrêre lêers skryf waarvan die naam begin met `~$`, alhoewel dit na die patch van die vorige kwesbaarheid nie moontlik was om in `/Library/Application Scripts` of in `/Library/LaunchAgents` te skryf nie.

Daar is ontdek dat dit binne die sandboks moontlik is om 'n **Aanmeldingsitem** (toepassings wat uitgevoer sal word wanneer die gebruiker aanmeld) te skep. Hierdie programme **sal egter nie uitgevoer word tensy** hulle **genotariseer** is nie en dit is **nie moontlik om args by te voeg** nie (sodat jy nie net 'n omgekeerde dop kan hardloop met behulp van **`bash`** nie).

Vanaf die vorige Sandboksontduiking het Microsoft die opsie om lêers in `~/Library/LaunchAgents` te skryf, uitgeskakel. Daar is egter ontdek dat as jy 'n **zip-lêer as 'n Aanmeldingsitem** plaas, sal die `Archive Utility` dit net op sy huidige plek **ontpak**. Dus, omdat die `LaunchAgents`-map van `~/Library` nie standaard geskep word nie, was dit moontlik om 'n plist in `LaunchAgents/~$escape.plist` te **zip** en die zip-lêer in **`~/Library`** te plaas sodat dit by die volhardingsbestemming sal uitpak.

Kyk na die [**oorspronklike verslag hier**](https://objective-see.org/blog/blog\_0x4B.html).

### Woordsandboksontduiking via Aanmeldingsitems en .zshenv

(Onthou dat vanaf die eerste ontsnapping kan Word arbitrêre lêers skryf waarvan die naam begin met `~$`).

Die vorige tegniek het egter 'n beperking gehad: as die map **`~/Library/LaunchAgents`** bestaan omdat 'n ander sagteware dit geskep het, sal dit misluk. Daarom is 'n ander Aanmeldingsitemketting vir hierdie doel ontdek.

'n Aanvaller kan die lêers **`.bash_profile`** en **`.zshenv`** skep met die payload om uit te voer en dit dan zip en die zip-lêer in die slagoffers se gebruikersmap **`~/~$escape.zip`** skryf.

Voeg dan die zip-lêer by die **Aanmeldingsitems** en dan die **`Terminal`**-toepassing. Wanneer die gebruiker weer aanmeld, sal die zip-lêer in die gebruikerslêer uitgepak word en **`.bash_profile`** en **`.zshenv`** oorskryf, en dus sal die terminal een van hierdie lêers uitvoer (afhangende of bash of zsh gebruik word).

Kyk na die [**oorspronklike verslag hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Woordsandboksontduiking met Open en omgewingsveranderlikes

Vanaf gesandbokste prosesse is dit steeds moontlik om ander prosesse aan te roep deur die **`open`** nutsprogram te gebruik. Hierdie prosesse sal egter **binne hul eie sandboks** uitgevoer word.

Daar is ontdek dat die open nutsprogram die **`--env`** opsie het om 'n toepassing met **spesifieke omgewingsveranderlikes** uit te voer. Daarom was dit moontlik om die **`.zshenv-lêer** binne 'n map **binne** die **sandboks** te skep en die `open` te gebruik met `--env` deur die **`HOME`-veranderlike** in te stel op daardie map en die `Terminal`-toepassing te open, wat die `.zshenv`-lêer sal uitvoer (vir een of ander rede was dit ook nodig om die veranderlike `__OSINSTALL_ENVIROMENT` in te stel).

Kyk na die [**oorspronklike verslag hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Woordsandboksontduiking met Open en stdin

Die **`open`** nutsprogram ondersteun ook die **`--stdin`** parameter (en na die vorige ontduiking was dit nie meer moontlik om `--env` te gebruik nie).

Die ding is dat selfs al is **`python`** deur Apple onderteken, dit nie 'n skripsie met die **`quarantine`**-eienskap sal uitvoer nie. Dit was egter moontlik om dit 'n skripsie van stdin te gee sodat dit nie sal nagaan of dit geïsoleer is nie:&#x20;

1. Laat 'n **`~$exploit.py`**-lêer met arbitrêre Python-opdragte val.
2. Voer _open_ **`–stdin='~$exploit.py' -a Python`** uit, wat die Python-toepassing met ons neergesitde lêer as sy standaardinvoer uitvoer. Python voer ons kode gelukkig uit, en omdat dit 'n kindproses van _launchd_ is, is dit nie aan Word se sandboksreëls gebind nie.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com
