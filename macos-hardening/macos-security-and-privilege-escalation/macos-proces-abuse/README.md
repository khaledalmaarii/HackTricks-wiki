# macOS Proseshandhawing

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>

## MacOS Proseshandhawing

MacOS, soos enige ander bedryfstelsel, bied 'n verskeidenheid metodes en meganismes vir **prosesse om te interaksieer, kommunikeer en data te deel**. Terwyl hierdie tegnieke noodsaaklik is vir doeltreffende stelselwerking, kan dit ook misbruik word deur bedreigingsakteurs om **booswillige aktiwiteite uit te voer**.

### Biblioteekinspuiting

Biblioteekinspuiting is 'n tegniek waarin 'n aanvaller 'n proses **dwing om 'n booswillige biblioteek te laai**. Sodra dit ingespuit is, loop die biblioteek in die konteks van die teikenproses en bied die aanvaller dieselfde toestemmings en toegang as die proses.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Funksiehaking

Funksiehaking behels die **onderskepping van funksie-oproepe** of boodskappe binne 'n sagtewarekode. Deur funksies te hak, kan 'n aanvaller die gedrag van 'n proses **verander**, sensitiewe data waarneem of selfs beheer oor die uitvoervloei verkry.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Interproseskommunikasie

Interproseskommunikasie (IPC) verwys na verskillende metodes waardeur afsonderlike prosesse **data deel en uitruil**. Terwyl IPC fundamenteel is vir baie wettige toepassings, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde aksies uit te voer.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Insuiting van Electron-toepassings

Electron-toepassings wat uitgevoer word met spesifieke omgewingsveranderlikes kan vatbaar wees vir prosesinspuiting:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Vuil NIB

NIB-lêers **definieer gebruikerskoppelvlak (UI) elemente** en hul interaksies binne 'n toepassing. Dit kan egter **willekeurige opdragte uitvoer** en **Gatekeeper verhoed nie** dat 'n reeds uitgevoerde toepassing uitgevoer word as 'n NIB-lêer gewysig is nie. Daarom kan dit gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Insuiting van Java-toepassings

Dit is moontlik om sekere Java-vermoëns (soos die **`_JAVA_OPTS`** omgewingsveranderlike) te misbruik om 'n Java-toepassing **willekeurige kode/opdragte** te laat uitvoer.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Insuiting van .Net-toepassings

Dit is moontlik om kode in .Net-toepassings in te spuit deur die **.Net aflynontledingsfunksionaliteit** te misbruik (nie beskerm deur macOS-beskermings soos uitvoeringverharding nie).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl-inspuiting

Kyk na verskillende opsies om 'n Perl-skripsie willekeurige kode te laat uitvoer:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby-inspuiting

Dit is ook moontlik om ruby-omgewingsveranderlikes te misbruik om willekeurige skripsies willekeurige kode te laat uitvoer:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python-inspuiting

As die omgewingsveranderlike **`PYTHONINSPECT`** ingestel is, sal die Python-proses in 'n Python-opdraglyn beland sodra dit klaar is. Dit is ook moontlik om **`PYTHONSTARTUP`** te gebruik om 'n Python-skripsie aan te dui wat aan die begin van 'n interaktiewe sessie uitgevoer moet word.\
Let egter daarop dat die **`PYTHONSTARTUP`**-skripsie nie uitgevoer sal word wanneer **`PYTHONINSPECT`** die interaktiewe sessie skep nie.

Ander omgewingsveranderlikes soos **`PYTHONPATH`** en **`PYTHONHOME`** kan ook nuttig wees om 'n Python-opdrag willekeurige kode te laat uitvoer.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, hierdie omgewingsveranderlikes nie sal gebruik nie, selfs as hulle gebruik maak van 'n ingebedde Python.

{% hint style="danger" %}
Oor die algemeen kon ek nie 'n manier vind om Python willekeurige kode te laat uitvoer deur omgewingsveranderlikes te misbruik nie.\
Die meeste mense installeer egter Python met behulp van **Hombrew**, wat Python in 'n **skryfbare ligging** vir die verstek-admin-gebruiker sal installeer. Jy kan dit kaap met iets soos:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Selfs **root** sal hierdie kode hardloop wanneer python uitgevoer word.
{% endhint %}

## Opmerking

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) is 'n oopbron-toepassing wat **prosesinjeksie-aksies kan opspoor en blokkeer**:

* Deur gebruik te maak van **Omgewingsveranderlikes**: Dit sal die teenwoordigheid van enige van die volgende omgewingsveranderlikes monitor: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** en **`ELECTRON_RUN_AS_NODE`**
* Deur gebruik te maak van **`task_for_pid`**-oproepe: Om te vind wanneer 'n proses die **taakpoort van 'n ander** wil kry, wat dit moontlik maak om kode in die proses in te spuit.
* **Electron-apps-parameters**: Iemand kan die **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`** opdraglynargument gebruik om 'n Electron-app in die opsporingsmodus te begin, en sodoende kode daarin in te spuit.
* Deur gebruik te maak van **symboliese skakels** of **hardlinks**: Tipies is die mees algemene misbruik om 'n skakel met ons gebruikersbevoegdhede te plaas en dit na 'n hoër bevoegdheid te verwys. Die opsporing is baie eenvoudig vir beide hardlinks en symboliese skakels. As die proses wat die skakel skep 'n **verskillende bevoegdheidsvlak** as die teikenlêer het, skep ons 'n **waarskuwing**. Ongelukkig is blokkering in die geval van symboliese skakels nie moontlik nie, aangesien ons nie vooraf inligting oor die bestemming van die skakel het nie. Dit is 'n beperking van Apple se EndpointSecuriy-raamwerk.

### Oproepe wat deur ander prosesse gemaak word

In [**hierdie blogpos**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die funksie **`task_name_for_pid`** te gebruik om inligting oor ander **prosesse wat kode in 'n proses in spuit** te kry en dan inligting oor daardie ander proses te kry.

Let daarop dat jy om daardie funksie te roep, **dieselfde uid** moet wees as die een wat die proses uitvoer of **root** (en dit gee inligting oor die proses, nie 'n manier om kode in te spuit nie).

## Verwysings

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
