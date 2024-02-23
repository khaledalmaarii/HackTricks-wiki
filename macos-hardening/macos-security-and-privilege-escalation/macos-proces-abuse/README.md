# macOS Prosesmisbruik

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## MacOS Prosesmisbruik

MacOS, soos enige ander bedryfstelsel, bied 'n verskeidenheid metodes en meganismes vir **prosesse om te interakteer, kommunikeer, en data te deel**. Terwyl hierdie tegnieke noodsaaklik is vir doeltreffende stelselwerking, kan dit ook misbruik word deur bedreigingsaktors om **booswillige aktiwiteite uit te voer**.

### Biblioteekinspuiting

Biblioteekinspuiting is 'n tegniek waarin 'n aanvaller 'n proses dwing om 'n skadelike biblioteek te laai. Sodra ingespuit, hardloop die biblioteek in die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang gee as die proses.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Funksiehaak

Funksiehaak behels **onderskepping van funksie-oproepe** of boodskappe binne 'n sagteware-kode. Deur funksies te haak, kan 'n aanvaller die gedrag van 'n proses **verander**, sensitiewe data waarneem, of selfs beheer oor die uitvoervloei verkry.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Interproseskommunikasie

Interproseskommunikasie (IPC) verwys na verskillende metodes waardeur afsonderlike prosesse **data deel en uitruil**. Terwyl IPC fundamenteel is vir baie wettige toepassings, kan dit ook misbruik word om prosesisolasie te omseil, sensitiewe inligting te lek, of ongemagtigde aksies uit te voer.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Elektron-toepassingsinspuiting

Elektron-toepassings wat uitgevoer word met spesifieke omgewingsveranderlikes kan vatbaar wees vir prosesinspuiting:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Chromium-inspuiting

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om 'n **man-in-die-blaaier-aanval** uit te voer wat dit moontlik maak om toetsaanslae, verkeer, koekies te steel, skripte in bladsye in te spuit...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Vuil NIB

NIB-lêers **definieer gebruikerskoppelvlak (UI) elemente** en hul interaksies binne 'n toepassing. Tog kan hulle **willekeurige bevele uitvoer** en **Gatekeeper verhoed nie** dat 'n reeds uitgevoerde toepassing uitgevoer word as 'n **NIB-lêer gewysig word** nie. Daarom kan dit gebruik word om willekeurige programme willekeurige bevele uit te voer:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java-toepassingsinspuiting

Dit is moontlik om sekere java-vermoëns (soos die **`_JAVA_OPTS`** omgewingsveranderlike) te misbruik om 'n java-toepassing willekeurige kode/bevele uit te voer.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net-toepassingsinspuiting

Dit is moontlik om kode in .Net-toepassings in te spuit deur **die .Net-afsyenfunksionaliteit te misbruik** (nie beskerm deur macOS-beskermings soos hardewareharding nie).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl-inspuiting

Kyk na verskillende opsies om 'n Perl-skrip willekeurige kode uit te voer in:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby-inspuiting

Dit is ook moontlik om ruby-omgewingsveranderlikes te misbruik om willekeurige skripte willekeurige kode uit te voer:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python-inspuiting

As die omgewingsveranderlike **`PYTHONINSPECT`** ingestel is, sal die python-proses in 'n python-cli val sodra dit klaar is. Dit is ook moontlik om **`PYTHONSTARTUP`** te gebruik om 'n python-skrip aan te dui wat aan die begin van 'n interaktiewe sessie uitgevoer moet word.\
Let egter daarop dat die **`PYTHONSTARTUP`**-skrip nie uitgevoer sal word wanneer **`PYTHONINSPECT`** die interaktiewe sessie skep nie.

Ander omgewingsveranderlikes soos **`PYTHONPATH`** en **`PYTHONHOME`** kan ook nuttig wees om 'n python-opdrag willekeurige kode uit te voer.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes sal gebruik nie, selfs as hulle hardloop met 'n ingeslote python.

{% hint style="danger" %}
Oor die algemeen kon ek nie 'n manier vind om python willekeurige kode uit te voer deur omgewingsveranderlikes te misbruik nie.\
Meeste mense installeer egter pyhton met **Hombrew**, wat pyhton in 'n **skryfbare ligging** vir die verstek-admin-gebruiker sal installeer. Jy kan dit oorneem met iets soos:
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

### Skild

[**Skild**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) is 'n oopbron toepassing wat **prosesinspuiting kan opspoor en blokkeer**:

* Deur **Omgewingsveranderlikes** te gebruik: Dit sal die teenwoordigheid van enige van die volgende omgewingsveranderlikes monitor: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** en **`ELECTRON_RUN_AS_NODE`**
* Deur **`task_for_pid`** oproepe te gebruik: Om te vind wanneer een proses die **taakpoort van 'n ander** wil kry wat dit moontlik maak om kode in die proses in te spuit.
* **Electron app parameters**: Iemand kan **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`** bevellynargumente gebruik om 'n Electron app in afstemmingsmodus te begin, en sodoende kode daarin in te spuit.
* Deur **symboliese skakels** of **hard skakels** te gebruik: Tipies is die mees algemene misbruik om 'n skakel met ons gebruikersbevoegdhede te **plaas**, en dit na 'n hoër bevoegdheid te **rig**. Die opsporing is baie eenvoudig vir beide hard- en simboliese skakels. As die proses wat die skakel skep 'n **verskillende bevoegdheidsvlak** as die teikenlêer het, skep ons 'n **waarskuwing**. Ongelukkig is blokkering in die geval van simboliese skakels nie moontlik nie, aangesien ons nie voor die skepping inligting oor die bestemming van die skakel het nie. Dit is 'n beperking van Apple se EndpointSecuriy-raamwerk.

### Oproepe gemaak deur ander prosesse

In [**hierdie blogpos**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die funksie **`task_name_for_pid`** te gebruik om inligting oor ander **prosesse wat kode in 'n proses inspuit** te kry en dan inligting oor daardie ander proses te kry.

Let daarop dat om daardie funksie te roep, moet jy **dieselfde uid** as die een wat die proses hardloop of **root** wees (en dit gee inligting oor die proses, nie 'n manier om kode in te spuit).

## Verwysings

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
