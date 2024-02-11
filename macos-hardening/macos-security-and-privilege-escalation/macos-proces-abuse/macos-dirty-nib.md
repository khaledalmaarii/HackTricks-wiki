# macOS Vuil NIB

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

**Vir verdere besonderhede oor die tegniek, kyk na die oorspronklike pos van: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Hier is 'n opsomming:

NIB-lêers, deel van Apple se ontwikkelingsekosisteem, is bedoel vir die definisie van **UI-elemente** en hul interaksies in programme. Dit sluit geserializeerde voorwerpe soos vensters en knoppies in, en word tydens uitvoering gelaai. Ten spyte van hul voortdurende gebruik, bevorder Apple nou Storyboards vir 'n meer omvattende UI-vloei-visualisering.

### Sekuriteitskwessies met NIB-lêers
Dit is krities om te let dat **NIB-lêers 'n sekuriteitsrisiko kan wees**. Hulle het die potensiaal om **arbitrêre opdragte uit te voer**, en veranderinge aan NIB-lêers binne 'n toepassing verhoed nie dat Gatekeeper die toepassing uitvoer nie, wat 'n beduidende bedreiging vorm.

### Vuil NIB-inspuitingsproses
#### Skep en Opstel van 'n NIB-lêer
1. **Aanvanklike opstel**:
- Skep 'n nuwe NIB-lêer met behulp van XCode.
- Voeg 'n voorwerp by die koppelvlak, stel sy klas in as `NSAppleScript`.
- Stel die aanvanklike `bron`-eienskap op via Gebruikersgedefinieerde Runtime-attribuut.

2. **Kode-uitvoeringsgadget**:
- Die opstel fasiliteer die uitvoering van AppleScript op aanvraag.
- Integreer 'n knoppie om die `Apple Script`-voorwerp te aktiveer, wat spesifiek die `executeAndReturnError:`-selekteerder aktiveer.

3. **Toetsing**:
- 'n Eenvoudige Apple Script vir toetsdoeleindes:
```bash
stel dieDialogText in op "PWND"
vertoon dialoogvenster dieDialogText
```
- Toets deur dit in die XCode-afskermingsprogram te hardloop en op die knoppie te klik.

#### Teiken van 'n Toepassing (Voorbeeld: Pages)
1. **Voorbereiding**:
- Kopieer die teiken-toepassing (bv. Pages) na 'n afsonderlike gids (bv. `/tmp/`).
- Begin die toepassing om Gatekeeper-kwessies te omseil en dit in die kas te stoor.

2. **Oorskryf van NIB-lêer**:
- Vervang 'n bestaande NIB-lêer (bv. About Panel NIB) met die vervaardigde DirtyNIB-lêer.

3. **Uitvoering**:
- Stel die uitvoering in werking deur met die toepassing te interaksieer (bv. die `About`-keuse-item te kies).

#### Bewys van Konsep: Toegang tot Gebruikersdata
- Wysig die AppleScript om toegang tot en onttrekking van gebruikersdata, soos foto's, sonder gebruikersgoedkeuring, te verkry.

### Kodevoorbeeld: Skadelike .xib-lêer
- Kry toegang tot en hersien 'n [**voorbeeld van 'n skadelike .xib-lêer**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) wat die uitvoering van arbitrêre kode demonstreer.

### Aanspreek van Lanceringbeperkings
- Lanceringbeperkings verhoed dat toepassings uit onverwagte plekke (bv. `/tmp`) uitgevoer word.
- Dit is moontlik om toepassings te identifiseer wat nie deur Lanceringbeperkings beskerm word nie en hulle teiken vir NIB-lêer-inspuiting.

### Addisionele macOS-beskerming
Vanaf macOS Sonoma en verder is wysigings binne App-bundels beperk. Vroeëre metodes het egter die volgende behels:
1. Kopiëring van die toepassing na 'n ander plek (bv. `/tmp/`).
2. Hersiening van gidsname binne die App-bundel om aanvanklike beskerming te omseil.
3. Na die uitvoering van die toepassing om by Gatekeeper te registreer, wysiging van die App-bundel (bv. vervanging van MainMenu.nib met Dirty.nib).
4. Terughernoeming van gidsname en heruitvoering van die toepassing om die geïnspireerde NIB-lêer uit te voer.

**Let op**: Onlangse macOS-opdaterings het hierdie uitbuiting beperk deur lêerwysigings binne App-bundels na Gatekeeper-kasgeheue te verhoed, wat die uitbuiting ondoeltreffend maak.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
