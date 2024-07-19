# macOS Dirty NIB

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Vir verdere besonderhede oor die tegniek, kyk na die oorspronklike pos van: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Hier is 'n opsomming:

NIB-lêers, deel van Apple se ontwikkelings-ekosisteem, is bedoel om **UI-elemente** en hul interaksies in toepassings te definieer. Hulle sluit geserialiseerde voorwerpe soos vensters en knoppies in, en word tydens uitvoering gelaai. Ten spyte van hul voortdurende gebruik, beveel Apple nou Storyboards aan vir 'n meer omvattende visualisering van UI-stroom.

### Sekuriteitskwessies met NIB-lêers
Dit is belangrik om op te let dat **NIB-lêers 'n sekuriteitsrisiko kan wees**. Hulle het die potensiaal om **arbitraire opdragte uit te voer**, en veranderinge aan NIB-lêers binne 'n app hinder nie Gatekeeper om die app uit te voer nie, wat 'n beduidende bedreiging inhou.

### Dirty NIB Inspuitingsproses
#### Skep en Stel 'n NIB-lêer op
1. **Beginopstelling**:
- Skep 'n nuwe NIB-lêer met XCode.
- Voeg 'n objek by die koppelvlak, stel sy klas op `NSAppleScript`.
- Konfigureer die aanvanklike `source` eienskap via Gebruiker Gedefinieerde Runtime Attribuut.

2. **Kode-uitvoeringsgadgets**:
- Die opstelling fasiliteer die uitvoering van AppleScript op aanvraag.
- Integreer 'n knoppie om die `Apple Script` objek te aktiveer, spesifiek die `executeAndReturnError:` selektor te aktiveer.

3. **Toetsing**:
- 'n Eenvoudige Apple Script vir toetsdoeleindes:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Toets deur in die XCode-debugger te loop en op die knoppie te klik.

#### Teiken 'n Toepassing (Voorbeeld: Pages)
1. **Voorbereiding**:
- Kopieer die teiken-app (bv. Pages) na 'n aparte gids (bv. `/tmp/`).
- Begin die app om Gatekeeper-probleme te omseil en dit te kas.

2. **Oorskrywing van NIB-lêer**:
- Vervang 'n bestaande NIB-lêer (bv. About Panel NIB) met die vervaardigde DirtyNIB-lêer.

3. **Uitvoering**:
- Activeer die uitvoering deur met die app te interaksie (bv. die `About` menu-item te kies).

#### Bewys van Konsep: Toegang tot Gebruikersdata
- Wysig die AppleScript om toegang te verkry tot en gebruikersdata, soos foto's, sonder gebruikers toestemming te onttrek.

### Kode Voorbeeld: Kwaadwillige .xib-lêer
- Toegang tot en hersien 'n [**voorbeeld van 'n kwaadwillige .xib-lêer**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) wat die uitvoering van arbitraire kode demonstreer.

### Aanspreek van Beginbeperkings
- Beginbeperkings hinder app-uitvoering vanaf onverwagte plekke (bv. `/tmp`).
- Dit is moontlik om apps te identifiseer wat nie deur Beginbeperkings beskerm word nie en hulle te teiken vir NIB-lêerinspuiting.

### Addisionele macOS Beskermings
Vanaf macOS Sonoma is wysigings binne App-pakkette beperk. egter, vroeëre metodes het ingesluit:
1. Kopieer die app na 'n ander plek (bv. `/tmp/`).
2. Hernoem gidse binne die app-pakket om aanvanklike beskermings te omseil.
3. Na die uitvoering van die app om by Gatekeeper te registreer, wysig die app-pakket (bv. vervang MainMenu.nib met Dirty.nib).
4. Hernoem gidse terug en herloop die app om die ingespuite NIB-lêer uit te voer.

**Let wel**: Onlangs macOS-opdaterings het hierdie uitbuiting verminder deur lêerwysigings binne app-pakkette na Gatekeeper-kas te voorkom, wat die uitbuiting ondoeltreffend maak.
