# macOS MDM

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Om meer te leer oor macOS MDM's kyk na:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basies

### **MDM (Mobile Device Management) Oorsig**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) word gebruik om verskeie eindgebruikers-toestelle soos slimfone, draagbare rekenaars en tablets te bestuur. Veral vir Apple se platforms (iOS, macOS, tvOS) behels dit 'n stel gespesialiseerde kenmerke, API's en praktyke. Die werking van MDM steun op 'n verenigbare MDM-bediener, wat of kommersieel beskikbaar is of oopbron, en moet die [MDM-protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) ondersteun. Sleutelpunte sluit in:

* Gekentraliseerde beheer oor toestelle.
* Afhanklikheid van 'n MDM-bediener wat die MDM-protokol nakom.
* Vermoë van die MDM-bediener om verskeie bevele na toestelle te stuur, byvoorbeeld afstanddata-uitvee of opsetinstallasie.

### **Basiese beginsels van DEP (Device Enrollment Program)**

Die [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) wat deur Apple aangebied word, vereenvoudig die integrasie van Mobile Device Management (MDM) deur nul-aanraking-konfigurasie vir iOS, macOS en tvOS-toestelle te fasiliteer. DEP outomatiseer die registrasieproses, wat toestelle in staat stel om reg uit die boks operasioneel te wees, met minimale gebruiker- of administratiewe ingryping. Essensiële aspekte sluit in:

* Stel toestelle in staat om outomaties te registreer by 'n voorafbepaalde MDM-bediener met die aanvanklike aktivering.
* Hoofsaaklik voordelig vir splinternuwe toestelle, maar ook toepaslik vir toestelle wat herkonfigurasie ondergaan.
* Fasiliteer 'n eenvoudige opstelling, wat toestelle vinnig gereed maak vir organisatoriese gebruik.

### **Sekuriteits oorwegings**

Dit is noodsaaklik om daarop te let dat die gemak van registrasie wat DEP bied, terwyl dit voordelig is, ook sekuriteitsrisiko's kan inhou. As beskermende maatreëls nie voldoende afgedwing word vir MDM-registrasie nie, kan aanvallers hierdie vereenvoudigde proses benut om hul toestel op die organisasie se MDM-bediener te registreer, wat as 'n korporatiewe toestel voorgee.

{% hint style="danger" %}
**Sekuriteitswaarskuwing**: Vereenvoudigde DEP-registrasie kan moontlik ongemagtigde toestelregistrasie op die organisasie se MDM-bediener toelaat as behoorlike beskermingsmaatreëls nie in plek is nie.
{% endhint %}

### Basies Wat is SCEP (Simple Certificate Enrolment Protocol)?

* 'n Relatief ou protokol, geskep voordat TLS en HTTPS wydverspreid was.
* Gee kliënte 'n gestandaardiseerde manier om 'n **Certificate Signing Request** (CSR) te stuur vir die doel om 'n sertifikaat toegeken te word. Die kliënt sal die bediener vra om hom 'n ondertekende sertifikaat te gee.

### Wat is Konfigurasieprofiel (ook bekend as mobielekonfigs)?

* Apple se amptelike manier om **sisteemkonfigurasie in te stel/af te dwing.**
* Lêerformaat wat verskeie vragte kan bevat.
* Gebaseer op eienskapslyste (die XML-soort).
* "kan onderteken en versleutel word om hul oorsprong te valideer, hul integriteit te verseker, en hul inhoud te beskerm." Basiese beginsels — Bladsy 70, iOS Security Guide, Januarie 2018.

## Protokolle

### MDM

* Kombinasie van APNs (**Apple-bedieners**) + RESTful API (**MDM-vennootskap**-bedieners)
* **Kommunikasie** vind plaas tussen 'n toestel en 'n bediener wat verband hou met 'n **toestelbestuursproduk**
* **Bevele** wat van die MDM na die toestel gestuur word in **plist-gekodeerde woordeboeke**
* Al oor **HTTPS**. MDM-bedieners kan (en is gewoonlik) gepin.
* Apple verleen die MDM-vennoot 'n **APNs-sertifikaat** vir verifikasie

### DEP

* **3 API's**: 1 vir wederverkopers, 1 vir MDM-vennote, 1 vir toestelidentiteit (ondokumenteer):
* Die sogenaamde [DEP "wolkmeganisme" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Dit word deur MDM-bedieners gebruik om DEP-profiel met spesifieke toestelle te assosieer.
* Die [DEP API wat deur Apple Gemagtigde Wederverkopers gebruik word](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle in te skryf, inskrywingsstatus te kontroleer, en transaksiestatus te kontroleer.
* Die ongedokumenteerde private DEP API. Dit word deur Apple-toestelle gebruik om hul DEP-profiel aan te vra. Op macOS is die `cloudconfigurationd` binêre verantwoordelik vir die kommunikasie oor hierdie API.
* Meer moderne en **JSON**-gebaseer (teenoor plist)
* Apple verleen 'n **OAuth-token** aan die MDM-vennoot

**DEP "wolkmeganisme" API**

* RESTful
* sink toestelrekords van Apple na die MDM-bediener
* sink "DEP-profiel" na Apple van die MDM-bediener (later deur Apple aan die toestel gelewer)
* 'n DEP "profiel" bevat:
* MDM-vennoot-bediener-URL
* Addisionele vertroude sertifikate vir bediener-URL (opsionele pinning)
* Ekstra instellings (bv. watter skerms om oor te slaan in die Opsetassistent)

## Serienommer

Apple-toestelle wat na 2010 vervaardig is, het oor die algemeen **12-karakter alfanumeriese** serienommers, met die **eerste drie syfers wat die vervaardigingsplek** verteenwoordig, die volgende **twee** wat die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers wat 'n **unieke** **identifiseerder** voorsien, en die **laaste** **vier** syfers wat die **modelnommer** verteenwoordig.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Stappe vir inskrywing en bestuur

1. Toestelrekord-skepping (Wederverkoper, Apple): Die rekord vir die nuwe toestel word geskep
2. Toestelrekord-toewysing (Kliënt): Die toestel word aan 'n MDM-bediener toegewys
3. Toestelrekord-sinkronisasie (MDM-vennoot): MDM sinkroniseer die toestelrekords en druk die DEP-profiel na Apple
4. DEP-inloer (Toestel): Toestel kry sy DEP-profiel
5. Profielherwinning (Toestel)
6. Profielinstallasie (Toestel) a. insl. MDM, SCEP en hoof-CA-vragte
7. MDM-beveluitreiking (Toestel)

![](<../../../.gitbook/assets/image (691).png>)

Die lêer `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` voer funksies uit wat as **hoëvlak "stappe"** van die inskrywingsproses beskou kan word.
### Stap 4: DEP kontrole - Kry die Aktiveringsrekord

Hierdie deel van die proses vind plaas wanneer 'n **gebruiker 'n Mac vir die eerste keer opstart** (of na 'n volledige vee)

![](<../../../.gitbook/assets/image (1041).png>)

of wanneer die `sudo profiles show -type enrollment` uitgevoer word

* Bepaal **of die toestel DEP-geaktiveer is**
* Aktiveringsrekord is die interne naam vir **DEP "profiel"**
* Begin sodra die toestel aan die internet gekoppel is
* Gedryf deur **`CPFetchActivationRecord`**
* Geïmplementeer deur **`cloudconfigurationd`** via XPC. Die **"Opstelassistent**" (wanneer die toestel vir die eerste keer opgestart word) of die **`profiles`** bevel sal **hierdie daemon kontak** om die aktiveringsrekord te herwin.
* LaunchDaemon (hardloop altyd as root)

Dit volg 'n paar stappe om die Aktiveringsrekord uit te voer deur **`MCTeslaConfigurationFetcher`**. Hierdie proses gebruik 'n enkripsie genaamd **Absinthe**

1. Herwin **sertifikaat**
1. KRY [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inisialiseer** toestand vanaf sertifikaat (**`NACInit`**)
1. Gebruik verskeie toestel-spesifieke data (bv. **Serienommer via `IOKit`**)
3. Herwin **sessiesleutel**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stel die sessie op (**`NACKeyEstablishment`**)
5. Doen die versoek
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) deur die data te stuur `{ "aksie": "VersoekProfielKonfigurasie", "sn": "" }`
2. Die JSON-lading word versleutel met Absinthe (**`NACSign`**)
3. Alle versoek is oor HTTPs, ingeboude root-sertifikate word gebruik

![](<../../../.gitbook/assets/image (566) (1).png>)

Die reaksie is 'n JSON-woordeboek met belangrike data soos:

* **url**: URL van die MDM-leweransier-gashuis vir die aktiveringsprofiel
* **anker-sertifikate**: Reeks DER-sertifikate wat as vertroude ankers gebruik word

### **Stap 5: Profielherwinning**

![](<../../../.gitbook/assets/image (441).png>)

* Versoek gestuur na **url wat in DEP-profiel verskaf is**.
* **Anker-sertifikate** word gebruik om **vertroue te evalueer** indien verskaf.
* Herinnering: die **anker\_serts** eienskap van die DEP-profiel
* **Versoek is 'n eenvoudige .plist** met toestelidentifikasie
* Voorbeelde: **UDID, OS-weergawe**.
* CMS-onderteken, DER-gekodeer
* Onderteken met die **toestelidentiteitsertifikaat (van APNS)**
* **Sertifikaatketting** sluit vervalde **Apple iPhone-toestel-CA** in

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Stap 6: Profielinstallasie

* Nadat herwin, **profiel word op die stelsel gestoor**
* Hierdie stap begin outomaties (indien in **opstelassistent**)
* Gedryf deur **`CPInstallActivationProfile`**
* Geïmplementeer deur mdmclient oor XPC
* LaunchDaemon (as root) of LaunchAgent (as gebruiker), afhangende van konteks
* Konfigurasieprofiele het verskeie vragte om te installeer
* Raamwerk het 'n plugin-gebaseerde argitektuur vir die installeer van profiele
* Elke vragtipe is geassosieer met 'n plugin
* Kan XPC wees (in raamwerk) of klassieke Cocoa (in ManagedClient.app)
* Voorbeeld:
* Sertifikaatvragte gebruik CertificateService.xpc

Tipies sal die **aktiveringsprofiel** wat deur 'n MDM-leweransier voorsien word, die volgende vragte insluit:

* `com.apple.mdm`: om die toestel in MDM **te laat inskryf**
* `com.apple.security.scep`: om veilig 'n **kliëntsertifikaat** aan die toestel te voorsien.
* `com.apple.security.pem`: om vertroude CA-sertifikate **op die toestel se Stelsel Sleutelketting te installeer**.
* Die installeer van die MDM-vrag is gelykstaande aan **MDM kontrole in die dokumentasie**
* Vrag bevat sleutel eienskappe:
*
* MDM Kontroleer-In URL (**`CheckInURL`**)
* MDM Opdrag Aftoets URL (**`ServerURL`**) + APNs-onderwerp om dit te aktiveer
* Om MDM-vrag te installeer, word versoek gestuur na **`CheckInURL`**
* Geïmplementeer in **`mdmclient`**
* MDM-vrag kan afhang van ander vragte
* Laat **versoeke toe om aan spesifieke sertifikate geheg te word**:
* Eienskap: **`CheckInURLPinningCertificateUUIDs`**
* Eienskap: **`ServerURLPinningCertificateUUIDs`**
* Afgelewer deur PEM-vrag
* Laat toe dat die toestel geassosieer word met 'n identiteitsertifikaat:
* Eienskap: IdentityCertificateUUID
* Afgelewer deur SCEP-vrag

### **Stap 7: Luister vir MDM-opdragte**

* Nadat MDM kontroleer-in voltooi is, kan die leweransier **dringende kennisgewings uitreik deur APNs**
* By ontvangs, hanteer deur **`mdmclient`**
* Om vir MDM-opdragte te aftoets, word versoek gestuur na ServerURL
* Maak gebruik van voorheen geïnstalleerde MDM-vrag:
* **`ServerURLPinningCertificateUUIDs`** vir speldversoek
* **`IdentityCertificateUUID`** vir TLS-kliëntsertifikaat
