# macOS MDM

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Om meer te leer oor macOS MDM's, kyk na:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basiese beginsels

### **MDM (Mobile Device Management) Oorsig**
[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) word gebruik om verskeie eindgebruikerstoestelle soos slimfone, draagbare rekenaars en tablette te bestuur. Veral vir Apple se platforms (iOS, macOS, tvOS) behels dit 'n stel gespesialiseerde funksies, API's en praktyke. Die werking van MDM steun op 'n verenigbare MDM-bediener, wat of kommersieel beskikbaar is of oopbron is, en moet die [MDM-protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) ondersteun. Sleutelpunte sluit in:

- Gekentraliseerde beheer oor toestelle.
- Afhanklikheid van 'n MDM-bediener wat die MDM-protokol nakom.
- Die vermoë van die MDM-bediener om verskeie opdragte na toestelle te stuur, byvoorbeeld verwydering van afgelewerde data of konfigurasie-installasie.

### **Basiese beginsels van DEP (Device Enrollment Program)**
Die [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) wat deur Apple aangebied word, vereenvoudig die integrasie van Mobile Device Management (MDM) deur outomatiese konfigurasie vir iOS-, macOS- en tvOS-toestelle te fasiliteer. DEP outomatiseer die registrasieproses, sodat toestelle reguit uit die boks gebruik kan word, met minimale gebruikers- of administratiewe ingryping. Belangrike aspekte sluit in:

- Stel toestelle in staat om outomaties by 'n voorafbepaalde MDM-bediener te registreer by aanvanklike aktivering.
- Hoofsaaklik voordelig vir splinternuwe toestelle, maar ook toepaslik vir toestelle wat herkonfigurasie ondergaan.
- Vereenvoudig 'n maklike opstelling, sodat toestelle vinnig gereed is vir organisatoriese gebruik.

### **Veiligheidsoorwegings**
Dit is belangrik om daarop te let dat die maklike registrasie wat deur DEP gebied word, terwyl dit voordelig is, ook sekuriteitsrisiko's kan inhou. As beskermingsmaatreëls nie behoorlik afgedwing word vir MDM-registrasie nie, kan aanvallers hierdie vereenvoudigde proses benut om hul toestel op die organisasie se MDM-bediener te registreer en as 'n korporatiewe toestel voor te gee.

{% hint style="danger" %}
**Veiligheidswaarskuwing**: Vereenvoudigde DEP-registrasie kan potensieel ongemagtigde toestelregistrasie op die organisasie se MDM-bediener toelaat as behoorlike veiligheidsmaatreëls nie in plek is nie.
{% endhint %}

### Basiese beginsels Wat is SCEP (Simple Certificate Enrolment Protocol)?

* 'n Relatief ou protokol, geskep voordat TLS en HTTPS wydverspreid was.
* Gee kliënte 'n gestandaardiseerde manier om 'n **Certificate Signing Request** (CSR) te stuur om 'n sertifikaat toegeken te word. Die kliënt sal die bediener vra om hom 'n ondertekende sertifikaat te gee.

### Wat is Konfigurasieprofiel (aka mobileconfigs)?

* Apple se amptelike manier om **sisteme-konfigurasie in te stel/af te dwing**.
* Lêerformaat wat verskeie ladinge kan bevat.
* Gebaseer op eiendomslyste (die XML-soort).
* "kan onderteken en versleutel word om hul oorsprong te valideer, hul integriteit te verseker en hul inhoud te beskerm." Basics — Bladsy 70, iOS Security Guide, Januarie 2018.

## Protokolle

### MDM

* Kombinasie van APNs (**Apple-bedieners**) + RESTful API (**MDM-vennoot**-bedieners)
* **Kommunikasie** vind plaas tussen 'n **toestel** en 'n bediener wat verband hou met 'n **toestelbestuursproduk**
* **Opdragte** word van die MDM na die toestel gestuur in **plist-gekodeerde woordeboeke**
* Alles oor **HTTPS**. MDM-bedieners kan (en word gewoonlik) vasgemaak.
* Apple verleen die MDM-vennoot 'n **APNs-sertifikaat** vir verifikasie

### DEP

* **3 API's**: 1 vir wederverkopers, 1 vir MDM-vennote, 1 vir toestelidentiteit (ondokumenteer):
* Die sogenaamde [DEP "wolkmeganisme" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Dit word deur MDM-bedieners gebruik om DEP-profiel met spesifieke toestelle te assosieer.
* Die [DEP API wat deur Apple Gemagtigde Wederverkopers gebruik word](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle in te skryf, inskrywingsstatus te kontroleer en transaksiestatus te kontroleer.
* Die ongedokumenteerde private DEP API. Dit word deur Apple-toestelle gebruik om hul DEP-profiel aan te vra. Op macOS is die `cloudconfigurationd` binêre verantwoordelik vir kommunikasie oor hierdie API.
* Meer moderne en **JSON**-gebaseerd (vs. plist)
* Apple verleen 'n **OAuth-token** aan die MDM-vennoot

**DEP "wolkmeganisme" API**

* RESTful
* sink toestelrekords van Apple na die MDM-bediener
* sink "DEP-profiel" na Apple van die MDM-bediener (later deur Apple aan die toestel afgelewer)
* 'n DEP "profiel" bevat:
* MDM-vennoot-bediener-URL
* Addisionele vertrouensertifikate vir bediener-URL (opsionele vaspen)
* Ekstra instellings (bv. watter skerms om oor te slaan in die Assistent vir Opstelling)

## Serienommer

Apple-toestelle wat na 2010 vervaardig is, het oor die algemeen **12-karakter alfanumeriese** serienommers, met die **eerste drie syfers wat die vervaardigingsplek** verteenwoordig, die volgende **twee** wat die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers wat 'n **unieke identifiseerder** verskaf, en die **laaste** **vier** syfers wat die **modelnommer** verteenwoordig.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Stappe vir inskrywing en bestuur

1. Ske
### Stap 4: DEP kontrole - Kry die Aktiveringsrekord

Hierdie deel van die proses gebeur wanneer 'n **gebruiker 'n Mac vir die eerste keer opstart** (of na 'n volledige uitvee)

![](<../../../.gitbook/assets/image (568).png>)

of wanneer die `sudo profiles show -type enrollment` uitgevoer word

* Bepaal **of die toestel DEP-geaktiveer is**
* Aktiveringsrekord is die interne naam vir die **DEP "profiel"**
* Begin sodra die toestel aan die internet gekoppel is
* Gedryf deur **`CPFetchActivationRecord`**
* Geïmplementeer deur **`cloudconfigurationd`** via XPC. Die **"Setup Assistant**" (wanneer die toestel eerste keer opgestart word) of die **`profiles`** opdrag sal **hierdie daemon kontak** om die aktiveringsrekord te kry.
* LaunchDaemon (loop altyd as root)

Dit volg 'n paar stappe om die Aktiveringsrekord uit te voer deur **`MCTeslaConfigurationFetcher`**. Hierdie proses maak gebruik van 'n versleuteling genaamd **Absinthe**

1. Kry **sertifikaat**
1. Kry [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inisialiseer** toestand vanaf sertifikaat (**`NACInit`**)
1. Gebruik verskillende toestel-spesifieke data (bv. **Serienommer via `IOKit`**)
3. Kry **sessiesleutel**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stel die sessie op (**`NACKeyEstablishment`**)
5. Doen die versoek
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en stuur die data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Die JSON-lading word versleutel met Absinthe (**`NACSign`**)
3. Alle versoek word oor HTTPs gestuur, ingeboude rootsertifikate word gebruik

![](<../../../.gitbook/assets/image (566).png>)

Die respons is 'n JSON-woordeboek met belangrike data soos:

* **url**: URL van die MDM-leweransier-gashuis vir die aktiveringsprofiel
* **anchor-certs**: Array van DER-sertifikate wat as vertroude ankers gebruik word

### **Stap 5: Profiel ophaling**

![](<../../../.gitbook/assets/image (567).png>)

* Versoek gestuur na **url wat in DEP-profiel verskaf is**.
* **Ankersertifikate** word gebruik om vertroue te **evalueer** indien verskaf.
* Onthou: die **anchor\_certs** eienskap van die DEP-profiel
* **Versoek is 'n eenvoudige .plist** met toestelidentifikasie
* Voorbeelde: **UDID, OS-weergawe**.
* CMS-onderteken, DER-gekodeer
* Onderteken met die **toestelidentiteitsertifikaat (van APNS)**
* **Sertifikaatketting** sluit verstreke **Apple iPhone Device CA** in

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### Stap 6: Profielinstallasie

* Sodra dit opgehaal is, word die **profiel op die stelsel gestoor**
* Hierdie stap begin outomaties (as in die **opstellingsassistent**)
* Gedryf deur **`CPInstallActivationProfile`**
* Geïmplementeer deur mdmclient oor XPC
* LaunchDaemon (as root) of LaunchAgent (as gebruiker), afhangende van die konteks
* Konfigurasieprofiel het verskeie ladinge om te installeer
* Die raamwerk het 'n plugin-gebaseerde argitektuur vir die installeer van profiele
* Elke ladingstipe is geassosieer met 'n plugin
* Dit kan XPC (in die raamwerk) of klassieke Cocoa (in ManagedClient.app) wees
* Voorbeeld:
* Sertifikaatladinge gebruik CertificateService.xpc

Gewoonlik sal die **aktiveringsprofiel** wat deur 'n MDM-leweransier verskaf word, die volgende ladinge insluit:

* `com.apple.mdm`: om die toestel in MDM te **registreer**
* `com.apple.security.scep`: om 'n **kliëntsertifikaat** veilig aan die toestel te voorsien.
* `com.apple.security.pem`: om vertroude CA-sertifikate in die toestel se Stelsel Sleutelketting te **installeer**.
* Installeer die MDM-lading wat gelykstaande is aan **MDM-kontrole in die dokumentasie**
* Lading bevat **sleutel eienskappe**:
*
* MDM Kontrole URL (**`CheckInURL`**)
* MDM Opdragopvraag URL (**`ServerURL`**) + APNs-onderwerp om dit te aktiveer
* Om MDM-lading te installeer, word 'n versoek gestuur na **`CheckInURL`**
* Geïmplementeer in **`mdmclient`**
* MDM-lading kan afhang van ander ladinge
* Maak dit moontlik om **versoeke aan spesifieke sertifikate te koppel**:
* Eienskap: **`CheckInURLPinningCertificateUUIDs`**
* Eienskap: **`ServerURLPinningCertificateUUIDs`**
* Afgelewer via PEM-lading
* Maak dit moontlik om die toestel aan 'n identiteitsertifikaat te koppel:
* Eienskap: IdentityCertificateUUID
* Afgelewer via SCEP-lading

### **Stap 7: Luister vir MDM-opdragte**

* Nadat MDM-kontrole voltooi is, kan die leweransier **push-meldings uitreik deur APNs te gebruik**
* Wanneer ontvang, hanteer deur **`mdmclient`**
* Om vir MDM-opdragte te vra, word 'n versoek gestuur na ServerURL
* Maak gebruik van voorheen geïnstalleerde MDM-lading:
* **`ServerURLPinningCertificateUUIDs`** vir koppeling van versoek
* **`IdentityCertificateUUID`** vir TLS-kliëntsertifikaat
