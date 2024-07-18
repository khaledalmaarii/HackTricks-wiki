# macOS MDM

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hackingtruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

**Om meer te leer oor macOS MDM's kyk:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basies

### **MDM (Mobile Device Management) Oorsig**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) word gebruik om verskeie eindgebruikers-toestelle soos slimfone, draagbare rekenaars en tablette te bestuur. Veral vir Apple se platforms (iOS, macOS, tvOS) behels dit 'n stel gespesialiseerde kenmerke, API's en praktyke. Die werking van MDM steun op 'n verenigbare MDM-bediener, wat of kommersieel beskikbaar is of oopbron, en moet die [MDM-protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) ondersteun. Sleutelpunte sluit in:

* Gekentraliseerde beheer oor toestelle.
* Afhanklikheid van 'n MDM-bediener wat voldoen aan die MDM-protokol.
* Vermoë van die MDM-bediener om verskeie bevele na toestelle te stuur, byvoorbeeld afstanddata-uitvee of opsetinstallasie.

### **Basiese beginsels van DEP (Device Enrollment Program)**

Die [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) wat deur Apple aangebied word, vereenvoudig die integrasie van Mobile Device Management (MDM) deur nul-aanraking-konfigurasie vir iOS, macOS en tvOS-toestelle te fasiliteer. DEP outomatiseer die intekeningsproses, wat toestelle in staat stel om reg uit die boks operasioneel te wees, met minimale gebruiker- of administratiewe ingryping. Belangrike aspekte sluit in:

* Stel toestelle in staat om outomaties te registreer by 'n voorafbepaalde MDM-bediener met aanvanklike aktivering.
* Hoofsaaklik voordelig vir splinternuwe toestelle, maar ook toepaslik vir toestelle wat herkonfigurasie ondergaan.
* Fasiliteer 'n eenvoudige opstelling, wat toestelle vinnig gereed maak vir organisatoriese gebruik.

### **Sekuriteits oorwegings**

Dit is noodsaaklik om daarop te let dat die gemak van intekening wat deur DEP gebied word, terwyl dit voordelig is, ook sekuriteitsrisiko's kan inhou. As beskermende maatreëls nie voldoende afgedwing word vir MDM-intekening nie, kan aanvallers hierdie vereenvoudigde proses benut om hul toestel op die organisasie se MDM-bediener te registreer, wat as 'n korporatiewe toestel voorgee.

{% hint style="danger" %}
**Sekuriteitswaarskuwing**: Vereenvoudigde DEP-intekening kan moontlik ongemagtigde toestelregistrasie op die organisasie se MDM-bediener toelaat as behoorlike beskermingsmaatreëls nie in plek is nie.
{% endhint %}

### Basies Wat is SCEP (Simple Certificate Enrolment Protocol)?

* 'n Relatief ou protokol, geskep voordat TLS en HTTPS wydverspreid was.
* Gee kliënte 'n gestandaardiseerde manier om 'n **Certificate Signing Request** (CSR) te stuur vir die doel om 'n sertifikaat toegeken te word. Die kliënt sal die bediener vra om hom 'n ondertekende sertifikaat te gee.

### Wat is Konfigurasieprofiel (ook bekend as mobiele konfigurasies)?

* Apple se amptelike manier om **sisteemkonfigurasie in te stel/af te dwing.**
* Lêerformaat wat verskeie vragte kan bevat.
* Gebaseer op eienskapslyste (die XML-soort).
* "kan onderteken en versleutel word om hul oorsprong te valideer, hul integriteit te verseker, en hul inhoud te beskerm." Basiese beginsels - Bladsy 70, iOS-sekuriteitsgids, Januarie 2018.

## Protokolle

### MDM

* Kombinasie van APNs (**Apple-bediener**s) + RESTful API (**MDM-vennoot**-bedieners)
* **Kommunikasie** vind plaas tussen 'n **toestel** en 'n bediener wat verband hou met 'n **toestelbestuursproduk**
* **Bevele** wat van die MDM na die toestel gestuur word in **plist-gekodeerde woordeboeke**
* Al oor **HTTPS**. MDM-bediener kan (en is gewoonlik) gepin.
* Apple verleen die MDM-vennoot 'n **APNs-sertifikaat** vir verifikasie

### DEP

* **3 API's**: 1 vir wederverkopers, 1 vir MDM-vennote, 1 vir toestelidentiteit (ondokumenteer):
* Die sogenaamde [DEP "wolkmeganisme" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Dit word deur MDM-bedieners gebruik om DEP-profiel met spesifieke toestelle te assosieer.
* Die [DEP-API wat deur Apple Gemagtigde Wederverkopers gebruik word](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle in te skryf, intekeningsstatus te kontroleer, en transaksiestatus te kontroleer.
* Die ongedokumenteerde private DEP-API. Dit word deur Apple-toestelle gebruik om hul DEP-profiel aan te vra. Op macOS is die `cloudconfigurationd` binêre verantwoordelik vir kommunikasie oor hierdie API.
* Meer moderne en **JSON**-gebaseer (vs. plist)
* Apple verleen 'n **OAuth-token** aan die MDM-vennoot

**DEP "wolkmeganisme" API**

* RESTful
* sink toestelrekords van Apple na die MDM-bediener
* sink "DEP-profiel" na Apple van die MDM-bediener (later deur Apple aan die toestel gelewer)
* 'n DEP "profiel" bevat:
* MDM-vennootbediener-URL
* Addisionele vertroude sertifikate vir bediener-URL (opsionele pinning)
* Ekstra instellings (bv. watter skerms om oor te slaan in die Opsetassistent)

## Serienommer

Apple-toestelle wat na 2010 vervaardig is, het oor die algemeen **12-karakter alfanumeriese** serienommers, met die **eerste drie syfers wat die vervaardigingsplek** verteenwoordig, die volgende **twee** wat die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers wat 'n **unieke** **identifiseerder** voorsien, en die **laaste** **vier** syfers wat die **modelnommer** verteenwoordig.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Stappe vir intekening en bestuur

1. Skep van toestelrekord (Wederverkoper, Apple): Die rekord vir die nuwe toestel word geskep
2. Toestelrekordtoewysing (Kliënt): Die toestel word toegewys aan 'n MDM-bediener
3. Toestelrekordsinkronisasie (MDM-vennoot): MDM sinkroniseer die toestelrekords en druk die DEP-profiel na Apple
4. DEP-inloer (Toestel): Toestel kry sy DEP-profiel
5. Profielherwinning (Toestel)
6. Profielinstallasie (Toestel) a. insl. MDM, SCEP en stam CA-vragte
7. MDM-beveluitreiking (Toestel)

![](<../../../.gitbook/assets/image (694).png>)

Die lêer `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` voer funksies uit wat as **hoëvlak "stappe"** van die intekeningsproses beskou kan word.
### Stap 4: DEP kontrole - Kry die Aktiveringsrekord

Hierdie deel van die proses vind plaas wanneer 'n **gebruiker 'n Mac vir die eerste keer opstart** (of na 'n volledige vee)

![](<../../../.gitbook/assets/image (1044).png>)

of wanneer die `sudo profiles show -type enrollment` uitgevoer word

* Bepaal **of toestel DEP-geaktiveer is**
* Aktiveringsrekord is die interne naam vir **DEP "profiel"**
* Begin sodra die toestel aan die internet gekoppel is
* Gedryf deur **`CPFetchActivationRecord`**
* Geïmplementeer deur **`cloudconfigurationd`** via XPC. Die **"Opstelassistent**" (wanneer die toestel vir die eerste keer opgestart word) of die **`profiles`** bevel sal **hierdie daemon kontak** om die aktiveringsrekord te haal.
* LaunchDaemon (hardloop altyd as root)

Dit volg 'n paar stappe om die Aktiveringsrekord uit te voer deur **`MCTeslaConfigurationFetcher`**. Hierdie proses gebruik 'n enkripsie genaamd **Absinthe**

1. Haal die **sertifikaat** op
1. KRY [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inisialiseer** toestand vanaf sertifikaat (**`NACInit`**)
1. Gebruik verskeie toestel-spesifieke data (bv. **Serienommer via `IOKit`**)
3. Haal die **sessiesleutel** op
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stel die sessie op (**`NACKeyEstablishment`**)
5. Doen die versoek
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) deur die data te stuur `{ "aksie": "VersoekProfielkonfigurasie", "sn": "" }`
2. Die JSON-lading word versleutel met Absinthe (**`NACSign`**)
3. Alle versoek is oor HTTPs, ingeboude root-sertifikate word gebruik

![](<../../../.gitbook/assets/image (566) (1).png>)

Die reaksie is 'n JSON-woordeboek met belangrike data soos:

* **url**: URL van die MDM-leweransiergasheer vir die aktiveringsprofiel
* **anker-sertifikate**: Reeks DER-sertifikate wat as vertroude ankers gebruik word

### **Stap 5: Profielherwinning**

![](<../../../.gitbook/assets/image (444).png>)

* Versoek gestuur na **url wat in DEP-profiel verskaf is**.
* **Anker-sertifikate** word gebruik om **vertroue te evalueer** indien verskaf.
* Herinnering: die **anker\_serts** eienskap van die DEP-profiel
* **Versoek is 'n eenvoudige .plist** met toestelidentifikasie
* Voorbeelde: **UDID, OS-weergawe**.
* CMS-onderteken, DER-gekodeer
* Onderteken met die **toestelidentiteitsertifikaat (van APNS)**
* **Sertifikaatketting** sluit vervalde **Apple iPhone-toestel-CA** in

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1)
