# Inskrywing van Toestelle in Ander Organisasies

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Inleiding

Soos [**voorheen genoem**](./#what-is-mdm-mobile-device-management)**,** is dit nodig om 'n toestel in 'n organisasie in te skryf **slegs 'n Serienommer wat aan daardie Organisasie behoort**. Sodra die toestel ingeskryf is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, programme, WiFi-wagwoorde, VPN-konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dit kan dus 'n gevaarlike toegangspunt vir aanvallers wees as die inskrywingsproses nie korrek beskerm word nie.

**Die volgende is 'n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Kyk daarvoor vir verdere tegniese besonderhede!**

## Oorsig van DEP en MDM Binêre Analise

Hierdie navorsing ondersoek die binêre lêers wat verband hou met die Device Enrollment Program (DEP) en Mobile Device Management (MDM) op macOS. Sleutelkomponente sluit in:

- **`mdmclient`**: Kommunikeer met MDM-bedieners en veroorsaak DEP-inchecks op macOS-weergawes voor 10.13.4.
- **`profiles`**: Bestuur Konfigurasieprofiel en veroorsaak DEP-inchecks op macOS-weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API-kommunikasie en haal Toestelinskrywingsprofiel op.

DEP-inchecks maak gebruik van die `CPFetchActivationRecord` en `CPGetActivationRecord` funksies van die private Konfigurasieprofiel-raamwerk om die Aktiveringsrekord op te haal, waar `CPFetchActivationRecord` deur middel van XPC met `cloudconfigurationd` saamwerk.

## Tesla-Protokol en Absint-Skema-Ontleding

Die DEP-incheck behels dat `cloudconfigurationd` 'n versleutelde, ondertekende JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload sluit die toestel se serienommer en die aksie "RequestProfileConfiguration" in. Die gebruikte versleutelingsskema word intern as "Absint" verwys. Die ontrafeling van hierdie skema is kompleks en behels verskeie stappe, wat gelei het tot die ondersoek van alternatiewe metodes om arbitrêre serienommers in die Aktiveringsrekordversoek in te voeg.

## DEP Versoeke Proksie

Pogings om DEP-versoeke na _iprofiles.apple.com_ te onderskep en te wysig met behulp van hulpmiddels soos Charles Proxy is belemmer deur payload-versleuteling en SSL/TLS-sekuriteitsmaatreëls. Die aktivering van die `MCCloudConfigAcceptAnyHTTPSCertificate`-konfigurasie maak egter omseiling van die sertifikaatvalidering van die bediener moontlik, alhoewel die versleutelde aard van die payload steeds die wysiging van die serienommer sonder die dekripsiesleutel verhoed.

## Instrumentering van Stelselbinêre Lêers wat met DEP Interageer

Die instrumentering van stelselbinêre lêers soos `cloudconfigurationd` vereis die deaktivering van Stelselintegriteitsbeskerming (SIP) op macOS. Met SIP gedeaktiveer, kan hulpmiddels soos LLDB gebruik word om aan stelselprosesse te heg en moontlik die serienommer wat in DEP API-interaksies gebruik word, te wysig. Hierdie metode is verkieslik omdat dit die kompleksiteite van toekennings en kodesondertekening vermy.

**Uitbuiting van Binêre Instrumentering:**
Die wysiging van die DEP-versoek-payload voor JSON-serialisering in `cloudconfigurationd` was doeltreffend. Die proses het die volgende ingesluit:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die stelselserienommer opgehaal word.
3. Voeg 'n arbitrêre serienommer in die geheue in voordat die payload versleutel en gestuur word.

Hierdie metode het dit moontlik gemaak om volledige DEP-profiels vir arbitrêre serienommers op te haal, wat 'n potensiële kwesbaarheid aandui.

### Outomatisering van Instrumentering met Python

Die uitbuitingsproses is geoutomatiseer met behulp van Python en die LLDB API, wat dit moontlik maak om arbitrêre serienommers outomaties in te voeg en ooreenstemmende DEP-profiels op te haal.

### Potensiële Impakte van DEP en MDM-kwesbaarhede

Die navorsing het beduidende sekuriteitskwessies beklemtoon:

1. **Inligtingsoopmaking**: Deur 'n DEP-geregistreerde serienommer te voorsien, kan sensitiewe organisatoriese inligting wat in die DEP-profiel bevat word, opgehaal word.
2. **Rogue DEP-inskrywing**: Sonder behoorlike outentisering kan 'n aanvaller met 'n DEP-geregistreerde serienommer 'n skelmtoestel in 'n organisasie se MDM-bediener inskryf, wat moontlik toegang tot sensitiewe data en netwerkbronne kan gee.

Ten slotte, alhoewel DEP en MDM kragtige hulpmiddels bied vir die bestuur van Apple-toestelle in ondernemingsomgewings, bied hulle ook potensiële aanvalsvektore wat beveilig en gemonitor moet word.



<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
