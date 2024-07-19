# Enrolling Devices in Other Organisations

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Intro

Soos [**voorheen kommentaar**](./#what-is-mdm-mobile-device-management)**,** om 'n toestel in 'n organisasie te probeer registreer, **is slegs 'n Serienommer wat aan daardie Organisasie behoort, nodig**. Sodra die toestel geregistreer is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi wagwoorde, VPN konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit 'n gevaarlike toegangspunt vir aanvallers wees as die registrasieproses nie korrek beskerm word nie.

**Die volgende is 'n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Kyk daarna vir verdere tegniese besonderhede!**

## Oorsig van DEP en MDM Binaire Analise

Hierdie navorsing delf in die binaire wat geassosieer word met die Toestel Registrasie Program (DEP) en Mobiele Toestel Bestuur (MDM) op macOS. Sleutelkomponente sluit in:

- **`mdmclient`**: Kommunikeer met MDM bedieners en aktiveer DEP aanmeldings op macOS weergawes voor 10.13.4.
- **`profiles`**: Bestuur Konfigurasie Profiele, en aktiveer DEP aanmeldings op macOS weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API kommunikasies en haal Toestel Registrasie profiele op.

DEP aanmeldings gebruik die `CPFetchActivationRecord` en `CPGetActivationRecord` funksies van die private Konfigurasie Profiele raamwerk om die Aktivering Rekord op te haal, met `CPFetchActivationRecord` wat saamwerk met `cloudconfigurationd` deur XPC.

## Tesla Protokol en Absinthe Skema Omgekeerde Ingenieurswese

Die DEP aanmelding behels `cloudconfigurationd` wat 'n geënkripteerde, geskrewe JSON payload na _iprofiles.apple.com/macProfile_ stuur. Die payload sluit die toestel se serienommer en die aksie "RequestProfileConfiguration" in. Die enkripsieskema wat gebruik word, word intern as "Absinthe" verwys. Om hierdie skema te ontrafel is kompleks en behels verskeie stappe, wat gelei het tot die verkenning van alternatiewe metodes om arbitrêre serienommers in die Aktivering Rekord versoek in te voeg.

## Proxying DEP Versoeke

Pogings om DEP versoeke na _iprofiles.apple.com_ te onderskep en te wysig met behulp van gereedskap soos Charles Proxy is belemmer deur payload enkripsie en SSL/TLS sekuriteitsmaatreëls. Dit is egter moontlik om die `MCCloudConfigAcceptAnyHTTPSCertificate` konfigurasie in te skakel, wat die bediener sertifikaat validasie omseil, alhoewel die geënkripteerde aard van die payload steeds die wysiging van die serienommer sonder die dekripsiesleutel verhinder.

## Instrumentering van Stelsels Binaries wat met DEP Interaksie het

Instrumentering van stelsels binaries soos `cloudconfigurationd` vereis die deaktivering van Stelsel Integriteit Beskerming (SIP) op macOS. Met SIP gedeaktiveer, kan gereedskap soos LLDB gebruik word om aan stelsels prosesse te koppel en moontlik die serienommer wat in DEP API interaksies gebruik word, te wysig. Hierdie metode is verkieslik aangesien dit die kompleksiteite van regte en kode ondertekening vermy.

**Eksploitering van Binaire Instrumentasie:**
Die wysiging van die DEP versoek payload voor JSON serialisering in `cloudconfigurationd` het effektief geblyk. Die proses het behels:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die stelsels serienommer opgevraag word.
3. Spuit 'n arbitrêre serienommer in die geheue in voordat die payload geënkripteer en gestuur word.

Hierdie metode het toegelaat om volledige DEP profiele vir arbitrêre serienommers te verkry, wat 'n potensiële kwesbaarheid demonstreer.

### Outomatisering van Instrumentasie met Python

Die eksploitasiestap is geoutomatiseer met behulp van Python met die LLDB API, wat dit haalbaar maak om programmaties arbitrêre serienommers in te spuit en ooreenstemmende DEP profiele op te haal.

### Potensiële Impakte van DEP en MDM Kwesbaarhede

Die navorsing het beduidende sekuriteitskwessies beklemtoon:

1. **Inligting Ontsluiting**: Deur 'n DEP-geregistreerde serienommer te verskaf, kan sensitiewe organisatoriese inligting wat in die DEP profiel bevat is, verkry word.
