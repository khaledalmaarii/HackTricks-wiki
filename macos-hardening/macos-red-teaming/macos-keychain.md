# macOS Sleutelbos

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Hoof Sleutelbosse

* Die **Gebruiker Sleutelbos** (`~/Library/Keychains/login.keycahin-db`), wat gebruik word om **gebruikerspesifieke geloofsbriewe** soos toepassingswagwoorde, internetwagwoorde, gebruikers gegenereerde sertifikate, netwerkwagwoorde en gebruikers gegenereerde openbare/privaat sleutels te stoor.
* Die **Stelsel Sleutelbos** (`/Library/Keychains/System.keychain`), wat **stelselwye geloofsbriewe** soos WiFi-wagwoorde, stelsel-rootsertifikate, stelsel private sleutels en stelseltoepassingswagwoorde stoor.

### Toegang tot Sleutelbos Wagwoorde

Hierdie lêers, alhoewel hulle nie inherente beskerming het en **afgelaai** kan word nie, is versleutel en vereis die **gebruiker se platte tekst wagwoord om ontsluit** te word. 'n Hulpmiddel soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word vir ontsleuteling.

## Sleutelbosinskrywingsbeskerming

### ACL's

Elke inskrywing in die sleutelbos word beheer deur **Toegangsbeheerlyste (ACL's)** wat bepaal wie verskeie aksies op die sleutelbosinskrywing kan uitvoer, insluitend:

* **ACLAuhtorizationExportClear**: Laat die houer toe om die geheime teks te kry.
* **ACLAuhtorizationExportWrapped**: Laat die houer toe om die geheime teks versleutel met 'n ander voorsiene wagwoord te kry.
* **ACLAuhtorizationAny**: Laat die houer toe om enige aksie uit te voer.

Die ACL's word verder vergesel deur 'n **lys van vertroude toepassings** wat hierdie aksies sonder 'n versoek kan uitvoer. Dit kan wees:

* &#x20;**N`il`** (geen toestemming vereis, **almal is vertrou**)
* 'n **Leë** lys (**niemand** is vertrou)
* **Lys** van spesifieke **toepassings**.

Die inskrywing kan ook die sleutel **`ACLAuthorizationPartitionID`** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.

* As die **teamid** gespesifiseer is, moet die gebruikte toepassing dieselfde **teamid** hê om toegang tot die inskrywingwaarde **sonder** 'n versoek te verkry.
* As die **apple** aangedui is, moet die toepassing deur **Apple** onderteken word.
* As die **cdhash** aangedui word, moet die toepassing die spesifieke **cdhash** hê.

### Die Skep van 'n Sleutelbosinskrywing

Wanneer 'n **nuwe** **inskrywing** geskep word met behulp van **`Keychain Access.app`**, geld die volgende reëls:

* Alle toepassings kan versleutel.
* **Geen toepassings** kan uitvoer/ontsleutel nie (sonder om die gebruiker te versoek).
* Alle toepassings kan die integriteitskontrole sien.
* Geen toepassings kan ACL's verander nie.
* Die **partitionID** word ingestel op **`apple`**.

Wanneer 'n **toepassing 'n inskrywing in die sleutelbos skep**, is die reëls effens anders:

* Alle toepassings kan versleutel.
* Slegs die **skeppende toepassing** (of enige ander toepassings wat eksplisiet bygevoeg is) kan uitvoer/ontsleutel (sonder om die gebruiker te versoek).
* Alle toepassings kan die integriteitskontrole sien.
* Geen toepassings kan ACL's verander nie.
* Die **partitionID** word ingestel op **`teamid:[teamID hier]`**.

## Toegang tot die Sleutelbos

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
Die **sleutelketting enumerasie en dump** van geheime wat **nie 'n vraag sal genereer** nie, kan gedoen word met die instrument [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lys en kry **inligting** oor elke sleutelkettinginskrywing:

* Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing en daar is sekere eienskappe wat jy kan instel wanneer jy dit gebruik:
* **`kSecReturnData`**: As waar, sal dit probeer om die data te ontsluit (stel dit in as vals om potensiële opduikende vensters te vermy)
* **`kSecReturnRef`**: Kry ook verwysing na sleutelkettingitem (stel dit in as waar in die geval dat jy sien jy kan ontsluit sonder opduikende venster)
* **`kSecReturnAttributes`**: Kry metadata oor inskrywings
* **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
* **`kSecClass`**: Watter soort sleutelkettinginskrywing

Kry **ACL's** van elke inskrywing:

* Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die sleutelkettingitem** kry, en dit sal 'n lys van ACL's teruggee (soos `ACLAuhtorizationExportClear` en die ander voorheen genoemde) waar elke lys het:
* Beskrywing
* **Vertroude Aansoeklys**. Dit kan wees:
* 'n Toepassing: /Applications/Slack.app
* 'n Binêre: /usr/libexec/airportd
* 'n Groep: group://AirPort

Voer die data uit:

* Die API **`SecKeychainItemCopyContent`** kry die platte teks
* Die API **`SecItemExport`** voer die sleutels en sertifikate uit, maar moontlik moet wagwoorde gestel word om die inhoud versleutel uit te voer

En hier is die **vereistes** om 'n geheim sonder 'n vraag uit te voer:

* As daar **1+ vertroude** programme gelys word:
* Benodig die toepaslike **magtigings** (**`Nil`**, of wees deel van die toegelate lys van programme in die magtiging om toegang tot die geheime inligting te verkry)
* Benodig kodehandtekening om ooreen te stem met **PartitionID**
* Benodig kodehandtekening om ooreen te stem met dié van een **vertroude toepassing** (of wees 'n lid van die regte KeychainAccessGroup)
* As **alle programme vertrou** word:
* Benodig die toepaslike **magtigings**
* Benodig kodehandtekening om ooreen te stem met **PartitionID**
* As daar **geen PartitionID** is, is dit nie nodig nie

{% hint style="danger" %}
Daarom, as daar **1 aansoek gelys** word, moet jy **kode in daardie aansoek inspuit**.

As **apple** aangedui word in die **partitionID**, kan jy dit met **`osascript`** toegang kry, sodat enige iets wat alle programme met apple in die partitionID vertrou. **`Python`** kan ook hiervoor gebruik word.
{% endhint %}

### Twee addisionele eienskappe

* **Onsigbaar**: Dit is 'n booleaanse vlag om die inskrywing van die **UI** Sleutelketting-toepassing te **versteek**
* **Algemeen**: Dit is om **metadata** te stoor (dit is NIE VERSLEUTELD nie)
* Microsoft het al die verfrissingsnommers om toegang tot sensitiewe eindpunte te verkry, in platte teks gestoor.

## Verwysings

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
