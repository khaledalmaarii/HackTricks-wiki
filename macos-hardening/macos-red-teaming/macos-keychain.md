# macOS Sleutelbos

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **donker-web** aangedrewe soekenjin wat **gratis** funksies bied om te kyk of 'n maatskappy of sy kliënte deur **steelmalware** **gekompromitteer** is.

Die primêre doel van WhiteIntel is om rekening-oorneeminge en losgeldaanvalle te beveg wat voortspruit uit inligtingsteelmalware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

***

## Hoof Sleutelbosse

* Die **Gebruiker Sleutelbos** (`~/Library/Keychains/login.keycahin-db`), wat gebruik word om **gebruikerspesifieke geloofsbriewe** soos aansoek wagwoorde, internet wagwoorde, gebruikers gegenereerde sertifikate, netwerk wagwoorde, en gebruikers gegenereerde openbare/privaat sleutels te stoor.
* Die **Stelsel Sleutelbos** (`/Library/Keychains/System.keychain`), wat **stelselwye geloofsbriewe** soos WiFi wagwoorde, stelsel wortelsertifikate, stelsel private sleutels, en stelsel aansoek wagwoorde stoor.

### Toegang tot Wagwoord Sleutelbos

Hierdie lêers, alhoewel hulle nie inherente beskerming het en **afgelaai** kan word nie, is versleutel en vereis die **gebruiker se platte tekst wagwoord om ontsluit** te word. 'n Gereedskap soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word vir ontsleuteling.

## Sleutelbosinskrywingsbeskerming

### ACLs

Elke inskrywing in die sleutelbos word geregeer deur **Toegangsbeheerlyste (ACLs)** wat bepaal wie verskeie aksies op die sleutelbosinskrywing kan uitvoer, insluitend:

* **ACLAuhtorizationExportClear**: Laat die houer toe om die teks van die geheim te kry.
* **ACLAuhtorizationExportWrapped**: Laat die houer toe om die teks versleutel met 'n ander voorsiene wagwoord te kry.
* **ACLAuhtorizationAny**: Laat die houer toe om enige aksie uit te voer.

Die ACLs word verder vergesel deur 'n **lys van vertroude aansoeke** wat hierdie aksies sonder 'n versoek kan uitvoer. Dit kan wees:

* **N`il`** (geen toestemming benodig, **almal is vertrou**)
* 'n **leë** lys (**niemand** is vertrou)
* **Lys** van spesifieke **aansoeke**.

Die inskrywing kan ook die sleutel **`ACLAuthorizationPartitionID`,** bevat wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.

* As die **teamid** gespesifiseer is, moet die gebruikte aansoek die **selfde teamid** hê om die inskrywingswaarde **sonder** 'n **versoek** te kan **ontsluit**.
* As die **apple** gespesifiseer is, moet die aansoek deur **Apple** wees **onderteken**.
* As die **cdhash** aangedui is, moet die **aansoek** die spesifieke **cdhash** hê.

### Skep van 'n Sleutelbosinskrywing

Wanneer 'n **nuwe** **inskrywing** geskep word met **`Keychain Access.app`**, geld die volgende reels:

* Alle aansoeke kan versleutel.
* **Geen aansoeke** kan uitvoer/ontsleutel (sonder om die gebruiker te versoek).
* Alle aansoeke kan die integriteitskontrole sien.
* Geen aansoeke kan ACLs verander nie.
* Die **partitionID** is ingestel op **`apple`**.

Wanneer 'n **aansoek 'n inskrywing in die sleutelbos skep**, is die reels effens anders:

* Alle aansoeke kan versleutel.
* Slegs die **skeppende aansoek** (of enige ander aansoeke wat eksplisiet bygevoeg is) kan uitvoer/ontsleutel (sonder om die gebruiker te versoek).
* Alle aansoeke kan die integriteitskontrole sien.
* Geen aansoeke kan ACLs verander nie.
* Die **partitionID** is ingestel op **`teamid:[spanID hier]`**.

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
### API's

{% hint style="success" %}
Die **sleutelketting enumerasie en dump** van geheime wat **nie 'n venster sal genereer** nie, kan gedoen word met die gereedskap [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lys en kry **inligting** oor elke sleutelketting inskrywing:

* Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing en daar is sekere eienskappe wat jy kan instel wanneer jy dit gebruik:
* **`kSecReturnData`**: As waar, sal dit probeer om die data te ontsluit (stel in op vals om potensiële pop-ups te vermy)
* **`kSecReturnRef`**: Kry ook verwysing na sleutelketting item (stel in op waar in geval jy later sien jy kan ontsluit sonder 'n pop-up)
* **`kSecReturnAttributes`**: Kry metadata oor inskrywings
* **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
* **`kSecClass`**: Watter soort sleutelketting inskrywing

Kry **ACL's** van elke inskrywing:

* Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die sleutelketting item** kry, en dit sal 'n lys van ACL's teruggee (soos `ACLAuhtorizationExportClear` en die ander voorheen genoemde) waar elke lys het:
* Beskrywing
* **Vertroude Aansoek Lys**. Dit kan wees:
* 'n Toep: /Applications/Slack.app
* 'n binêre: /usr/libexec/airportd
* 'n groep: group://AirPort

Voer die data uit:

* Die API **`SecKeychainItemCopyContent`** kry die platte teks
* Die API **`SecItemExport`** voer die sleutels en sertifikate uit maar jy moet moontlik wagwoorde instel om die inhoud versleutel uit te voer

En hierdie is die **vereistes** om in staat te wees om **'n geheim uit te voer sonder 'n venster**:

* As daar **1+ vertroude** programme gelys is:
* Benodig die toepaslike **magtigings** (**`Nil`**, of wees **deel** van die toegelate lys van programme in die magtiging om die geheime inligting te benader)
* Benodig kodehandtekening om ooreen te stem met **PartitionID**
* Benodig kodehandtekening om ooreen te stem met dié van een **vertroude toep** (of wees 'n lid van die regte KeychainAccessGroup)
* As **alle programme vertrou** word:
* Benodig die toepaslike **magtigings**
* Benodig kodehandtekening om ooreen te stem met **PartitionID**
* As daar **geen PartitionID** is, is dit nie nodig nie

{% hint style="danger" %}
Daarom, as daar **1 aansoek gelys** is, moet jy **kode inspuit in daardie aansoek**.

As **apple** aangedui word in die **partitionID**, kan jy dit benader met **`osascript`** sodat enige iets wat alle programme met apple in die partitionID vertrou. **`Python`** kan ook hiervoor gebruik word.
{% endhint %}

### Twee addisionele eienskappe

* **Onsigbaar**: Dit is 'n booleaanse vlag om die inskrywing van die **UI** Sleutelketting toep te **versteek**
* **Algemeen**: Dit is om **metadata** te stoor (dus dit is NIE VERSLEUTELD NIE)
* Microsoft het al die verfris tokens om toegang tot sensitiewe eindpunt te kry in die plat teks gestoor.

## Verwysings

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **donker-web** aangedrewe soekenjin wat **gratis** funksies bied om te kyk of 'n maatskappy of sy kliënte deur **diefstal malware** **gekompromitteer** is.

Die primêre doel van WhiteIntel is om rekening oorneem te bekamp en losgeldware aanvalle te voorkom wat voortspruit uit inligtingsteel malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
