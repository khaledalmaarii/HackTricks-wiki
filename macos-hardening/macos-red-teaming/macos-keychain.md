# macOS Sleutelbos

{% hint style="success" %}
Leer en oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegramgroep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steelmalware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekening-oorneemings en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteelmalware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

***

## Hoof Sleutelbosse

* Die **Gebruiker Sleutelbos** (`~/Library/Keychains/login.keycahin-db`), wat gebruik word om **gebruikerspesifieke geloofsbriewe** soos aansoek wagwoorde, internet wagwoorde, gebruikers gegenereerde sertifikate, netwerk wagwoorde, en gebruikers gegenereerde openbare/privaat sleutels te stoor.
* Die **Stelsel Sleutelbos** (`/Library/Keychains/System.keychain`), wat **stelselwye geloofsbriewe** soos WiFi-wagwoorde, stelsel root sertifikate, stelsel private sleutels, en stelsel aansoek wagwoorde stoor.

### Toegang tot Wagwoord Sleutelbos

Hierdie lêers, alhoewel hulle nie inherente beskerming het en afgelei kan word nie, is versleutel en vereis die **gebruiker se platte tekst wagwoord om ontsluit** te word. 'n Gereedskap soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word vir ontsleuteling.

## Sleutelbosinskrywingsbeskerming

### ACL's

Elke inskrywing in die sleutelbos word geregeer deur **Toegangsbeheerlyste (ACL's)** wat bepaal wie verskeie aksies op die sleutelbosinskrywing kan uitvoer, insluitend:

* **ACLAuhtorizationExportClear**: Laat die houer toe om die teks van die geheim te kry.
* **ACLAuhtorizationExportWrapped**: Laat die houer toe om die teks versleutel met 'n ander voorsiene wagwoord te kry.
* **ACLAuhtorizationAny**: Laat die houer toe om enige aksie uit te voer.

Die ACL's word verder vergesel deur 'n **lys van vertroue toepassings** wat hierdie aksies sonder vraag kan uitvoer. Dit kan wees:

* **N`il`** (geen toestemming benodig, **almal is vertrou**).
* 'n **Leë** lys (**niemand is vertrou**).
* **Lys** van spesifieke **toepassings**.

Ook kan die inskrywing die sleutel **`ACLAuthorizationPartitionID`** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.

* As die **teamid** gespesifiseer is, moet die gebruikte toepassing dieselfde **teamid** hê om die inskrywingswaarde **sonder** 'n **vraag** te kan **ontsluit**.
* As die **apple** gespesifiseer is, moet die toepassing deur **Apple** wees.
* As die **cdhash** aangedui word, moet die toepassing die spesifieke **cdhash** hê.

### Skep 'n Sleutelbosinskrywing

Wanneer 'n **nuwe** **inskrywing** geskep word met behulp van **`Keychain Access.app`**, geld die volgende reels:

* Alle toepassings kan versleutel.
* **Geen toepassings** kan uitvoer/ontsleutel (sonder om die gebruiker te vra).
* Alle toepassings kan die integriteitskontrole sien.
* Geen toepassings kan ACL's verander nie.
* Die **partitionID** is ingestel op **`apple`**.

Wanneer 'n **toepassing 'n inskrywing in die sleutelbos skep**, is die reels effens anders:

* Alle toepassings kan versleutel.
* Slegs die **skeppende toepassing** (of enige ander toepassings wat eksplisiet bygevoeg is) kan uitvoer/ontsleutel (sonder om die gebruiker te vra).
* Alle toepassings kan die integriteitskontrole sien.
* Geen toepassings kan ACL's verander nie.
* Die **partitionID** is ingestel op **`teamid:[teamID hier]`**.

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
* **`kSecMatchLimit`**: Hoeveel resultate om terug te keer
* **`kSecClass`**: Watter soort sleutelketting inskrywing

Kry **ACL's** van elke inskrywing:

* Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die sleutelketting item** kry, en dit sal 'n lys van ACL's teruggee (soos `ACLAuhtorizationExportClear` en die ander voorheen genoemde) waar elke lys het:
* Beskrywing
* **Vertroude Aansoeklys**. Dit kan wees:
* 'n Toep: /Applications/Slack.app
* 'n binêre: /usr/libexec/airportd
* 'n groep: group://AirPort

Voer die data uit:

* Die API **`SecKeychainItemCopyContent`** kry die platte teks
* Die API **`SecItemExport`** voer die sleutels en sertifikate uit, maar dit mag nodig wees om wagwoorde in te stel om die inhoud versleutel uit te voer

En hierdie is die **vereistes** om in staat te wees om **'n geheim sonder 'n venster uit te voer**:

* As daar **1+ vertroude** programme gelys is:
* Benodig die toepaslike **magtigings** (**`Nil`**, of wees **deel** van die toegelate lys van programme in die magtiging om die geheime inligting te benader)
* Benodig kodehandtekening om ooreen te stem met **PartitionID**
* Benodig kodehandtekening om ooreen te stem met dié van een **vertroude toep** (of wees 'n lid van die regte KeychainAccessGroup)
* As **alle programme vertrou** word:
* Benodig die toepaslike **magtigings**
* Benodig kodehandtekening om ooreen te stem met **PartitionID**
* As daar **geen PartitionID** is, is dit nie nodig nie

{% hint style="danger" %}
Daarom, as daar **1 aansoek gelys** is, moet jy kode **inspuit in daardie aansoek**.

As **apple** aangedui word in die **partitionID**, kan jy dit benader met **`osascript`** sodat enige iets wat alle programme met apple in die partitionID vertrou. **`Python`** kan ook hiervoor gebruik word.
{% endhint %}

### Twee addisionele eienskappe

* **Onsigbaar**: Dit is 'n booleaanse vlag om die inskrywing van die **UI** Sleutelketting toep te **versteek**
* **Algemeen**: Dit is om **metadata** te stoor (dus dit is NIE VERSLEUTELD NIE)
* Microsoft het al die verfris tokens om toegang tot sensitiewe eindpunt te kry, in die platte teks gestoor.

## Verwysings

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **donker-web** aangedrewe soekenjin wat **gratis** funksies bied om te kyk of 'n maatskappy of sy kliënte deur **diewe malware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekening oorneem te bekamp en losgeldware aanvalle te voorkom wat voortspruit uit inligtingsteel malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
