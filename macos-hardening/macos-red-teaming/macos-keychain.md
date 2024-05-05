# macOS Keychain

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wame **vamiwa** na **malware za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

***

## Keychains Kuu

* **Keychain ya Mtumiaji** (`~/Library/Keychains/login.keycahin-db`), ambayo hutumika kuhifadhi **siri maalum za mtumiaji** kama nywila za programu, nywila za mtandao, vyeti vilivyoundwa na mtumiaji, nywila za mtandao, na funguo za umma/binafsi zilizoundwa na mtumiaji.
* **Keychain ya Mfumo** (`/Library/Keychains/System.keychain`), ambayo hifadhi **siri za mfumo kwa ujumla** kama vile nywila za WiFi, vyeti vya msingi vya mfumo, funguo binafsi za mfumo, na nywila za programu za mfumo.

### Upatikanaji wa Keychain ya Nywila

Faili hizi, ingawa hazina ulinzi wa asili na zinaweza **kupakuliwa**, zimefichwa na zinahitaji **nywila ya wazi ya mtumiaji ili kufichuliwa**. Zana kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kwa kufichua.

## Kinga ya Kuingia kwa Keychain

### ACLs

Kila kuingia katika keychain inatawaliwa na **Orodha za Kudhibiti Upatikanaji (ACLs)** ambazo zinaamua ni nani anaweza kutekeleza vitendo mbalimbali kwenye kuingia cha keychain, ikiwa ni pamoja na:

* **ACLAuhtorizationExportClear**: Inaruhusu mmiliki kupata maandishi wazi ya siri.
* **ACLAuhtorizationExportWrapped**: Inaruhusu mmiliki kupata maandishi wazi yaliyofichwa na nywila nyingine iliyotolewa.
* **ACLAuhtorizationAny**: Inaruhusu mmiliki kutekeleza kitendo chochote.

ACLs hizo zinaambatana na **orodha ya programu za kuaminika** ambazo zinaweza kutekeleza vitendo hivi bila kuulizwa. Hii inaweza kuwa:

* **N`il`** (hakuna idhini inayohitajika, **kila mtu anaaminika**)
* Orodha **tupu** (**hakuna mtu** anaaminika)
* **Orodha** ya **programu maalum**.

Pia kuingia kinaweza kuwa na funguo **`ACLAuthorizationPartitionID`,** ambayo hutumiwa kutambua **teamid, apple,** na **cdhash.**

* Ikiwa **teamid** imetajwa, basi ili **kupata thamani ya kuingia** bila **kuuliza**, programu iliyotumiwa lazima iwe na **teamid sawa**.
* Ikiwa **apple** imetajwa, basi programu inahitaji kuwa **imesainiwa** na **Apple**.
* Ikiwa **cdhash** imetajwa, basi **programu** lazima iwe na **cdhash** maalum.

### Kuunda Kuingia cha Keychain

Wakati kuingia **mgeni** **mgeni** anavyoundwa kwa kutumia **`Keychain Access.app`**, sheria zifuatazo zinatumika:

* Programu zote zinaweza kufanya usimbaji.
* **Hakuna programu** inaweza kuuza/kufuli (bila kuuliza mtumiaji).
* Programu zote zinaweza kuona ukaguzi wa uadilifu.
* Hakuna programu inaweza kubadilisha ACLs.
* **partitionID** inawekwa kuwa **`apple`**.

Wakati **programu inaunda kuingia katika keychain**, sheria ni tofauti kidogo:

* Programu zote zinaweza kufanya usimbaji.
* Ni **programu inayounda** (au programu nyingine yoyote iliyowekwa wazi) inaweza kuuza/kufuli (bila kuuliza mtumiaji).
* Programu zote zinaweza kuona ukaguzi wa uadilifu.
* Hakuna programu inaweza kubadilisha ACLs.
* **partitionID** inawekwa kuwa **`teamid:[teamID hapa]`**.

## Kupata Keychain

### `usalama`
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
**Uchambuzi wa keychain na kudumpisha** siri ambazo **hazitazalisha ombi** linaweza kufanywa kwa kutumia chombo [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Pata na upe **taarifa** kuhusu kila kuingiaji cha keychain:

* API ya **`SecItemCopyMatching`** hutoa taarifa kuhusu kila kuingiaji na kuna sifa kadhaa unazoweza kuweka unapotumia:
* **`kSecReturnData`**: Ikiwa ni kweli, itajaribu kufichua data (weka kama uwongo kuepuka pop-ups)
* **`kSecReturnRef`**: Pata pia kumbukumbu ya kuingiaji cha keychain (weka kama kweli kwa kesi utaona unaweza kufichua bila pop-up)
* **`kSecReturnAttributes`**: Pata maelezo kuhusu kuingiaji
* **`kSecMatchLimit`**: Ni matokeo mangapi ya kurudi
* **`kSecClass`**: Aina gani ya kuingiaji cha keychain

Pata **ACLs** ya kila kuingiaji:

* Kwa API ya **`SecAccessCopyACLList`** unaweza kupata **ACL ya kuingiaji cha keychain**, na itarudisha orodha ya ACLs (kama `ACLAuhtorizationExportClear` na zingine zilizotajwa awali) ambapo kila orodha ina:
* Maelezo
* **Orodha ya Maombi Yaliyoaminika**. Hii inaweza kuwa:
* Programu: /Applications/Slack.app
* Binary: /usr/libexec/airportd
* Kikundi: group://AirPort

Ficha data:

* API ya **`SecKeychainItemCopyContent`** inapata maandishi wazi
* API ya **`SecItemExport`** inaexport funguo na vyeti lakini inaweza kuhitaji kuweka nywila kuuza yaliyomo yaliyofichwa

Na hizi ni **mahitaji** ya kuweza **kuuza siri bila ombi**:

* Ikiwa kuna **programu 1 au zaidi** zilizoorodheshwa:
* Unahitaji **idhini sahihi** (**`Nil`**, au kuwa **sehemu** ya orodha iliyoruhusiwa ya programu katika idhini ya kupata taarifa za siri)
* Unahitaji sahihi ya msimbo kulingana na **PartitionID**
* Unahitaji sahihi ya msimbo kulingana na ile ya programu moja **iliyoaminika** (au kuwa mwanachama wa Kikundi sahihi cha KeychainAccessGroup)
* Ikiwa **programu zote zinaaminika**:
* Unahitaji **idhini sahihi**
* Unahitaji sahihi ya msimbo kulingana na **PartitionID**
* Ikiwa **hakuna PartitionID**, basi hii haifai

{% hint style="danger" %}
Hivyo, ikiwa kuna **programu 1 iliyoorodheshwa**, unahitaji **kuingiza msimbo katika programu hiyo**.

Ikiwa **apple** imeonyeshwa katika **partitionID**, unaweza kufikia hiyo kwa kutumia **`osascript`** hivyo chochote kinachotumaini programu zote zenye apple katika partitionID. **`Python`** pia inaweza kutumika kwa hili.
{% endhint %}

### Sifa mbili za ziada

* **Invisible**: Ni bendera ya boolean ya **kuficha** kuingiaji kutoka kwa programu ya **UI** ya Keychain
* **General**: Ni kuhifadhi **metadata** (kwa hivyo SIYOFICHWA)
* Microsoft ilikuwa inahifadhi katika maandishi wazi vitambulisho vyote vya upya kufikia mwisho wa hisia.

## Marejeo

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumiwa na **dark-web** inayotoa huduma za **bure** kuchunguza ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za wizi wa habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao kwa **bure** kwenye:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 **kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
