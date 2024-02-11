# macOS Keychain

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Keychain Kuu

* **Keychain ya Mtumiaji** (`~/Library/Keychains/login.keycahin-db`), ambayo hutumika kuhifadhi **vitambulisho maalum vya mtumiaji** kama nywila za programu, nywila za mtandao, vyeti vilivyotengenezwa na mtumiaji, nywila za mtandao, na funguo za umma / binafsi zilizotengenezwa na mtumiaji.
* **Keychain ya Mfumo** (`/Library/Keychains/System.keychain`), ambayo inahifadhi **vitambulisho vya mfumo kwa kiwango cha mfumo** kama vile nywila za WiFi, vyeti vya mfumo, funguo binafsi za mfumo, na nywila za programu za mfumo.

### Upatikanaji wa Nywila za Keychain

Faili hizi, ingawa hazina ulinzi wa asili na zinaweza **kupakuliwa**, zimefichwa na zinahitaji **nywila halisi ya mtumiaji ili kufichuliwa**. Zana kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) inaweza kutumika kwa kufichua.

## Ulinzi wa Vitambulisho vya Keychain

### ACLs

Kila kuingia kwenye keychain linatawaliwa na **Majedwali ya Kudhibiti Upatikanaji (ACLs)** ambayo yanadhibiti ni nani anaweza kufanya vitendo mbalimbali kwenye kuingia kwenye keychain, ikiwa ni pamoja na:

* **ACLAuhtorizationExportClear**: Inaruhusu mmiliki kupata maandishi wazi ya siri.
* **ACLAuhtorizationExportWrapped**: Inaruhusu mmiliki kupata maandishi wazi yaliyofichwa na nywila nyingine iliyotolewa.
* **ACLAuhtorizationAny**: Inaruhusu mmiliki kufanya kitendo chochote.

ACLs hizo zinaambatana na **orodha ya programu za kuaminika** ambazo zinaweza kufanya vitendo hivi bila kuuliza. Hii inaweza kuwa:

* &#x20;**N`il`** (hakuna idhini inayohitajika, **kila mtu anaaminika**)
* Orodha **tupu** (**hakuna mtu** anaaminika)
* **Orodha** ya **programu maalum**.

Pia kuingia kunaweza kuwa na ufunguo **`ACLAuthorizationPartitionID`,** ambao hutumiwa kutambua **teamid, apple,** na **cdhash.**

* Ikiwa **teamid** imeelekezwa, basi ili **kupata thamani ya kuingia** bila **kuuliza**, programu iliyotumika lazima iwe na **teamid sawa**.
* Ikiwa **apple** imeelekezwa, basi programu inahitaji kuwa **imesainiwa** na **Apple**.
* Ikiwa **cdhash** inaonyeshwa, basi programu lazima iwe na **cdhash** maalum.

### Kuunda Kuingia kwenye Keychain

Wakati kuingia kwenye keychain mpya inaundwa kwa kutumia **`Keychain Access.app`**, sheria zifuatazo zinatumika:

* Programu zote zinaweza kusimbua.
* **Hakuna programu** inaweza kusafirisha/kusimbua (bila kuuliza mtumiaji).
* Programu zote zinaweza kuona ukaguzi wa uadilifu.
* Hakuna programu inaweza kubadilisha ACLs.
* **partitionID** imewekwa kuwa **`apple`**.

Wakati programu inaunda kuingia kwenye keychain, sheria ni kidogo tofauti:

* Programu zote zinaweza kusimbua.
* Ni programu ya **kuunda kuingia** (au programu nyingine yoyote iliyowekwa wazi) tu inaweza kusafirisha/kusimbua (bila kuuliza mtumiaji).
* Programu zote zinaweza kuona ukaguzi wa uadilifu.
* Hakuna programu inaweza kubadilisha ACLs.
* **partitionID** imewekwa kuwa **`teamid:[teamID hapa]`**.

## Kupata Keychain

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
**Uchunguzi na kudondosha** kwa siri za **keychain** ambazo **hazitazalisha ombi** inaweza kufanywa kwa kutumia zana [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Pata orodha na **habari** kuhusu kila kuingia kwenye keychain:

* API ya **`SecItemCopyMatching`** inatoa habari kuhusu kila kuingia na kuna sifa kadhaa unazoweza kuweka unapotumia:
* **`kSecReturnData`**: Ikiwa ni kweli, itajaribu kufichua data (weka kuwa sahihi ili kuepuka pop-ups)
* **`kSecReturnRef`**: Pata pia kumbukumbu ya kipengee cha keychain (weka kuwa kweli ikiwa baadaye unaona unaweza kufichua bila pop-up)
* **`kSecReturnAttributes`**: Pata metadata kuhusu kuingia
* **`kSecMatchLimit`**: Ni matokeo mangapi ya kurudi
* **`kSecClass`**: Aina gani ya kuingia kwenye keychain

Pata **ACLs** ya kila kuingia:

* Kwa kutumia API ya **`SecAccessCopyACLList`** unaweza kupata **ACL kwa kuingia kwenye keychain**, na itarudi orodha ya ACLs (kama `ACLAuhtorizationExportClear` na zingine zilizotajwa hapo awali) ambapo kila orodha ina:
* Maelezo
* **Orodha ya Maombi Yaliyoidhinishwa**. Hii inaweza kuwa:
* Programu: /Applications/Slack.app
* Binary: /usr/libexec/airportd
* Kikundi: group://AirPort

Changanua data:

* API ya **`SecKeychainItemCopyContent`** inapata maandishi wazi
* API ya **`SecItemExport`** inachanganua funguo na vyeti lakini inaweza kuwa inahitaji kuweka nywila ili kuchanganua yaliyomo yaliyofichwa

Na hizi ndizo **mahitaji** ya kuweza **kuchanganua siri bila ombi**:

* Ikiwa kuna **programu 1 au zaidi zilizoidhinishwa**:
* Inahitaji **idhini sahihi** (**`Nil`**, au kuwa sehemu ya orodha iliyoruhusiwa ya programu katika idhini ya kufikia habari za siri)
* Inahitaji saini ya nambari kufanana na **PartitionID**
* Inahitaji saini ya nambari kufanana na ile ya **programu iliyoidhinishwa** (au kuwa mwanachama wa Kikundi sahihi cha KeychainAccessGroup)
* Ikiwa **programu zote zinatambuliwa**:
* Inahitaji **idhini sahihi**
* Inahitaji saini ya nambari kufanana na **PartitionID**
* Ikiwa hakuna **PartitionID**, basi hii haihitajiki

{% hint style="danger" %}
Kwa hivyo, ikiwa kuna **programu 1 iliyoorodheshwa**, unahitaji **kuingiza nambari kwenye programu hiyo**.

Ikiwa **apple** imeonyeshwa katika **PartitionID**, unaweza kufikia hiyo na **`osascript`** kwa hivyo chochote kinachotumaini programu zote na apple katika PartitionID. **`Python`** pia inaweza kutumika kwa hili.
{% endhint %}

### Atributi mbili zaidi

* **Invisible**: Ni bendera ya boolean ya **kuficha** kuingia kutoka kwenye programu ya **UI** ya Keychain
* **General**: Ni kuhifadhi **metadata** (kwa hivyo HAIJAFICHWA)
* Microsoft ilikuwa inahifadhi kwa maandishi wazi vivuli vyote vya kuboresha kufikia mwisho nyeti.

## Marejeo

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
