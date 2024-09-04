# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Main Keychains

* **Keychain ya Mtumiaji** (`~/Library/Keychains/login.keycahin-db`), ambayo inatumika kuhifadhi **akidi za mtumiaji** kama vile nywila za programu, nywila za mtandao, vyeti vilivyoundwa na mtumiaji, nywila za mtandao, na funguo za umma/za faragha zilizoundwa na mtumiaji.
* **Keychain ya Mfumo** (`/Library/Keychains/System.keychain`), ambayo inahifadhi **akidi za mfumo mzima** kama vile nywila za WiFi, vyeti vya mizizi ya mfumo, funguo za faragha za mfumo, na nywila za programu za mfumo.

### Upatikanaji wa Nywila ya Keychain

Faili hizi, ingawa hazina ulinzi wa ndani na zinaweza **kupakuliwa**, zimefungwa na zinahitaji **nywila ya mtumiaji ya maandiko ili kufunguliwa**. Chombo kama [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kinaweza kutumika kwa kufungua.

## Ulinzi wa Kuingia kwa Keychain

### ACLs

Kila kuingia katika keychain inasimamiwa na **Orodha za Udhibiti wa Upatikanaji (ACLs)** ambazo zinaelekeza nani anaweza kufanya vitendo mbalimbali kwenye kuingia kwa keychain, ikiwa ni pamoja na:

* **ACLAuhtorizationExportClear**: Inaruhusu mwenyewe kupata maandiko ya siri.
* **ACLAuhtorizationExportWrapped**: Inaruhusu mwenyewe kupata maandiko ya wazi yaliyofichwa kwa nywila nyingine iliyotolewa.
* **ACLAuhtorizationAny**: Inaruhusu mwenyewe kufanya kitendo chochote.

ACLs zinakuja na **orodha ya programu zinazotegemewa** ambazo zinaweza kufanya vitendo hivi bila kuombwa. Hii inaweza kuwa:

* **N`il`** (hakuna idhini inayohitajika, **kila mtu anategemewa**)
* Orodha **tyupu** (**hakuna mtu** anategemewa)
* **Orodha** ya **programu** maalum.

Pia kuingia kunaweza kuwa na funguo **`ACLAuthorizationPartitionID`,** ambayo inatumika kutambua **teamid, apple,** na **cdhash.**

* Ikiwa **teamid** imeainishwa, basi ili **kupata thamani ya kuingia** **bila** **kuombwa** programu inayotumika lazima iwe na **teamid sawa**.
* Ikiwa **apple** imeainishwa, basi programu inahitaji kuwa **imewekwa saini** na **Apple**.
* Ikiwa **cdhash** imeainishwa, basi **programu** lazima iwe na **cdhash** maalum.

### Kuunda Kuingia kwa Keychain

Wakati **kuingia** **mpya** inaundwa kwa kutumia **`Keychain Access.app`**, sheria zifuatazo zinatumika:

* Programu zote zinaweza kuficha.
* **Hakuna programu** zinaweza kusafirisha/kufungua (bila kuombwa mtumiaji).
* Programu zote zinaweza kuona ukaguzi wa uaminifu.
* Hakuna programu zinaweza kubadilisha ACLs.
* **partitionID** imewekwa kuwa **`apple`**.

Wakati **programu inaunda kuingia katika keychain**, sheria ni tofauti kidogo:

* Programu zote zinaweza kuficha.
* Ni **programu inayounda** pekee (au programu nyingine yoyote iliyoongezwa wazi) zinaweza kusafirisha/kufungua (bila kuombwa mtumiaji).
* Programu zote zinaweza kuona ukaguzi wa uaminifu.
* Hakuna programu zinaweza kubadilisha ACLs.
* **partitionID** imewekwa kuwa **`teamid:[teamID hapa]`**.

## Upatikanaji wa Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
Utaratibu wa **kuhesabu na kutupa** siri ambazo **hazitazalisha ujumbe** zinaweza kufanywa kwa kutumia chombo [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Orodhesha na pata **habari** kuhusu kila kipengee cha keychain:

* API **`SecItemCopyMatching`** inatoa habari kuhusu kila kipengee na kuna baadhi ya sifa unaweza kuweka unapoitumia:
* **`kSecReturnData`**: Ikiwa ni kweli, itajaribu kufungua data (weka kuwa uongo ili kuepuka pop-up zinazoweza kutokea)
* **`kSecReturnRef`**: Pata pia rejea kwa kipengee cha keychain (weka kuwa kweli ikiwa baadaye utaona unaweza kufungua bila pop-up)
* **`kSecReturnAttributes`**: Pata metadata kuhusu vipengee
* **`kSecMatchLimit`**: Ni matokeo mangapi ya kurudisha
* **`kSecClass`**: Ni aina gani ya kipengee cha keychain

Pata **ACLs** za kila kipengee:

* Kwa kutumia API **`SecAccessCopyACLList`** unaweza kupata **ACL kwa kipengee cha keychain**, na itarudisha orodha ya ACLs (kama `ACLAuhtorizationExportClear` na nyingine zilizotajwa hapo awali) ambapo kila orodha ina:
* Maelezo
* **Orodha ya Maombi ya Kuaminika**. Hii inaweza kuwa:
* Programu: /Applications/Slack.app
* Binary: /usr/libexec/airportd
* Kundi: group://AirPort

Export data:

* API **`SecKeychainItemCopyContent`** inapata maandiko
* API **`SecItemExport`** inasafirisha funguo na vyeti lakini inaweza kuhitaji kuweka nywila ili kusafirisha yaliyomo kwa usimbuaji

Na haya ndiyo **mahitaji** ya kuwa na uwezo wa **kusafirisha siri bila ujumbe**:

* Ikiwa **1+ maombi ya kuaminika** yameorodheshwa:
* Inahitaji **idhini** sahihi (**`Nil`**, au kuwa **sehemu** ya orodha inayoruhusiwa ya maombi katika idhini ya kufikia habari ya siri)
* Inahitaji saini ya msimbo kuendana na **PartitionID**
* Inahitaji saini ya msimbo kuendana na ile ya **programu moja ya kuaminika** (au kuwa mwanachama wa kundi sahihi la KeychainAccessGroup)
* Ikiwa **maombi yote ni ya kuaminika**:
* Inahitaji **idhini** sahihi
* Inahitaji saini ya msimbo kuendana na **PartitionID**
* Ikiwa **hakuna PartitionID**, basi hii haitahitajika

{% hint style="danger" %}
Hivyo, ikiwa kuna **programu 1 iliyoorodheshwa**, unahitaji **kuingiza msimbo katika programu hiyo**.

Ikiwa **apple** inaonyeshwa katika **partitionID**, unaweza kuipata kwa kutumia **`osascript`** hivyo chochote kinachotegemea maombi yote na apple katika partitionID. **`Python`** inaweza pia kutumika kwa hili.
{% endhint %}

### Sifa mbili za ziada

* **Invisible**: Ni bendera ya boolean ili **kuficha** kipengee kutoka kwa programu ya **UI** Keychain
* **General**: Ni kuhifadhi **metadata** (hivyo HAIJASIMBULIWA)
* Microsoft ilikuwa ikihifadhi katika maandiko yote ya wazi tokens za refresher ili kufikia mwisho wa nyeti.

## Marejeleo

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)


{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
