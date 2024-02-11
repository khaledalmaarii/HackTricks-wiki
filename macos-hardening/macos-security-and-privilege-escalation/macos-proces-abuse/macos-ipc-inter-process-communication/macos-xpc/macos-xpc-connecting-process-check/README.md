# Uthibitisho wa Uunganishaji wa Mchakato wa macOS XPC

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Uthibitisho wa Uunganishaji wa Mchakato wa XPC

Wakati uunganishaji unafanywa kwa huduma ya XPC, seva itathibitisha ikiwa uunganishaji huo unaruhusiwa. Hizi ni uthibitisho ambao kawaida hufanywa:

1. Angalia ikiwa **mchakato unaounganisha umesainiwa na cheti kilichosainiwa na Apple** (kinachotolewa tu na Apple).
* Ikiwa hii **haitathibitishwa**, mshambuliaji anaweza kuunda **cheti bandia** ili kufanana na uthibitisho mwingine wowote.
2. Angalia ikiwa mchakato unaounganisha umesainiwa na **cheti cha shirika** (uthibitisho wa kitambulisho cha timu).
* Ikiwa hii **haitathibitishwa**, **cheti chochote cha maendeleo** kutoka Apple kinaweza kutumika kwa kusaini na kuunganisha na huduma.
3. Angalia ikiwa mchakato unaounganisha una **kitambulisho sahihi cha kifurushi**.
* Ikiwa hii **haitathibitishwa**, zana yoyote **iliyosainiwa na shirika lile lile** inaweza kutumika kwa kuingiliana na huduma ya XPC.
4. (4 au 5) Angalia ikiwa mchakato unaounganisha una **nambari sahihi ya toleo la programu**.
* Ikiwa hii **haitathibitishwa**, wateja wazee na dhaifu, walio hatarini kwa kuingiza mchakato, wanaweza kutumika kuunganisha na huduma ya XPC hata na uthibitisho mwingine uliopo.
5. (4 au 5) Angalia ikiwa mchakato unaounganisha una **runtime imara bila ruhusa hatari** (kama zile zinazoruhusu kupakia maktaba za aina yoyote au kutumia mazingira ya DYLD)
1. Ikiwa hii **haitathibitishwa**, mteja anaweza kuwa **hatarini kwa kuingiza nambari**
6. Angalia ikiwa mchakato unaounganisha una **ruhusa** inayoruhusu kuunganisha na huduma. Hii inatumika kwa programu za Apple.
7. **Uthibitisho** lazima uwe **kulingana** na **kitambulisho cha ukaguzi cha mteja kinachounganisha** badala ya Kitambulisho cha Mchakato (**PID**) kwani cha kwanza kinazuia mashambulizi ya kutumia tena PID.
* Watengenezaji **mara chache hutumia wito wa API ya kitambulisho cha ukaguzi** kwani ni **binafsi**, kwa hivyo Apple inaweza **kubadilisha** wakati wowote. Kwa kuongezea, matumizi ya API binafsi hayaruhusiwi katika programu za Duka la App la Mac.
* Ikiwa njia ya **`processIdentifier`** inatumika, inaweza kuwa hatarini
* Badala ya **`xpc_connection_get_audit_token`**, inapaswa kutumika **`xpc_dictionary_get_audit_token`**, kwani ya mwisho inaweza pia kuwa [hatarini katika hali fulani](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Mashambulizi ya Mawasiliano

Kwa habari zaidi kuhusu shambulio la kutumia tena PID angalia:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Kwa habari zaidi kuhusu shambulio la **`xpc_connection_get_audit_token`** angalia:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Kuzuia Mashambulizi ya Kupunguza - Trustcache

Trustcache ni njia ya ulinzi iliyoletwa kwenye mashine za Apple Silicon ambayo inahifadhi kwenye hifadhidata CDHSAH ya programu za Apple ili tu programu zisizobadilishwa zinazoruhusiwa ziweze kutekelezwa. Hii inazuia utekelezaji wa toleo za kupunguza.

### Mifano ya Nambari

Seva itatekeleza uthibitisho huu katika kazi inayoitwa **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Kitu NSXPCConnection ina mali ya **binafsi** **`auditToken`** (ile inayopaswa kutumika lakini inaweza kubadilika) na mali ya **umma** **`processIdentifier`** (ile ambayo haipaswi kutumika).

Mchakato wa kuunganisha unaweza kuthibitishwa kwa kitu kama hiki:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

Ikiwa msanidi programu hataki kuangalia toleo la mteja, anaweza angalia kuwa mteja hana udhaifu wa kuingiza mchakato angalau:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
