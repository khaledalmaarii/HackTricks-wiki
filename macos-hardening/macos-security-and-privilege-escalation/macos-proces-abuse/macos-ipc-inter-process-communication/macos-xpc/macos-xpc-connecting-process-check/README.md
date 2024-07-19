# macOS XPC Connecting Process Check

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

## XPC Connecting Process Check

Wakati muunganisho unapoanzishwa na huduma ya XPC, seva itakagua ikiwa muunganisho unaruhusiwa. Hizi ndizo ukaguzi ambao kawaida hufanywa:

1. Angalia ikiwa **mchakato unaounganisha umeandikwa na cheti kilichosainiwa na Apple** (ambacho kinatolewa tu na Apple).
* Ikiwa hii **haijathibitishwa**, mshambuliaji anaweza kuunda **cheti bandia** ili kufanana na ukaguzi mwingine wowote.
2. Angalia ikiwa mchakato unaounganisha umeandikwa na **cheti cha shirika**, (uthibitisho wa kitambulisho cha timu).
* Ikiwa hii **haijathibitishwa**, **cheti chochote cha mende** kutoka Apple kinaweza kutumika kwa kusaini, na kuungana na huduma.
3. Angalia ikiwa mchakato unaounganisha **una kitambulisho sahihi cha kifurushi**.
* Ikiwa hii **haijathibitishwa**, chombo chochote **kilichosainiwa na shirika hilo hilo** kinaweza kutumika kuingiliana na huduma ya XPC.
4. (4 au 5) Angalia ikiwa mchakato unaounganisha una **nambari sahihi ya toleo la programu**.
* Ikiwa hii **haijathibitishwa**, wateja wa zamani, wasio salama, walio hatarini kwa sindano ya mchakato wanaweza kutumika kuungana na huduma ya XPC hata na ukaguzi mwingine ukiwa mahali.
5. (4 au 5) Angalia ikiwa mchakato unaounganisha una mazingira ya runtime yaliyohakikishwa bila ruhusa hatari (kama zile zinazoruhusu kupakia maktaba za kawaida au kutumia DYLD env vars)
1. Ikiwa hii **haijathibitishwa**, mteja anaweza kuwa **hatari kwa sindano ya msimbo**
6. Angalia ikiwa mchakato unaounganisha una **ruhusa** inayoruhusu kuungana na huduma. Hii inatumika kwa binaries za Apple.
7. **Uthibitisho** lazima uwe **kulingana** na **tokeni ya ukaguzi ya mteja** **badala** ya kitambulisho chake cha mchakato (**PID**) kwani ya kwanza inazuia **shambulio la upya la PID**.
* Wandevu **hawatumii mara kwa mara tokeni ya ukaguzi** API wito kwani ni **binafsi**, hivyo Apple inaweza **kubadilisha** wakati wowote. Zaidi ya hayo, matumizi ya API binafsi hayaruhusiwi katika programu za Duka la Mac.
* Ikiwa njia **`processIdentifier`** inatumika, inaweza kuwa hatari
* **`xpc_dictionary_get_audit_token`** inapaswa kutumika badala ya **`xpc_connection_get_audit_token`**, kwani ya mwisho inaweza pia kuwa [hatari katika hali fulani](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Kwa maelezo zaidi kuhusu shambulio la upya la PID angalia:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Kwa maelezo zaidi **`xpc_connection_get_audit_token`** shambulio angalia:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Downgrade Attacks Prevention

Trustcache ni njia ya kujihami iliyowekwa katika mashine za Apple Silicon ambayo inahifadhi hifadhidata ya CDHSAH ya binaries za Apple ili tu binaries zisizobadilishwa zinazoruhusiwa ziweze kutekelezwa. Hii inazuia utekelezaji wa toleo la kudharau.

### Code Examples

Seva itatekeleza **uthibitisho** huu katika kazi inayoitwa **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Kitu NSXPCConnection kina mali **ya faragha** **`auditToken`** (ile ambayo inapaswa kutumika lakini inaweza kubadilika) na mali **ya umma** **`processIdentifier`** (ile ambayo haipaswi kutumika).

Mchakato unaounganisha unaweza kuthibitishwa kwa kitu kama:

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

Ikiwa mendelevu hataki kuangalia toleo la mteja, anaweza kuangalia kwamba mteja si hatarini kwa sindano ya mchakato angalau:

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

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
