# macOS XPC Verbindende Prosessie Kontroleer

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## XPC Verbindende Prosessie Kontroleer

Wanneer 'n verbinding met 'n XPC-diens tot stand gebring word, sal die bediener nagaan of die verbinding toegelaat word. Dit is die kontroles wat gewoonlik uitgevoer word:

1. Kyk of die verbindende **proses onderteken is met 'n Apple-ondertekende** sertifikaat (slegs deur Apple uitgereik).
* As dit **nie geverifieer word nie**, kan 'n aanvaller 'n **vals sertifikaat** skep om enige ander kontrole te pas.
2. Kyk of die verbindende proses onderteken is met die **organisasie se sertifikaat**, (span-ID-verifikasie).
* As dit **nie geverifieer word nie**, kan **enige ontwikkelaarssertifikaat** van Apple gebruik word vir ondertekening en om met die diens te verbind.
3. Kyk of die verbindende proses **'n korrekte bundel-ID** bevat.
* As dit **nie geverifieer word nie**, kan enige instrument **onderteken deur dieselfde organisasie** gebruik word om met die XPC-diens te kommunikeer.
4. (4 of 5) Kyk of die verbindende proses 'n **korrekte sagteware-weergawe-nommer** het.
* As dit **nie geverifieer word nie**, kan 'n ou, onveilige kliënte wat vatbaar is vir prosesinjeksie, gebruik word om selfs met die ander kontroles in plek met die XPC-diens te verbind.
5. (4 of 5) Kyk of die verbindende proses 'n geharde uitvoertyd het sonder gevaarlike toekennings (soos diegene wat die laai van willekeurige biblioteke of die gebruik van DYLD-omgewingsveranderlikes toelaat).
1. As dit **nie geverifieer word nie**, kan die kliënt **vatbaar wees vir koderingsinjeksie**
6. Kyk of die verbindende proses 'n **toekennings** het wat dit in staat stel om met die diens te verbind. Dit is van toepassing op Apple-binêres.
7. Die **verifikasie** moet **gebaseer** wees op die verbindende **kliënt se oudit-token** **in plaas** van sy proses-ID (**PID**) aangesien die eerste **PID-hergebruikaanvalle** voorkom.
* Ontwikkelaars gebruik **skaars die oudit-token** API-oproep aangesien dit **privaat** is, sodat Apple dit enige tyd kan **verander**. Daarbenewens is die gebruik van private API's nie toegelaat in Mac App Store-toepassings nie.
* As die metode **`processIdentifier`** gebruik word, kan dit vatbaar wees
* **`xpc_dictionary_get_audit_token`** moet eerder gebruik word as **`xpc_connection_get_audit_token`**, aangesien die laaste ook [vatbaar kan wees in sekere situasies](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Kommunikasie-aanvalle

Vir meer inligting oor die PID-hergebruikaanval, kyk na:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Vir meer inligting oor die **`xpc_connection_get_audit_token`**-aanval, kyk na:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Voorkoming van Afwaartse Aanvalle

Trustcache is 'n verdedigingsmetode wat in Apple Silicon-masjiene ingevoer is en 'n databasis van CDHSAH van Apple-binêres stoor, sodat slegs toegelate, onveranderde binêres uitgevoer kan word. Dit voorkom die uitvoering van afwaartse weergawes.

### Kodevoorbeelde

Die bediener sal hierdie **verifikasie** implementeer in 'n funksie genaamd **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Die objek NSXPCConnection het 'n **privaat** eienskap **`auditToken`** (die een wat gebruik moet word maar kan verander) en 'n **publieke** eienskap **`processIdentifier`** (die een wat nie gebruik moet word nie).

Die verbindende proses kan geverifieer word met iets soos:

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

As 'n ontwikkelaar nie die weergawe van die kliënt wil nagaan nie, kan hy ten minste nagaan of die kliënt vatbaar is vir prosesinjeksie:

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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
