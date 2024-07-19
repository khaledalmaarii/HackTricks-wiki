# macOS XPC Connecting Process Check

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## XPC Connecting Process Check

Wanneer 'n verbinding met 'n XPC-diens tot stand gebring word, sal die bediener nagaan of die verbinding toegelaat word. Dit is die kontroles wat dit gewoonlik sal uitvoer:

1. Kyk of die verbindende **proses onderteken is met 'n Apple-ondertekende** sertifikaat (slegs deur Apple gegee).
* As dit **nie geverifieer is nie**, kan 'n aanvaller 'n **valse sertifikaat** skep om aan enige ander kontrole te voldoen.
2. Kyk of die verbindende proses onderteken is met die **organisasie se sertifikaat**, (span ID verifikasie).
* As dit **nie geverifieer is nie**, kan **enige ontwikkelaar sertifikaat** van Apple gebruik word om te onderteken, en met die diens te verbind.
3. Kyk of die verbindende proses **'n behoorlike bundel ID** bevat.
* As dit **nie geverifieer is nie**, kan enige hulpmiddel **onderteken deur dieselfde org** gebruik word om met die XPC-diens te kommunikeer.
4. (4 of 5) Kyk of die verbindende proses 'n **behoorlike sagteware weergawe nommer** het.
* As dit **nie geverifieer is nie**, kan 'n ou, onveilige kliënt, kwesbaar vir proses inspuiting, gebruik word om met die XPC-diens te verbind, selfs met die ander kontroles in plek.
5. (4 of 5) Kyk of die verbindende proses 'n geharde tydperk het sonder gevaarlike regte (soos dié wat toelaat om arbitrêre biblioteke te laai of DYLD omgewings veranderlikes te gebruik).
1. As dit **nie geverifieer is nie**, mag die kliënt **kwesbaar wees vir kode inspuiting**.
6. Kyk of die verbindende proses 'n **regte** het wat dit toelaat om met die diens te verbind. Dit is van toepassing op Apple binêre.
7. Die **verifikasie** moet **gebaseer** wees op die verbindende **kliënt se oudit token** **in plaas van** sy proses ID (**PID**) aangesien die eerste **PID hergebruik aanvalle** voorkom.
* Ontwikkelaars **gebruik selde die oudit token** API-oproep aangesien dit **privaat** is, so Apple kan dit **enige tyd verander**. Boonop is privaat API gebruik nie toegelaat in Mac App Store toepassings nie.
* As die metode **`processIdentifier`** gebruik word, mag dit kwesbaar wees.
* **`xpc_dictionary_get_audit_token`** moet gebruik word in plaas van **`xpc_connection_get_audit_token`**, aangesien laasgenoemde ook [kwesbaar kan wees in sekere situasies](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Vir meer inligting oor die PID hergebruik aanval, kyk:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Vir meer inligting oor **`xpc_connection_get_audit_token`** aanval, kyk:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Downgrade Attacks Prevention

Trustcache is 'n defensiewe metode wat in Apple Silicon masjiene bekendgestel is wat 'n databasis van CDHSAH van Apple binêre stoor sodat slegs toegelate nie-gemodifiseerde binêre uitgevoer kan word. Dit voorkom die uitvoering van downgrade weergawes.

### Code Examples

Die bediener sal hierdie **verifikasie** in 'n funksie genaamd **`shouldAcceptNewConnection`** implementeer.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Die objek NSXPCConnection het 'n **private** eiendom **`auditToken`** (die een wat gebruik moet word maar kan verander) en 'n **public** eiendom **`processIdentifier`** (die een wat nie gebruik moet word nie).

Die verbindingsproses kan verifieer word met iets soos:

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

As 'n ontwikkelaar nie die weergawe van die kliënt wil nagaan nie, kan hy ten minste nagaan dat die kliënt nie kwesbaar is vir prosesinspuiting nie:

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
Leer en oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
