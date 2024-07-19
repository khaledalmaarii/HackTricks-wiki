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

Kada se uspostavi veza sa XPC servisom, server će proveriti da li je veza dozvoljena. Ovo su provere koje bi obično izvršio:

1. Proveri da li je **proces koji se povezuje potpisan Apple-ovim** sertifikatom (samo ga Apple izdaje).
* Ako ovo **nije verifikovano**, napadač bi mogao da kreira **lažni sertifikat** koji bi odgovarao bilo kojoj drugoj proveri.
2. Proveri da li je proces koji se povezuje potpisan **sertifikatom organizacije** (verifikacija tim ID-a).
* Ako ovo **nije verifikovano**, **bilo koji developerski sertifikat** od Apple-a može se koristiti za potpisivanje i povezivanje sa servisom.
3. Proveri da li proces koji se povezuje **sadrži odgovarajući bundle ID**.
* Ako ovo **nije verifikovano**, bilo koji alat **potpisan od iste organizacije** mogao bi se koristiti za interakciju sa XPC servisom.
4. (4 ili 5) Proveri da li proces koji se povezuje ima **odgovarajući broj verzije softvera**.
* Ako ovo **nije verifikovano**, stari, nesigurni klijenti, ranjivi na injekciju procesa mogli bi se koristiti za povezivanje sa XPC servisom čak i uz druge provere.
5. (4 ili 5) Proveri da li proces koji se povezuje ima ojačanu runtime bez opasnih prava (kao što su ona koja omogućavaju učitavanje proizvoljnih biblioteka ili korišćenje DYLD env varijabli).
* Ako ovo **nije verifikovano**, klijent bi mogao biti **ranjiv na injekciju koda**.
6. Proveri da li proces koji se povezuje ima **pravo** koje mu omogućava povezivanje sa servisom. Ovo se primenjuje na Apple binarne datoteke.
7. **Verifikacija** mora biti **zasnovana** na **audit token-u klijenta** **umesto** na njegovom ID-u procesa (**PID**) jer prvi sprečava **napade ponovne upotrebe PID-a**.
* Programeri **retko koriste audit token** API poziv jer je **privatan**, tako da Apple može **promeniti** u bilo kojem trenutku. Pored toga, korišćenje privatnog API-ja nije dozvoljeno u aplikacijama Mac App Store-a.
* Ako se koristi metoda **`processIdentifier`**, može biti ranjiva.
* **`xpc_dictionary_get_audit_token`** treba koristiti umesto **`xpc_connection_get_audit_token`**, jer bi poslednji mogao biti [ranjiv u određenim situacijama](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Za više informacija o napadu ponovne upotrebe PID-a proverite:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Za više informacija o napadu **`xpc_connection_get_audit_token`** proverite:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Downgrade Attacks Prevention

Trustcache je odbrambena metoda uvedena u Apple Silicon mašinama koja čuva bazu podataka CDHSAH Apple binarnih datoteka tako da samo dozvoljene neizmenjene binarne datoteke mogu biti izvršene. Što sprečava izvršavanje verzija sa smanjenim nivoom.

### Code Examples

Server će implementirati ovu **verifikaciju** u funkciji pod nazivom **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Objekat NSXPCConnection ima **privatnu** osobinu **`auditToken`** (onu koja bi trebala da se koristi, ali može da se promeni) i **javnu** osobinu **`processIdentifier`** (onu koja ne bi trebala da se koristi).

Povezani proces može se verifikovati sa nečim poput:

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

Ako programer ne želi da proveri verziju klijenta, mogao bi da proveri da klijent nije podložan injekciji procesa barem:

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
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
