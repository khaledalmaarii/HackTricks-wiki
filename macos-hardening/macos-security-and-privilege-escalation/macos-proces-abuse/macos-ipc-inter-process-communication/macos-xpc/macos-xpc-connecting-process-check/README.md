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

Gdy nawiązywane jest połączenie z usługą XPC, serwer sprawdzi, czy połączenie jest dozwolone. Oto kontrole, które zazwyczaj są przeprowadzane:

1. Sprawdź, czy **proces łączący jest podpisany certyfikatem podpisanym przez Apple** (wydawanym tylko przez Apple).
* Jeśli to **nie jest zweryfikowane**, atakujący może stworzyć **fałszywy certyfikat**, aby dopasować się do innej kontroli.
2. Sprawdź, czy proces łączący jest podpisany **certyfikatem organizacji** (weryfikacja ID zespołu).
* Jeśli to **nie jest zweryfikowane**, **dowolny certyfikat dewelopera** z Apple może być użyty do podpisania i połączenia z usługą.
3. Sprawdź, czy proces łączący **zawiera odpowiedni identyfikator pakietu**.
* Jeśli to **nie jest zweryfikowane**, każde narzędzie **podpisane przez tę samą organizację** może być użyte do interakcji z usługą XPC.
4. (4 lub 5) Sprawdź, czy proces łączący ma **odpowiedni numer wersji oprogramowania**.
* Jeśli to **nie jest zweryfikowane**, stary, niebezpieczny klient, podatny na wstrzykiwanie procesów, może być użyty do połączenia z usługą XPC, nawet przy innych kontrolach.
5. (4 lub 5) Sprawdź, czy proces łączący ma wzmocniony czas działania bez niebezpiecznych uprawnień (jak te, które pozwalają na ładowanie dowolnych bibliotek lub używanie zmiennych środowiskowych DYLD).
* Jeśli to **nie jest zweryfikowane**, klient może być **podatny na wstrzykiwanie kodu**.
6. Sprawdź, czy proces łączący ma **uprawnienie**, które pozwala mu połączyć się z usługą. To dotyczy binarnych plików Apple.
7. **Weryfikacja** musi być **oparta** na **tokenie audytu klienta** **zamiast** na jego identyfikatorze procesu (**PID**), ponieważ ten pierwszy zapobiega **atakom na ponowne użycie PID**.
* Deweloperzy **rzadko używają tokena audytu** w wywołaniach API, ponieważ jest on **prywatny**, więc Apple może **zmienić** go w dowolnym momencie. Dodatkowo, użycie prywatnych API nie jest dozwolone w aplikacjach Mac App Store.
* Jeśli używana jest metoda **`processIdentifier`**, może być podatna.
* **`xpc_dictionary_get_audit_token`** powinno być używane zamiast **`xpc_connection_get_audit_token`**, ponieważ to ostatnie może być również [podatne w pewnych sytuacjach](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Aby uzyskać więcej informacji na temat ataku ponownego użycia PID, sprawdź:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Aby uzyskać więcej informacji o ataku **`xpc_connection_get_audit_token`**, sprawdź:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Downgrade Attacks Prevention

Trustcache to metoda obronna wprowadzona w maszynach Apple Silicon, która przechowuje bazę danych CDHSAH binarnych plików Apple, aby tylko dozwolone, niezmodyfikowane binaria mogły być wykonywane. Co zapobiega wykonywaniu wersji downgrade.

### Code Examples

Serwer zaimplementuje tę **weryfikację** w funkcji zwanej **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Obiekt NSXPCConnection ma **prywatną** właściwość **`auditToken`** (ta, która powinna być używana, ale może się zmienić) oraz **publiczną** właściwość **`processIdentifier`** (ta, która nie powinna być używana).

Proces łączący można zweryfikować za pomocą czegoś takiego:

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

Jeśli deweloper nie chce sprawdzać wersji klienta, może przynajmniej sprawdzić, że klient nie jest podatny na wstrzykiwanie procesów:

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
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
