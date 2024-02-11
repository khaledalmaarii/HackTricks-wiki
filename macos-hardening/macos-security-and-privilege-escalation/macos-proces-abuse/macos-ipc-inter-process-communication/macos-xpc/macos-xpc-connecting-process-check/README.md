# Sprawdzanie procesu łączącego się z macOS XPC

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Sprawdzanie procesu łączącego się z XPC

Gdy nawiązywane jest połączenie z usługą XPC, serwer sprawdzi, czy połączenie jest dozwolone. Oto zwykle wykonywane sprawdzenia:

1. Sprawdzenie, czy łączący się **proces jest podpisany certyfikatem Apple** (wydanym tylko przez Apple).
* Jeśli to **nie zostanie zweryfikowane**, atakujący może stworzyć **fałszywy certyfikat**, aby dopasować się do innych sprawdzeń.
2. Sprawdzenie, czy łączący się proces jest podpisany **certyfikatem organizacji** (weryfikacja identyfikatora zespołu).
* Jeśli to **nie zostanie zweryfikowane**, **dowolny certyfikat dewelopera** od Apple może być używany do podpisania i połączenia z usługą.
3. Sprawdzenie, czy łączący się proces **zawiera właściwy identyfikator pakietu**.
* Jeśli to **nie zostanie zweryfikowane**, dowolne narzędzie **podpisane przez tę samą organizację** może być używane do interakcji z usługą XPC.
4. (4 lub 5) Sprawdzenie, czy łączący się proces ma **właściwy numer wersji oprogramowania**.
* Jeśli to **nie zostanie zweryfikowane**, stare, podatne klienty, podatne na wstrzykiwanie procesów, mogą być używane do połączenia z usługą XPC, nawet jeśli inne sprawdzenia są włączone.
5. (4 lub 5) Sprawdzenie, czy łączący się proces ma zabezpieczony czas wykonania bez niebezpiecznych uprawnień (takich jak te, które pozwalają na ładowanie dowolnych bibliotek lub korzystanie z zmiennych środowiskowych DYLD)
1. Jeśli to **nie zostanie zweryfikowane**, klient może być **podatny na wstrzykiwanie kodu**.
6. Sprawdzenie, czy łączący się proces ma **uprawnienie**, które pozwala mu na połączenie się z usługą. Dotyczy to binarnych plików Apple.
7. **Weryfikacja** musi być **oparta** na **tokenie audytu klienta łączącego się** **zamiast** na jego identyfikatorze procesu (**PID**), ponieważ to pierwsze zapobiega **atakowi ponownego wykorzystania PID**.
* Deweloperzy **rzadko korzystają z wywołania API tokena audytu**, ponieważ jest ono **prywatne**, więc Apple może je **zmienić** w dowolnym momencie. Ponadto, korzystanie z prywatnego interfejsu API nie jest dozwolone w aplikacjach Mac App Store.
* Jeśli używana jest metoda **`processIdentifier`**, może być podatna
* Zamiast **`xpc_connection_get_audit_token`** należy używać **`xpc_dictionary_get_audit_token`**, ponieważ ta ostatnia może również być [podatna w określonych sytuacjach](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Ataki komunikacyjne

Aby uzyskać więcej informacji na temat ataku ponownego wykorzystania PID, sprawdź:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Aby uzyskać więcej informacji na temat ataku **`xpc_connection_get_audit_token`**, sprawdź:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Zapobieganie atakom na obniżenie wersji Trustcache

Trustcache to metoda obronna wprowadzona w maszynach Apple Silicon, która przechowuje bazę danych CDHSAH binarnych plików Apple, dzięki czemu można uruchamiać tylko dozwolone, niezmodyfikowane wersje. Zapobiega to wykonywaniu obniżonych wersji.

### Przykłady kodu

Serwer będzie implementował tę **weryfikację** w funkcji o nazwie **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Obiekt NSXPCConnection ma **prywatną** właściwość **`auditToken`** (ta, która powinna być używana, ale może się zmienić) oraz **publiczną** właściwość **`processIdentifier`** (ta, która nie powinna być używana).

Proces łączący można zweryfikować przy użyciu czegoś takiego jak:

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

Jeśli programista nie chce sprawdzać wersji klienta, może przynajmniej sprawdzić, czy klient nie jest podatny na wstrzykiwanie procesu:

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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
