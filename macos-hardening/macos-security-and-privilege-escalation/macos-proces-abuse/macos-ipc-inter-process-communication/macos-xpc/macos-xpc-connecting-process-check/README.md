# macOS XPC Verbindung Prozessprüfung

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## XPC Verbindung Prozessprüfung

Wenn eine Verbindung zu einem XPC-Dienst hergestellt wird, überprüft der Server, ob die Verbindung zulässig ist. Dies sind die üblicherweise durchgeführten Überprüfungen:

1. Überprüfen Sie, ob der verbindende **Prozess mit einem von Apple signierten** Zertifikat signiert ist (das nur von Apple vergeben wird).
* Wenn dies **nicht überprüft** wird, könnte ein Angreifer ein **gefälschtes Zertifikat** erstellen, um jede andere Überprüfung zu erfüllen.
2. Überprüfen Sie, ob der verbindende Prozess mit dem **Zertifikat der Organisation** signiert ist (Team-ID-Überprüfung).
* Wenn dies **nicht überprüft** wird, kann jedes Entwicklerzertifikat von Apple zum Signieren und zur Verbindung mit dem Dienst verwendet werden.
3. Überprüfen Sie, ob der verbindende Prozess eine **korrekte Bundle-ID** enthält.
* Wenn dies **nicht überprüft** wird, kann jedes von derselben Organisation signierte Tool verwendet werden, um mit dem XPC-Dienst zu interagieren.
4. (4 oder 5) Überprüfen Sie, ob der verbindende Prozess eine **korrekte Softwareversionsnummer** hat.
* Wenn dies **nicht überprüft** wird, können alte, unsichere Clients, die anfällig für Prozesseinspritzung sind, verwendet werden, um sich mit dem XPC-Dienst zu verbinden, selbst wenn die anderen Überprüfungen vorhanden sind.
5. (4 oder 5) Überprüfen Sie, ob der verbindende Prozess eine gehärtete Laufzeit ohne gefährliche Berechtigungen hat (wie solche, die das Laden beliebiger Bibliotheken oder die Verwendung von DYLD-Umgebungsvariablen ermöglichen).
1. Wenn dies **nicht überprüft** wird, könnte der Client **anfällig für Codeinjektion** sein.
6. Überprüfen Sie, ob der verbindende Prozess eine Berechtigung hat, die ihm die Verbindung mit dem Dienst ermöglicht. Dies gilt für Apple-Binärdateien.
7. Die **Überprüfung** muss **basierend** auf dem **Audit-Token des verbindenden Clients** erfolgen, **anstatt** auf seiner Prozess-ID (**PID**), da ersteres **PID-Wiederverwendungsangriffe** verhindert.
* Entwickler verwenden die Audit-Token-API-Routine **selten**, da sie **privat** ist und von Apple jederzeit **geändert** werden könnte. Außerdem ist die Verwendung privater APIs in Mac App Store-Apps nicht zulässig.
* Wenn die Methode **`processIdentifier`** verwendet wird, könnte sie anfällig sein.
* Anstelle von **`xpc_connection_get_audit_token`** sollte **`xpc_dictionary_get_audit_token`** verwendet werden, da letztere in bestimmten Situationen ebenfalls [anfällig sein könnte](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Kommunikationsangriffe

Weitere Informationen zum Angriff auf die PID-Wiederverwendung finden Sie unter:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Weitere Informationen zum Angriff auf **`xpc_connection_get_audit_token`** finden Sie unter:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Prävention von Downgrade-Angriffen

Trustcache ist eine defensive Methode, die in Apple Silicon-Maschinen eingeführt wurde und eine Datenbank von CDHSAH von Apple-Binärdateien speichert, sodass nur zugelassene, nicht modifizierte Binärdateien ausgeführt werden können. Dadurch wird die Ausführung von Downgrade-Versionen verhindert.

### Codebeispiele

Der Server implementiert diese **Überprüfung** in einer Funktion namens **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

Das Objekt NSXPCConnection hat eine **private** Eigenschaft **`auditToken`** (die verwendet werden sollte, aber sich ändern könnte) und eine **öffentliche** Eigenschaft **`processIdentifier`** (die nicht verwendet werden sollte).

Der verbindende Prozess könnte mit etwas Ähnlichem überprüft werden:

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

Wenn ein Entwickler die Version des Clients nicht überprüfen möchte, könnte er zumindest überprüfen, ob der Client anfällig für Prozessinjektion ist:

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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
