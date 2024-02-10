# macOS SIP

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Basic Information**

**System Integrity Protection (SIP)** in macOS is a mechanism designed to prevent even the most privileged users from making unauthorized changes to key system folders. This feature plays a crucial role in maintaining the integrity of the system by restricting actions like adding, modifying, or deleting files in protected areas. The primary folders shielded by SIP include:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

The rules that govern SIP's behavior are defined in the configuration file located at **`/System/Library/Sandbox/rootless.conf`**. Within this file, paths that are prefixed with an asterisk (*) are denoted as exceptions to the otherwise stringent SIP restrictions.

Consider the example below:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
**`SIP`** **`/usr`** **`/usr/libexec/cups`** **`/usr/local`** **`/usr/share/man`** **`ls -lOd`** **`restricted`** **`sunlnk`**
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In this case, the **`sunlnk`** flag signifies that the `/usr/libexec/cups` directory itself **cannot be deleted**, though files within it can be created, modified, or deleted.

On the other hand:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
DaH, **`restricted`** qutlh /usr/libexec qachDaq SIP qoH. SIP qutlhDI' qachDaq, lo'laHbe'chugh, maqtaHvIS, 'ej lo'laHbe'chughDaq vItlhutlh.

Qatlh **`com.apple.rootless`** vItlhutlhDI' vItlhutlhDaq, vItlhutlh qutlhDI' SIP qoH.

**SIP** qutlhDI' **root** chenmoH:

* lo'laHbe'chugh kernel extensions lo'laHbe'chugh
* Apple-signed processes task-ports laH
* NVRAM variables maqtaHvIS
* kernel debugging laH

bitflag (`csr-active-config` Intel 'ej `lp-sip0` booted Device Tree ARM) nvram variable vItlhutlhDI' jImej. vItlhutlhDI' flags XNU source code 'ej 'ej vItlhutlhDI' `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP Status

SIP vItlhutlhDI' lo'laHbe'chugh command vItlhutlh:
```bash
csrutil status
```
**Translation (Klingon):**

```
SIP janglu'chugh, vaj SIQmeyDaq Quch (Command+R) ngevwI' 'ej vItlhutlh 'e' vItlhutlh: 
```
```bash
csrutil disable
```
**Klingon Translation:**

```
Qaghmey SIP jatlh 'ej debugging protections vItlhutlhlaHbe'chugh, 'ej: 
```

**HTML Translation:**

```
<p>Qaghmey SIP jatlh 'ej debugging protections vItlhutlhlaHbe'chugh, 'ej:</p>
```
```bash
csrutil enable --without debug
```
### QaD jImej

- **QaDpu'wI'vam vItlhutlh** (kexts), vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
**Translation:**

**The exploitation of this vulnerability has severe implications. The `Info.plist` file, normally responsible for managing permissions for kernel extensions, becomes ineffective. This includes the inability to blacklist certain extensions, such as `AppleHWAccess.kext`. Consequently, with the SIP's control mechanism out of order, this extension can be loaded, granting unauthorized read and write access to the system's RAM.**

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**It was possible to mount a new file system over **SIP protected folders to bypass the protection**.**
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

The system is set to boot from an embedded installer disk image within the `Install macOS Sierra.app` to upgrade the OS, utilizing the `bless` utility. The command used is as follows:

#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

The system is set to boot from an embedded installer disk image within the `Install macOS Sierra.app` to upgrade the OS, utilizing the `bless` utility. The command used is as follows:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
The security of this process can be compromised if an attacker alters the upgrade image (`InstallESD.dmg`) before booting. The strategy involves substituting a dynamic loader (dyld) with a malicious version (`libBaseIA.dylib`). This replacement results in the execution of the attacker's code when the installer is initiated.

The attacker's code gains control during the upgrade process, exploiting the system's trust in the installer. The attack proceeds by altering the `InstallESD.dmg` image via method swizzling, particularly targeting the `extractBootBits` method. This allows the injection of malicious code before the disk image is employed.

Moreover, within the `InstallESD.dmg`, there's a `BaseSystem.dmg`, which serves as the upgrade code's root file system. Injecting a dynamic library into this allows the malicious code to operate within a process capable of altering OS-level files, significantly increasing the potential for system compromise.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In this talk from [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), it's shown how **`systemmigrationd`** (which can bypass SIP) executes a **bash** and a **perl** script, which can be abused via env variables **`BASH_ENV`** and **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
The entitlement **`com.apple.rootless.install`** allows to bypass SIP
{% endhint %}

The entitlement `com.apple.rootless.install` is known to bypass System Integrity Protection (SIP) on macOS. This was notably mentioned in relation to [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In this specific case, the system XPC service located at `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possesses this entitlement. This allows the related process to circumvent SIP constraints. Furthermore, this service notably presents a method that permits the movement of files without enforcing any security measures.


## Sealed System Snapshots

Sealed System Snapshots are a feature introduced by Apple in **macOS Big Sur (macOS 11)** as a part of its **System Integrity Protection (SIP)** mechanism to provide an additional layer of security and system stability. They are essentially read-only versions of the system volume.

Here's a more detailed look:

1. **Immutable System**: Sealed System Snapshots make the macOS system volume "immutable", meaning that it cannot be modified. This prevents any unauthorised or accidental changes to the system that could compromise security or system stability.
2. **System Software Updates**: When you install macOS updates or upgrades, macOS creates a new system snapshot. The macOS startup volume then uses **APFS (Apple File System)** to switch to this new snapshot. The entire process of applying updates becomes safer and more reliable as the system can always revert to the previous snapshot if something goes wrong during the update.
3. **Data Separation**: In conjunction with the concept of Data and System volume separation introduced in macOS Catalina, the Sealed System Snapshot feature makes sure that all your data and settings are stored on a separate "**Data**" volume. This separation makes your data independent from the system, which simplifies the process of system updates and enhances system security.

Remember that these snapshots are automatically managed by macOS and don't take up additional space on your disk, thanks to the space sharing capabilities of APFS. It’s also important to note that these snapshots are different from **Time Machine snapshots**, which are user-accessible backups of the entire system.

### Check Snapshots

The command **`diskutil apfs list`** lists the **details of the APFS volumes** and their layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

In the previous output it's possible to see that **user-accessible locations** are mounted under `/System/Volumes/Data`.

Moreover, **macOS System volume snapshot** is mounted in `/` and it's **sealed** (cryptographically signed by the OS). So, if SIP is bypassed and modifies it, the **OS won't boot anymore**.

It's also possible to **verify that seal is enabled** by running:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
**DaH jImej** vItlhutlh **read-only** **mounted**.
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>qaStaHvIS AWS hacking vItlhlaHbe'chugh</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks poH:

* **HackTricks** vItlhutlhlaH **company advertise** 'ej **HackTricks PDF download** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **chek**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) vItlhutlhlaH
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) vItlhutlhlaH, **exclusive NFTs** [**opensea.io**](https://opensea.io/collection/the-peass-family) **ghItlh**.
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **join** 'ej [**telegram group**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking tricks** **submit PRs** [**HackTricks**](https://github.com/carlospolop/hacktricks) 'ej [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **Share**.

</details>
