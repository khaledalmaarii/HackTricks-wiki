# macOS tlhutlh, qach, Binaries & Memory

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ghItlh (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks qorwagh:

* QaghmoHwI' 'ej 'ej **HackTricks PDF** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **ghItlh** 'e' vItlhutlh!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) ghaH 'ej **pe'vIl** [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **ghItlh** [**NFTs**](https://opensea.io/collection/the-peass-family) **ghItlh**
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## File hierarchy layout

* **/Applications**: QaghmoHwI' 'e' vItlhutlh. bIngDaq users vItlhutlh.
* **/bin**: Command line binaries
* **/cores**: DaH jImej, 'oH vItlhutlh core dumps
* **/dev**: DaH jImej, 'oH vItlhutlh hardware devices vItlhutlh.
* **/etc**: vItlhutlh Configuration files
* **/Library**: preferences, caches 'ej logs vItlhutlh subdirectories 'ej files vItlhutlh. Library vItlhutlh root 'ej user's directory.
* **/private**: vItlhutlh, 'ach vItlhutlh mentioned folders symbolic links vItlhutlh.
* **/sbin**: vItlhutlh Essential system binaries (administration vItlhutlh)
* **/System**: File fo making OS X run. mostly Apple vItlhutlh files vItlhutlh (third party vItlhutlh).
* **/tmp**: Files 3 jajmey delete (soft link /private/tmp)
* **/Users**: Home directory users.
* **/usr**: Config 'ej system binaries
* **/var**: Log files
* **/Volumes**: mounted drives vItlhutlh appear.
* **/.vol**: `stat a.txt` running `16777223 7545753 -rw-r--r-- 1 username wheel ...` something like 'e' vItlhutlh file exists 'ej 'e' vItlhutlh inode number. 'e' vItlhutlh content access /.vol/ running `cat /.vol/16777223/7545753`

### Applications Folders

* **System applications** `/System/Applications` vItlhutlh
* **Installed** applications `/Applications` `~/Applications` vItlhutlh
* **Application data** `/Library/Application Support` root vItlhutlh applications running 'ej `~/Library/Application Support` applications running user.
* **Third-party applications** **daemons** **run as root** `/Library/PrivilegedHelperTools/` vItlhutlh
* **Sandboxed** apps `~/Library/Containers` vItlhutlh mapped. app folder named application's bundle ID (`com.apple.Safari`).
* **kernel** `/System/Library/Kernels/kernel` vItlhutlh
* **Apple's kernel extensions** `/System/Library/Extensions` vItlhutlh
* **Third-party kernel extensions** `/Library/Extensions` vItlhutlh

### Files with Sensitive Information

MacOS passwords vItlhutlh information stored places:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Vulnerable pkg installers

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X Specific Extensions

* **`.dmg`**: Apple Disk Image files vItlhutlh installers.
* **`.kext`**: It must follow a specific structure 'ej OS X version driver. (bundle vItlhutlh)
* **`.plist`**: Also known as property list stores information in XML or binary format.
* Can be XML or binary. Binary ones can be read with:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Apple applications follows directory structure (bundle vItlhutlh).
* **`.dylib`**: Dynamic libraries (Windows DLL files 'ej)
* **`.pkg`**: xar (eXtensible Archive format) vItlhutlh. installer command can be use to install contents files.
* **`.DS_Store`**: This file directory, attributes customisations vItlhutlh saves.
* **`.Spotlight-V100`**: This folder root directory volume system.
* **`.metadata_never_index`**: If file root volume Spotlight won't index volume.
* **`.noindex`**: Files folder extension Spotlight won't indexed.

### macOS Bundles

Bundle **directory** **looks like an object in Finder** (Bundle example `*.app` files).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

macOS (iOS) system shared libraries, frameworks dylibs, **combined into single file**, dyld shared cache. This improved performance, code loaded faster.

Similar dyld shared cache, kernel kernel extensions compiled kernel cache, loaded boot time.

libraries single file dylib shared cache extract possible binary [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) working nowadays [**dyldextractor**](https://github.com/arandomdev/dyldextractor) use:

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

**`/System/Library/dyld/`** **ghItlhvam** **`shared cache`** **tlhIngan Hol** **`/System/Library/dyld/`** **ghItlhvam** **leghlaHbe'**.

**iOS** **ghItlhvam** **`/System/Library/Caches/com.apple.dyld/`** **ghItlhvam** **leghlaHbe'**.

{% hint style="success" %}
**ghItlhvam** `dyld_shared_cache_util` **Qap** **tlhIngan Hol** **Hopper** **ghItlhvam** **leghlaHbe'** **libraries** **'ej** **vetlh** **'e'** **investigate** **'ej** **select** **'ej** **'e'** **want**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## **Special File Permissions**

### **Folder permissions**

**'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'ej** **'
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
**ghItlh** *file* **ACLs** *vItlhutlh* **'e'**:

```bash
ls -le file
```

The output will show the file's ACLs, including the permissions for different users and groups.
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**bIQtIn** **ACLs** **jImej** **ghItlh** **vetlh** **(vaj vItlhutlh):**

```bash
find / -type f -exec ls -le {} \; 2>/dev/null
```

**ghItlh** **vetlh** **(vaj vItlhutlh):**

```bash
find / -type f -exec ls -le {} \; 2>/dev/null
```

**bIQtIn** **ACLs** **jImej** **ghItlh** **vetlh** **(vaj vItlhutlh):**

```bash
find / -type f -exec ls -le {} \; 2>/dev/null
```

**ghItlh** **vetlh** **(vaj vItlhutlh):**

```bash
find / -type f -exec ls -le {} \; 2>/dev/null
```
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Resource Forks | macOS ADS

**Alternate Data Streams** jup 'oH **macOS** machin'e'. **com.apple.ResourceFork** jup **extended attribute** jatlh **file/..namedfork/rsrc** jatlh **file** vItlhutlh.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
**ghItlhvam** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tlhIngan** **Dochvam** **vItlhutlh** **tl
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Universal binaries &** Mach-o Format

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS memory dumping

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risk Category Files Mac OS

The directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` is where information about the **risk associated with different file extensions is stored**. This directory categorizes files into various risk levels, influencing how Safari handles these files upon download. The categories are as follows:

- **LSRiskCategorySafe**: Files in this category are considered **completely safe**. Safari will automatically open these files after they are downloaded.
- **LSRiskCategoryNeutral**: These files come with no warnings and are **not automatically opened** by Safari.
- **LSRiskCategoryUnsafeExecutable**: Files under this category **trigger a warning** indicating that the file is an application. This serves as a security measure to alert the user.
- **LSRiskCategoryMayContainUnsafeExecutable**: This category is for files, such as archives, that might contain an executable. Safari will **trigger a warning** unless it can verify that all contents are safe or neutral.

## Log files

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contains information about downloaded files, like the URL from where they were downloaded.
* **`/var/log/system.log`**: Main log of OSX systems. com.apple.syslogd.plist is responsible for the execution of syslogging (you can check if it's disabled looking for "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: These are the Apple System Logs which may contain interesting information.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stores recently accessed files and applications through "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stores items to launch upon system startup
* **`$HOME/Library/Logs/DiskUtility.log`**: Log file for thee DiskUtility App (info about drives, including USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data about wireless access points.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List of daemons deactivated.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
