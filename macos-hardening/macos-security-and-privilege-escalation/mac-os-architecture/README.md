# macOS Kernel & System Extensions

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## XNU Kernel

**macOS** jup XNU **core**, 'ej "X is Not Unix" jatlh. vItlhutlh kernel **Mach microkernel** (qaStaHvIS), **'ej** Berkeley Software Distribution (**BSD**) 'e' vItlhutlh. XNU 'ej **kernel drivers** 'e' vItlhutlh **I/O Kit** jatlh. XNU kernel **Darwin** open source project 'e' vItlhutlh, 'ej **source code** vItlhutlh **freely accessible**.

**macOS** security researcher 'ej Unix developer perspective, **macOS** **FreeBSD** system **similar** jatlh **elegant GUI** 'ej **custom applications**. BSD vItlhutlh **applications** developed **macOS** **compile** 'ej **run** **modifications**, **command-line tools** familiar **Unix users** vItlhutlh **macOS**. 'ach, XNU kernel incorporates Mach, **traditional Unix-like system** 'ej macOS **difference** **potential issues** 'ej **unique advantages**.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach **microkernel** vItlhutlh **UNIX-compatible**. Mach **key design principles** 'oH minimize **code** running **kernel** space 'ej **allow** many **typical kernel functions**, such **file system**, **networking**, 'ej **I/O**, **run user-level tasks**.

XNU, Mach vItlhutlh **responsible** many **critical low-level operations** kernel typically handles, such **processor scheduling**, **multitasking**, 'ej **virtual memory management**.

### BSD

XNU **kernel** vItlhutlh **incorporates** significant amount code derived **FreeBSD** project. 'ej code **run** **kernel** along Mach, **same address space**. 'ach, FreeBSD code within XNU **differ** substantially **original FreeBSD code** modifications required **compatibility** Mach. FreeBSD contributes many kernel operations including:

* Process management
* Signal handling
* Basic security mechanisms, including user and group management
* System call infrastructure
* TCP/IP stack and sockets
* Firewall and packet filtering

BSD 'ej Mach interaction **complex**, due **different conceptual frameworks**. 'ach, XNU **associate** BSD process **Mach task** contains **one Mach thread**. BSD's fork() system call used, BSD code within kernel **Mach functions** create task 'ej thread structure.

**Mach** 'ej **BSD** vItlhutlh **different security models**: Mach's security model **port rights** based, whereas BSD's security model operates based **process ownership**. Disparities between models occasionally resulted **local privilege-escalation vulnerabilities**. 'ach, typical system calls, **Mach traps** allow user-space programs **interact** kernel. 'ej elements together form multifaceted, hybrid architecture macOS kernel.

### I/O Kit - Drivers

I/O Kit vItlhutlh **open-source**, **object-oriented device-driver framework** XNU kernel, handles **dynamically loaded device drivers**. 'oH modular code **added** kernel on-the-fly, supporting diverse hardware.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Inter Process Communication

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Kernelcache vItlhutlh **pre-compiled** 'ej **pre-linked version** XNU kernel, along **essential device drivers** 'ej **kernel extensions**. 'oH stored **compressed** format 'ej gets decompressed memory during boot-up process. Kernelcache facilitates **faster boot time** having ready-to-run version kernel 'ej crucial drivers available, reducing time 'ej resources spent dynamically loading 'ej linking components boot time.

iOS **located** **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** macOS **find** **`find / -name kernelcache 2>/dev/null`**

#### IMG4

IMG4 file format vItlhutlh **container format** used Apple iOS 'ej macOS devices securely **storing 'ej verifying firmware** components (like **kernelcache**). IMG4 format includes header 'ej several tags encapsulate different pieces data including actual payload (like kernel 'ej bootloader), signature, 'ej set manifest properties. Format supports cryptographic verification, allowing device confirm authenticity 'ej integrity firmware component executing it.

Usually composed following components:

* Payload (IM4P):
* Often compressed (LZFSE4, LZSS, ...)
* Optionally encrypted
* Manifest (IM4M):
* Contains Signature
* Additional Key/Value dictionary
* Restore Info (IM4R):
* Also known APNonce
* Prevents replaying updates
* OPTIONAL: Usually this isn't found

Decompress the Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Kernelcache Symbols

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

These are Apple **firmwares** you can download from [**https://ipsw.me/**](https://ipsw.me/). Among other files it will contains the **kernelcache**.\
To **extract** the files you can just **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
**`nm -a kernelcache.release.iphone14.e | wc -l`**  **tlhIngan Hol:**
**`nm -a kernelcache.release.iphone14.e | wc -l`**  **tlhIngan Hol:**

**'kernelcache.release.iphone14.e'** **tlhIngan Hol:**
**'kernelcache.release.iphone14.e'** **tlhIngan Hol:**

**'extract all the extensions'** **tlhIngan Hol:**
**'extract all the extensions'** **tlhIngan Hol:**

**'one you are interested in'** **tlhIngan Hol:**
**'one you are interested in'** **tlhIngan Hol:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS Kernel Extensions

macOS **tlhIngan Hol** **QaQ** **Kernel Extensions** (.kext) **ghaH** **super restrictive** **vaj** **load** **QaQ** **Kernel Extensions** **(vaj)** **high privileges** **code** **run** **with**. **Actually**, **default** **virtually impossible** (unless **bypass** **found**).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS System Extensions

**Kernel Extensions** **vaj** **macOS** **created** **System Extensions**, **vaj** **offers** **user level APIs** **interact** **kernel**. **This way**, **developers** **avoid** **use** **kernel extensions**.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## References

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
