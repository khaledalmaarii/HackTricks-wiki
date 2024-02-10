# macOS Sandbox

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basic Information

MacOS Sandbox (initially called Seatbelt) **limits applications** running inside the sandbox to the **allowed actions specified in the Sandbox profile** the app is running with. This helps to ensure that **the application will be accessing only expected resources**.

Any app with the **entitlement** **`com.apple.security.app-sandbox`** will be executed inside the sandbox. **Apple binaries** are usually executed inside a Sandbox and in order to publish inside the **App Store**, **this entitlement is mandatory**. So most applications will be executed inside the sandbox.

In order to control what a process can or cannot do the **Sandbox has hooks** in all **syscalls** across the kernel. **Depending** on the **entitlements** of the app the Sandbox will **allow** certain actions.

Some important components of the Sandbox are:

* The **kernel extension** `/System/Library/Extensions/Sandbox.kext`
* The **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* A **daemon** running in userland `/usr/libexec/sandboxd`
* The **containers** `~/Library/Containers`

Inside the containers folder you can find **a folder for each app executed sandboxed** with the name of the bundle id:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
**tlhIngan Hol**:

ghItlhvamDaq Daqtagh 'e' vItlhutlh. **plist** 'ej **Data directory** jatlhpu' vItlhutlh 'ej App vIghro' vItlhutlh.
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
ghobe' vItlhutlhlaHbe'chugh, "Sandbox" vaj 'ej 'oH vItlhutlhlaHbe'chugh, 'ach 'oH vItlhutlhlaHbe'chugh, **'ej permissions** vItlhutlhlaHbe'chugh. vItlhutlhlaHbe'chugh 'oH **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
ghItlhutlh! **Sandbox** qorwaghmeyDaq **yIqaw** **quarantine attribut**e. **Sandbox** app **`open`** **qarDaq** **yIqaw** **quarantine attribut**e **ghItlhutlh** **Gatekeeper** **trigger** **yIqaw**.
{% endhint %}

### **Sandbox Profiles**

**Sandbox Profiles** **Sandbox** **allowed/forbidden** **yIqaw** **configuration files** **ghItlhutlh**. **Sandbox Profile Language (SBPL)** **yIqaw** **Sandbox Profile Language (SBPL)** **Scheme** **programming language** **yIqaw**.

**Example** **yIqaw** **tlhIngan Hol**:

```markdown
```
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Qa'pla' [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **to check more actions that could be allowed or denied.**
{% endhint %}

Important **system services** also run inside their own custom **sandbox** such as the `mdnsresponder` service. You can view these custom **sandbox profiles** inside:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Other sandbox profiles can be checked in [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store** apps use the **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. You can check in this profile how entitlements such as **`com.apple.security.network.server`** allows a process to use the network.

SIP is a Sandbox profile called platform\_profile in /System/Library/Sandbox/rootless.conf

### Sandbox Profile Examples

To start an application with an **specific sandbox profile** you can use:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```klingon
touch.sb
```

{% endcode %}
{% endtab %}

{% tab title="sandbox-exec" %}
{% code title="sandbox-exec" %}

```klingon
sandbox-exec
```

{% endcode %}
{% endtab %}

{% tab title="sandbox-simplify" %}
{% code title="sandbox-simplify" %}

```klingon
sandbox-simplify
```

{% endcode %}
{% endtab %}
{% endtabs %}

The `touch.sb` file is a sample sandbox profile for the `touch` command. It restricts the command's access to specific resources and operations.

To use the sandbox profile, you can execute the `touch` command with the `sandbox-exec` utility, specifying the `touch.sb` profile as an argument:

```bash
sandbox-exec -f touch.sb touch <filename>
```

The `sandbox-simplify` utility can be used to simplify an existing sandbox profile. It removes unnecessary rules and consolidates redundant ones, making the profile more concise and easier to understand.

To simplify the `touch.sb` profile, you can run the following command:

```bash
sandbox-simplify -f touch.sb > simplified.sb
```

The simplified profile will be saved in the `simplified.sb` file.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}

```
(version 1)
(deny default)

(import "sandbox.sb")

;; Allow reading and writing to the user's home directory
(allow file-read* file-write* (subpath "/Users/<username>"))

;; Allow reading and writing to specific files
(allow file-read* file-write* (regex #"^/private/var/folders/"))

;; Allow executing the touch command
(allow file-executable* (regex #"^/usr/bin/touch$"))

;; Allow executing the ls command
(allow file-executable* (regex #"^/bin/ls$"))

;; Allow executing the echo command
(allow file-executable* (regex #"^/bin/echo$"))

;; Allow executing the cat command
(allow file-executable* (regex #"^/bin/cat$"))

;; Allow executing the rm command
(allow file-executable* (regex #"^/bin/rm$"))

;; Allow executing the mv command
(allow file-executable* (regex #"^/bin/mv$"))

;; Allow executing the cp command
(allow file-executable* (regex #"^/bin/cp$"))

;; Allow executing the chmod command
(allow file-executable* (regex #"^/bin/chmod$"))

;; Allow executing the chown command
(allow file-executable* (regex #"^/usr/sbin/chown$"))

;; Allow executing the chflags command
(allow file-executable* (regex #"^/usr/sbin/chflags$"))

;; Allow executing the sudo command
(allow file-executable* (regex #"^/usr/bin/sudo$"))

;; Allow executing the su command
(allow file-executable* (regex #"^/usr/bin/su$"))

;; Allow executing the open command
(allow file-executable* (regex #"^/usr/bin/open$"))

;; Allow executing the kill command
(allow file-executable* (regex #"^/bin/kill$"))

;; Allow executing the ps command
(allow file-executable* (regex #"^/bin/ps$"))

;; Allow executing the top command
(allow file-executable* (regex #"^/usr/bin/top$"))

;; Allow executing the pkill command
(allow file-executable* (regex #"^/usr/bin/pkill$"))

;; Allow executing the killall command
(allow file-executable* (regex #"^/usr/bin/killall$"))

;; Allow executing the launchctl command
(allow file-executable* (regex #"^/bin/launchctl$"))

;; Allow executing the defaults command
(allow file-executable* (regex #"^/usr/bin/defaults$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;; Allow executing the scutil command
(allow file-executable* (regex #"^/usr/sbin/scutil$"))

;; Allow executing the dscl command
(allow file-executable* (regex #"^/usr/bin/dscl$"))

;; Allow executing the security command
(allow file-executable* (regex #"^/usr/bin/security$"))

;; Allow executing the codesign command
(allow file-executable* (regex #"^/usr/bin/codesign$"))

;; Allow executing the spctl command
(allow file-executable* (regex #"^/usr/sbin/spctl$"))

;; Allow executing the pkgutil command
(allow file-executable* (regex #"^/usr/sbin/pkgutil$"))

;; Allow executing the installer command
(allow file-executable* (regex #"^/usr/sbin/installer$"))

;; Allow executing the diskutil command
(allow file-executable* (regex #"^/usr/sbin/diskutil$"))

;; Allow executing the systemsetup command
(allow file-executable* (regex #"^/usr/sbin/systemsetup$"))

;; Allow executing the nvram command
(allow file-executable* (regex #"^/usr/sbin/nvram$"))

;; Allow executing the networksetup command
(allow file-executable* (regex #"^/usr/sbin/networksetup$"))

;; Allow executing the system_profiler command
(allow file-executable* (regex #"^/usr/sbin/system_profiler$"))

;; Allow executing the softwareupdate command
(allow file-executable* (regex #"^/usr/sbin/softwareupdate$"))

;;
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Qapla'! **Apple-authored** **software** that runs on **Windows** **doesn’t have additional security precautions**, such as application sandboxing.
{% endhint %}

Bypasses examples:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (they are able to write files outside the sandbox whose name starts with `~$`).

### MacOS Sandbox Profiles

macOS stores system sandbox profiles in two locations: **/usr/share/sandbox/** and **/System/Library/Sandbox/Profiles**.

And if a third-party application carry the _**com.apple.security.app-sandbox**_ entitlement, the system applies the **/System/Library/Sandbox/Profiles/application.sb** profile to that process.

### **iOS Sandbox Profile**

The default profile is called **container** and we don't have the SBPL text representation. In memory, this sandbox is represented as Allow/Deny binary tree for each permissions from the sandbox.

### Debug & Bypass Sandbox

On macOS, unlike iOS where processes are sandboxed from the start by the kernel, **processes must opt-in to the sandbox themselves**. This means on macOS, a process is not restricted by the sandbox until it actively decides to enter it.

Processes are automatically Sandboxed from userland when they start if they have the entitlement: `com.apple.security.app-sandbox`. For a detailed explanation of this process check:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Check PID Privileges**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), the **`sandbox_check`** (it's a `__mac_syscall`), can check **if an operation is allowed or not** by the sandbox in a certain PID.

The [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) can check if a PID can perform a certain action:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

**Qapla'!** Qa'vam jatlhpu' vItlhutlh **custom Sandbox profiles** (ghorgh vItlhutlh) **'ej** (default) **vay'** **run apps** **companies** **'e'** **possible**. **'ej** **entitlement** **`com.apple.security.temporary-exception.sbpl`** **use** **need** **Apple** **authorized** **be**.

**'ej** **definition** **entitlement** **check** **possible** **'e'** **/System/Library/Sandbox/Profiles/application.sb:**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
**eval** **tlhIngan Hol** **Sandbox profile** **eval** **tlhIngan Hol** **Sandbox profile**.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
