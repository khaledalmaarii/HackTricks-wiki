# macOS Sandbox

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

## Basic Information

MacOS Sandbox (awali ilijulikana kama Seatbelt) **inaweka mipaka kwa programu** zinazotembea ndani ya sandbox kwa **vitendo vilivyokubaliwa vilivyobainishwa katika profaili ya Sandbox** ambayo programu inatumia. Hii husaidia kuhakikisha kwamba **programu itakuwa ikipata rasilimali zinazotarajiwa tu**.

Programu yoyote yenye **entitlement** **`com.apple.security.app-sandbox`** itatekelezwa ndani ya sandbox. **Mifumo ya Apple** kwa kawaida hutekelezwa ndani ya Sandbox na ili kuchapishwa ndani ya **App Store**, **entitlement hii ni ya lazima**. Hivyo, programu nyingi zitatekelezwa ndani ya sandbox.

Ili kudhibiti kile mchakato unaweza au hawezi kufanya, **Sandbox ina vidokezo** katika **syscalls** zote kupitia kernel. **Kulingana** na **entitlements** za programu, Sandbox it **aruhusu** vitendo fulani.

Baadhi ya vipengele muhimu vya Sandbox ni:

* **kiongezeo cha kernel** `/System/Library/Extensions/Sandbox.kext`
* **mfumo wa faragha** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* **daemon** inayotembea katika userland `/usr/libexec/sandboxd`
* **mifuko** `~/Library/Containers`

Ndani ya folda ya mifuko unaweza kupata **folda kwa kila programu inayotekelezwa sandboxed** yenye jina la bundle id:
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
Ndani ya kila folda ya bundle id unaweza kupata **plist** na **Data directory** ya App:
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
Kumbuka kwamba hata kama symlinks zipo ili "kutoroka" kutoka Sandbox na kufikia folda nyingine, App bado inahitaji **kuwa na ruhusa** za kuzifikia. Ruhusa hizi ziko ndani ya **`.plist`**.
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
Kila kitu kilichoundwa/kilibadilishwa na programu ya Sandboxed kitapata **sifa ya karantini**. Hii itazuia nafasi ya sandbox kwa kuanzisha Gatekeeper ikiwa programu ya sandbox inajaribu kutekeleza kitu kwa **`open`**.
{% endhint %}

### Profaili za Sandbox

Profaili za Sandbox ni faili za usanidi zinazoonyesha kile kitakachokuwa **kuruhusiwa/kukatazwa** katika hiyo **Sandbox**. Inatumia **Sandbox Profile Language (SBPL)**, ambayo inatumia lugha ya programu ya [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Hapa unaweza kupata mfano:
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
Check this [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **ili kuangalia vitendo zaidi ambavyo vinaweza kuruhusiwa au kukataliwa.**
{% endhint %}

Mifumo muhimu ya **huduma** pia inafanya kazi ndani ya **sandbox** yake maalum kama huduma ya `mdnsresponder`. Unaweza kuona hizi **profiles za sandbox** maalum ndani ya:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Profiles nyingine za sandbox zinaweza kuangaliwa katika [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Programu za **App Store** zinatumia **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Unaweza kuangalia katika profile hii jinsi haki kama **`com.apple.security.network.server`** inavyoruhusu mchakato kutumia mtandao.

SIP ni profile ya Sandbox inayoitwa platform\_profile katika /System/Library/Sandbox/rootless.conf

### Mifano ya Profile ya Sandbox

Ili kuanzisha programu na **profile maalum ya sandbox** unaweza kutumia:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
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
{% endcode %}

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
Kumbuka kwamba **programu** **iliyoundwa na Apple** inayofanya kazi kwenye **Windows** **haina tahadhari za ziada za usalama**, kama vile sandboxing ya programu.
{% endhint %}

Mifano ya kupita:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (wanaweza kuandika faili nje ya sandbox ambayo jina lake linaanza na `~$`).

### Profaili za Sandbox za MacOS

macOS inahifadhi profaili za sandbox za mfumo katika maeneo mawili: **/usr/share/sandbox/** na **/System/Library/Sandbox/Profiles**.

Na ikiwa programu ya upande wa tatu ina _**com.apple.security.app-sandbox**_ haki, mfumo unatumia profaili ya **/System/Library/Sandbox/Profiles/application.sb** kwa mchakato huo.

### **Profaili ya Sandbox ya iOS**

Profaili ya chaguo-msingi inaitwa **container** na hatuna uwakilishi wa maandiko ya SBPL. Katika kumbukumbu, sandbox hii inawakilishwa kama mti wa binary wa Ruhusu/Kataa kwa kila ruhusa kutoka kwenye sandbox.

### Debug & Bypass Sandbox

Katika macOS, tofauti na iOS ambapo michakato inasandboxed tangu mwanzo na kernel, **michakato lazima ijitolee kwenye sandbox yenyewe**. Hii inamaanisha katika macOS, mchakato haujawekewa vizuizi na sandbox hadi uamuzi wa kuingia ndani yake ufanyike.

Michakato inasandboxed kiotomatiki kutoka kwa userland wanapoanza ikiwa wana haki: `com.apple.security.app-sandbox`. Kwa maelezo ya kina kuhusu mchakato huu angalia:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Angalia Haki za PID**

[**Kulingana na hii**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (ni `__mac_syscall`), inaweza kuangalia **kama operesheni inaruhusiwa au la** na sandbox katika PID fulani.

[**chombo sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) kinaweza kuangalia ikiwa PID inaweza kufanya kitendo fulani:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

Inawezekana kwa kampuni kufanya programu zao zifanye kazi **na wasifu wa Sandbox wa kawaida** (badala ya ule wa kawaida). Wanahitaji kutumia haki **`com.apple.security.temporary-exception.sbpl`** ambayo inahitaji kuidhinishwa na Apple.

Inawezekana kuangalia ufafanuzi wa haki hii katika **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Hii itafanya **eval string baada ya haki hii** kama profaili ya Sandbox.

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
