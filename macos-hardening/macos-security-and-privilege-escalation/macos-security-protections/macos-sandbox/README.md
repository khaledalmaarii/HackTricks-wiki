# Sanduku la macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Sanduku la MacOS (awali lililoitwa Seatbelt) **linapunguza matumizi** yanayoendesha ndani ya sanduku kwa **vitendo vilivyoidhinishwa vilivyoelezwa katika wasifu wa Sanduku** ambao programu inaendeshwa nao. Hii husaidia kuhakikisha kwamba **programu itakuwa ikifikia rasilimali zinazotarajiwa tu**.

Programu yoyote yenye **haki** ya **`com.apple.security.app-sandbox`** itatekelezwa ndani ya sanduku. **Faili za Apple** kawaida hutekelezwa ndani ya Sanduku na ili kuchapisha kwenye **Duka la App**, **haki hii ni lazima**. Kwa hivyo, programu nyingi zitatekelezwa ndani ya sanduku.

Ili kudhibiti kile mchakato unaweza au hauwezi kufanya, **Sanduku lina kitanzi** katika **syscalls** zote kwenye kernel. **Kulingana** na **haki** za programu, Sanduku itaruhusu vitendo fulani.

Baadhi ya sehemu muhimu za Sanduku ni:

* **Kernel extension** `/System/Library/Extensions/Sandbox.kext`
* **Framework binafsi** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* **Daemon** inayotumia userland `/usr/libexec/sandboxd`
* **Makontena** `~/Library/Containers`

Ndani ya folda za makontena unaweza kupata **folda kwa kila programu inayotekelezwa kwenye sanduku** na jina la kitambulisho cha mfuko:
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
Ndani ya kila folda ya kitambulisho cha mfuko unaweza kupata **plist** na **Data directory** ya App:
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
Tafadhali kumbuka kwamba hata kama viungo vya ishara vipo hapo ili "kutoroka" kutoka kwenye Sanduku la Mchanga na kupata ufikiaji wa folda zingine, Programu bado inahitaji **kuwa na ruhusa** ya kuzifikia. Ruhusa hizi zipo ndani ya **`.plist`**.
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
Kila kitu kilichoundwa/kibadilishwa na programu iliyowekwa kwenye Sandboksi kitapata sifa ya **karantini**. Hii itazuia nafasi ya sandboksi kwa kuzindua Gatekeeper ikiwa programu ya sandboksi inajaribu kutekeleza kitu na **`open`**.
{% endhint %}

### Profaili za Sandboksi

Profaili za Sandboksi ni faili za usanidi ambazo zinaonyesha ni nini kitakachoruhusiwa/kukatazwa katika **Sandboksi** hiyo. Inatumia Lugha ya Profaili ya Sandboksi (SBPL), ambayo hutumia lugha ya programu ya [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

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
Angalia [**utafiti**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **ili kuangalia hatua zaidi ambazo zinaweza kuruhusiwa au kukataliwa.**
{% endhint %}

**Huduma muhimu za mfumo** pia zinaendeshwa ndani ya **sandbox yao ya kawaida** kama huduma ya `mdnsresponder`. Unaweza kuona maelezo ya **sandbox maalum** haya ndani ya:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Maelezo mengine ya sandbox yanaweza kuangaliwa katika [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Programu za **Duka la App** hutumia **maelezo ya sandbox** **`/System/Library/Sandbox/Profiles/application.sb`**. Unaweza kuangalia katika maelezo haya jinsi idhini kama vile **`com.apple.security.network.server`** inavyoruhusu mchakato kutumia mtandao.

SIP ni maelezo ya sandbox yanayoitwa platform\_profile katika /System/Library/Sandbox/rootless.conf

### Mifano ya Maelezo ya Sandbox

Ili kuanza programu na **maelezo ya sandbox maalum**, unaweza kutumia:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```plaintext
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))
```

This is a simple example of a sandbox profile for the `touch` command. It allows the command to read and write metadata and data for a specific file located at `/path/to/file`. All other operations are denied by default.
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
Tafadhali kumbuka kuwa **programu** iliyoundwa na **Apple** inayofanya kazi kwenye **Windows** **haina tahadhari za ziada za usalama**, kama vile sandboxing ya programu.
{% endhint %}

Mifano ya kuvuka:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (wanaweza kuandika faili nje ya sandbox ambayo jina lake linaanza na `~$`).

### Profaili za Sandbox za MacOS

macOS inahifadhi profaili za sandbox za mfumo katika maeneo mawili: **/usr/share/sandbox/** na **/System/Library/Sandbox/Profiles**.

Na ikiwa programu ya mtu wa tatu ina kibali cha _**com.apple.security.app-sandbox**_, mfumo unatumia profaili ya **/System/Library/Sandbox/Profiles/application.sb** kwa mchakato huo.

### **Profaili ya Sandbox ya iOS**

Profaili ya chaguo-msingi inaitwa **container** na hatuna uwakilishi wa maandishi wa SBPL. Kumbukumbu, sandbox hii inawakilishwa kama mti wa kibinari wa Ruhusu/Kataa kwa kila idhini kutoka kwenye sandbox.

### Kuchunguza na Kuvuka Sandbox

Kwenye macOS, tofauti na iOS ambapo michakato inawekwa kwenye sandbox tangu mwanzo na kernel, **michakato lazima ijiunge na sandbox yenyewe**. Hii inamaanisha kuwa kwenye macOS, mchakato hauna kizuizi cha sandbox mpaka uamue kuingia ndani yake.

Michakato inawekwa kwenye Sandbox kiotomatiki kutoka kwa userland wanapoanza ikiwa wana kibali: `com.apple.security.app-sandbox`. Kwa maelezo zaidi juu ya mchakato huu angalia:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Angalia Uwezo wa PID**

[**Kulingana na hii**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (ni `__mac_syscall`), inaweza kuangalia **kama operesheni inaruhusiwa au la** na sandbox katika PID fulani.

[**Zana ya sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) inaweza kuangalia ikiwa PID inaweza kutekeleza hatua fulani:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### SBPL ya kawaida katika programu za Duka la App

Inawezekana kwa makampuni kuunda programu zao zifanye kazi **na maelezo ya SBPL ya kawaida** (badala ya ile ya msingi). Wanahitaji kutumia ruhusa ya **`com.apple.security.temporary-exception.sbpl`** ambayo inahitaji idhini kutoka kwa Apple.

Inawezekana kuangalia ufafanuzi wa ruhusa hii katika **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Hii ita **eval string baada ya haki ya kumiliki** kama profile ya Sandbox.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
