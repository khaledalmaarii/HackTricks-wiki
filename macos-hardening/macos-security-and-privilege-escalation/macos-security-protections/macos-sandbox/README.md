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

MacOS Sandbox (początkowo nazywany Seatbelt) **ogranicza aplikacje** działające w piaskownicy do **dozwolonych działań określonych w profilu Sandbox**, z którym działa aplikacja. Pomaga to zapewnić, że **aplikacja będzie miała dostęp tylko do oczekiwanych zasobów**.

Każda aplikacja z **uprawnieniem** **`com.apple.security.app-sandbox`** będzie uruchamiana w piaskownicy. **Binarne pliki Apple** są zazwyczaj uruchamiane w piaskownicy, a aby opublikować w **App Store**, **to uprawnienie jest obowiązkowe**. Dlatego większość aplikacji będzie uruchamiana w piaskownicy.

Aby kontrolować, co proces może lub nie może robić, **Sandbox ma haki** we wszystkich **wywołaniach systemowych** w jądrze. **W zależności** od **uprawnień** aplikacji, Sandbox **zezwoli** na określone działania.

Niektóre ważne komponenty Sandbox to:

* **rozszerzenie jądra** `/System/Library/Extensions/Sandbox.kext`
* **prywatny framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* **demon** działający w przestrzeni użytkownika `/usr/libexec/sandboxd`
* **kontenery** `~/Library/Containers`

W folderze kontenerów można znaleźć **folder dla każdej aplikacji uruchamianej w piaskownicy** o nazwie identyfikatora pakietu:
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
Wewnątrz każdego folderu identyfikatora pakietu możesz znaleźć **plist** i **katalog danych** aplikacji:
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
Zauważ, że nawet jeśli symlinki są tam, aby "uciec" z Sandbox i uzyskać dostęp do innych folderów, aplikacja nadal musi **mieć uprawnienia** do ich dostępu. Te uprawnienia znajdują się w **`.plist`**.
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
Wszystko stworzone/zmodyfikowane przez aplikację w piaskownicy otrzyma **atrybut kwarantanny**. To zapobiegnie przestrzeni piaskownicy, uruchamiając Gatekeeper, jeśli aplikacja w piaskownicy spróbuje wykonać coś za pomocą **`open`**.
{% endhint %}

### Profile Piaskownicy

Profile piaskownicy to pliki konfiguracyjne, które wskazują, co będzie **dozwolone/zabronione** w tej **piaskownicy**. Używa **Języka Profilu Piaskownicy (SBPL)**, który wykorzystuje język programowania [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Tutaj możesz znaleźć przykład:
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
Sprawdź to [**badanie**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **aby sprawdzić więcej działań, które mogą być dozwolone lub zabronione.**
{% endhint %}

Ważne **usługi systemowe** również działają w swoim własnym niestandardowym **sandboxie**, takim jak usługa `mdnsresponder`. Możesz zobaczyć te niestandardowe **profile sandbox** w:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Inne profile sandbox można sprawdzić w [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Aplikacje z **App Store** używają **profilu** **`/System/Library/Sandbox/Profiles/application.sb`**. Możesz sprawdzić w tym profilu, jak uprawnienia takie jak **`com.apple.security.network.server`** pozwalają procesowi na korzystanie z sieci.

SIP to profil Sandbox o nazwie platform\_profile w /System/Library/Sandbox/rootless.conf

### Przykłady profili Sandbox

Aby uruchomić aplikację z **konkretnym profilem sandbox**, możesz użyć:
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
Zauważ, że **oprogramowanie** **napisane przez Apple**, które działa na **Windows**, **nie ma dodatkowych środków bezpieczeństwa**, takich jak piaskownica aplikacji.
{% endhint %}

Przykłady obejścia:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (są w stanie zapisywać pliki poza piaskownicą, których nazwa zaczyna się od `~$`).

### Profile piaskownicy MacOS

macOS przechowuje profile piaskownicy systemu w dwóch lokalizacjach: **/usr/share/sandbox/** i **/System/Library/Sandbox/Profiles**.

A jeśli aplikacja firm trzecich posiada uprawnienie _**com.apple.security.app-sandbox**_, system stosuje profil **/System/Library/Sandbox/Profiles/application.sb** do tego procesu.

### **Profil piaskownicy iOS**

Domyślny profil nazywa się **container** i nie mamy tekstowej reprezentacji SBPL. W pamięci ta piaskownica jest reprezentowana jako drzewo binarne Allow/Deny dla każdego uprawnienia z piaskownicy.

### Debugowanie i obejście piaskownicy

Na macOS, w przeciwieństwie do iOS, gdzie procesy są od początku piaskowane przez jądro, **procesy muszą same zdecydować o wejściu do piaskownicy**. Oznacza to, że na macOS proces nie jest ograniczany przez piaskownicę, dopóki aktywnie nie zdecyduje się do niej wejść.

Procesy są automatycznie piaskowane z przestrzeni użytkownika, gdy się uruchamiają, jeśli mają uprawnienie: `com.apple.security.app-sandbox`. Aby uzyskać szczegółowe wyjaśnienie tego procesu, sprawdź:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Sprawdź uprawnienia PID**

[**Zgodnie z tym**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (to jest `__mac_syscall`), może sprawdzić **czy operacja jest dozwolona, czy nie** przez piaskownicę w danym PID.

[**Narzędzie sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) może sprawdzić, czy PID może wykonać określoną akcję:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL w aplikacjach App Store

Możliwe jest, aby firmy uruchamiały swoje aplikacje **z niestandardowymi profilami Sandbox** (zamiast z domyślnym). Muszą użyć uprawnienia **`com.apple.security.temporary-exception.sbpl`**, które musi być autoryzowane przez Apple.

Można sprawdzić definicję tego uprawnienia w **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
To będzie **eval string po tym uprawnieniu** jako profil Sandbox.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
