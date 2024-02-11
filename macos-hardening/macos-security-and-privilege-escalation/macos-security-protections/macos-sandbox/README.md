# Piaskownica macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

Piaskownica macOS (początkowo nazywana Seatbelt) **ogranicza działanie aplikacji** uruchomionych wewnątrz piaskownicy do **dozwolonych działań określonych w profilu piaskownicy**, z którym aplikacja jest uruchamiana. Pomaga to zapewnić, że **aplikacja będzie miała dostęp tylko do oczekiwanych zasobów**.

Każda aplikacja z **uprawnieniem** **`com.apple.security.app-sandbox`** będzie uruchamiana wewnątrz piaskownicy. **Binaria Apple** zazwyczaj są uruchamiane wewnątrz piaskownicy i w celu publikacji w **App Store**, **to uprawnienie jest obowiązkowe**. Większość aplikacji będzie uruchamiana wewnątrz piaskownicy.

Aby kontrolować, co proces może lub nie może robić, **Piaskownica ma hooki** we wszystkich **wywołaniach systemowych** w jądrze. **W zależności** od **uprawnień** aplikacji, Piaskownica **pozwoli** na określone działania.

Niektóre ważne komponenty Piaskownicy to:

* Rozszerzenie jądra `/System/Library/Extensions/Sandbox.kext`
* Prywatny framework `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Demon działający w przestrzeni użytkownika `/usr/libexec/sandboxd`
* Kontenery `~/Library/Containers`

Wewnątrz folderu kontenerów można znaleźć **folder dla każdej aplikacji uruchomionej w piaskownicy** o nazwie identyfikatora pakietu:
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
Wewnątrz każdego folderu identyfikatora pakietu można znaleźć plik **plist** oraz katalog **Data** aplikacji:
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
Należy pamiętać, że nawet jeśli są dostępne symlinki, które pozwalają "uciec" z piaskownicy i uzyskać dostęp do innych folderów, aplikacja nadal musi **mieć uprawnienia** do ich odczytu. Te uprawnienia znajdują się w pliku **`.plist`**.
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
Wszystko, co zostało utworzone/zmodyfikowane przez aplikację w piaskownicy, otrzyma atrybut **kwarantanny**. Spowoduje to zapobieżenie uruchomieniu przestrzeni piaskownicy przez Gatekeeper, jeśli aplikacja w piaskownicy spróbuje wykonać coś za pomocą **`open`**.
{% endhint %}

### Profile piaskownicy

Profile piaskownicy to pliki konfiguracyjne, które wskazują, co jest **dozwolone/zabronione** w tej **piaskownicy**. Wykorzystuje on język profilu piaskownicy (SBPL), który używa języka programowania [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

Tutaj znajdziesz przykład:
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
Sprawdź tę [**badanie**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **aby sprawdzić więcej akcji, które mogą być dozwolone lub zabronione.**
{% endhint %}

Ważne **usługi systemowe** również działają w swoim własnym niestandardowym **sandboxie**, takim jak usługa `mdnsresponder`. Możesz zobaczyć te niestandardowe **profile sandboxa** w:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Inne profile sandboxa można sprawdzić na stronie [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Aplikacje z **App Store** używają profilu **`/System/Library/Sandbox/Profiles/application.sb`**. Możesz sprawdzić w tym profilu, jak uprawnienia takie jak **`com.apple.security.network.server`** pozwalają procesowi korzystać z sieci.

SIP to profil sandboxa o nazwie platform\_profile w /System/Library/Sandbox/rootless.conf

### Przykłady profilu sandboxa

Aby uruchomić aplikację z **konkretnym profilem sandboxa**, możesz użyć:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))
```

{% endcode %}
{% endtab %}

{% tab title="chmod" %}
{% code title="chmod.sb" %}
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

Ten plik to przykład pliku konfiguracyjnego dla mechanizmu piaskownicy w systemie macOS. Piaskownica to mechanizm bezpieczeństwa, który izoluje aplikacje od reszty systemu, ograniczając ich dostęp do zasobów i funkcji systemowych. Plik konfiguracyjny definiuje zasady, które określają, jakie uprawnienia ma dana aplikacja w piaskownicy.

W tym konkretnym przykładzie, plik touch2.sb definiuje zasady dla aplikacji touch2. Aplikacja ta ma dostęp tylko do swojego własnego katalogu domowego i nie może korzystać z żadnych innych zasobów systemowych.
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
Należy zauważyć, że **oprogramowanie** **autorstwa Apple**, które działa na **systemie Windows**, nie posiada dodatkowych środków bezpieczeństwa, takich jak izolacja aplikacji.
{% endhint %}

Przykłady bypassowania:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (są w stanie zapisywać pliki poza piaskownicą, których nazwa zaczyna się od `~$`).

### Profile piaskownicy MacOS

macOS przechowuje profile piaskownicy systemowej w dwóch lokalizacjach: **/usr/share/sandbox/** i **/System/Library/Sandbox/Profiles**.

Jeśli aplikacja innej firmy posiada uprawnienie _**com.apple.security.app-sandbox**_, system stosuje profil **/System/Library/Sandbox/Profiles/application.sb** do tego procesu.

### **Profil piaskownicy iOS**

Domyślny profil nosi nazwę **container** i nie posiadamy reprezentacji tekstowej SBPL. W pamięci ta piaskownica jest reprezentowana jako drzewo binarne Zezwalaj/Odmawiaj dla każdego uprawnienia z piaskownicy.

### Debugowanie i bypassowanie piaskownicy

Na macOS, w przeciwieństwie do iOS, gdzie procesy są od początku izolowane przez jądro, **procesy muszą samodzielnie zdecydować o dołączeniu do piaskownicy**. Oznacza to, że na macOS proces nie jest ograniczony przez piaskownicę, dopóki sam nie zdecyduje się do niej dołączyć.

Procesy są automatycznie izolowane w piaskownicy z przestrzeni użytkownika podczas uruchamiania, jeśli posiadają uprawnienie: `com.apple.security.app-sandbox`. Szczegółowe wyjaśnienie tego procesu można znaleźć pod adresem:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Sprawdzanie uprawnień PID**

[Zgodnie z tym](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (jest to `__mac_syscall`) może sprawdzić, **czy operacja jest dozwolona czy nie** przez piaskownicę w określonym PID.

[Narzędzie sbtool](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) może sprawdzić, czy PID może wykonać określoną czynność:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Niestandardowe profile SBPL w aplikacjach App Store

Firmy mają możliwość uruchamiania swoich aplikacji z **niestandardowymi profilami Sandbox** (zamiast domyślnego). Muszą użyć uprawnienia **`com.apple.security.temporary-exception.sbpl`**, które musi zostać autoryzowane przez Apple.

Można sprawdzić definicję tego uprawnienia w pliku **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
To **ocenić ciąg znaków po tym uprawnieniu**, jako profil Sandbox, wykonaj następujące czynności.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
