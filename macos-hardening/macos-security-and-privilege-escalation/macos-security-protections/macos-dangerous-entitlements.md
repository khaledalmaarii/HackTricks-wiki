# macOS Niebezpieczne Uprawnienia i Uprawnienia TCC

<details>

<summary><strong>Nauka hakerska AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

{% hint style="warning" %}
Zauważ, że uprawnienia zaczynające się od **`com.apple`** nie są dostępne dla stron trzecich, tylko Apple może je przyznać.
{% endhint %}

## Wysokie

### `com.apple.rootless.install.heritable`

Uprawnienie **`com.apple.rootless.install.heritable`** pozwala na **ominięcie SIP**. Sprawdź [to dla więcej informacji](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Uprawnienie **`com.apple.rootless.install`** pozwala na **ominięcie SIP**. Sprawdź [to dla więcej informacji](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (wcześniej nazywane `task_for_pid-allow`)**

To uprawnienie pozwala uzyskać **port zadania dla dowolnego** procesu, z wyjątkiem jądra. Sprawdź [**to dla więcej informacji**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

To uprawnienie pozwala innym procesom z uprawnieniem **`com.apple.security.cs.debugger`** uzyskać port zadania procesu uruchamianego przez binarny plik z tym uprawnieniem i **wstrzykiwać w niego kod**. Sprawdź [**to dla więcej informacji**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplikacje z Uprawnieniem Narzędzia Debugowania mogą wywołać `task_for_pid()` w celu pobrania ważnego portu zadania dla aplikacji niepodpisanych i stron trzecich z uprawnieniem `Get Task Allow` ustawionym na `true`. Jednak nawet z uprawnieniem narzędzia debugowania, debugger **nie może uzyskać portów zadań** procesów, które **nie mają uprawnienia `Get Task Allow`**, a więc są chronione przez System Integrity Protection. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

To uprawnienie pozwala na **ładowanie frameworków, wtyczek lub bibliotek bez podpisywania przez Apple lub podpisywania tym samym identyfikatorem zespołu** co główny plik wykonywalny, więc atakujący mógłby wykorzystać niektóre arbitralne ładowanie bibliotek do wstrzykiwania kodu. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

To uprawnienie jest bardzo podobne do **`com.apple.security.cs.disable-library-validation`** ale **zamiast** bezpośrednio wyłączać walidację bibliotek, pozwala procesowi **wywołać wywołanie systemowe `csops` w celu jej wyłączenia**.\
Sprawdź [**to dla więcej informacji**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

To uprawnienie pozwala na **użycie zmiennych środowiskowych DYLD**, które mogą być używane do wstrzykiwania bibliotek i kodu. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` lub `com.apple.rootless.storage`.`TCC`

[Zgodnie z tym blogiem](https://objective-see.org/blog/blog\_0x4C.html) **i** [**tym blogiem**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), te uprawnienia pozwalają na **modyfikację** bazy danych **TCC**.

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Te uprawnienia pozwalają na **instalowanie oprogramowania bez pytania o zgodę** użytkownika, co może być pomocne dla **eskalacji uprawnień**.

### `com.apple.private.security.kext-management`

Uprawnienie potrzebne do poproszenia **jądra o załadowanie rozszerzenia jądra**.

### **`com.apple.private.icloud-account-access`**

Uprawnienie **`com.apple.private.icloud-account-access`** umożliwia komunikację z usługą XPC **`com.apple.iCloudHelper`**, która **dostarczy tokeny iCloud**.

**iMovie** i **Garageband** miały to uprawnienie.

Aby uzyskać więcej **informacji** na temat wykorzystania do **uzyskania tokenów iCloud** z tego uprawnienia, sprawdź prezentację: [**#OBTS v5.0: "Co się dzieje na twoim Macu, zostaje w iCloudzie Apple'a?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Nie wiem, co to pozwala zrobić

### `com.apple.private.apfs.revert-to-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że może to być używane do** aktualizacji chronionych zawartości SSV po ponownym uruchomieniu. Jeśli wiesz, jak to zrobić, prześlij PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że może to być używane do** aktualizacji chronionych zawartości SSV po ponownym uruchomieniu. Jeśli wiesz, jak to zrobić, prześlij PR!

### `keychain-access-groups`

To uprawnienie wyświetla grupy **kluczy** do których aplikacja ma dostęp:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Nadaje uprawnienia **Pełnego dostępu do dysku**, jedno z najwyższych uprawnień TCC, jakie można uzyskać.

### **`kTCCServiceAppleEvents`**

Pozwala aplikacji wysyłać zdarzenia do innych aplikacji, które są często używane do **automatyzacji zadań**. Kontrolując inne aplikacje, może nadużyć udzielonych uprawnień tym innym aplikacjom.

Na przykład zmuszając je do poproszenia użytkownika o hasło:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Lub sprawić, że wykonują **dowolne czynności**.

### **`kTCCServiceEndpointSecurityClient`**

Pozwala między innymi na **zapis do bazy danych TCC użytkowników**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Pozwala **zmienić** atrybut **`NFSHomeDirectory`** użytkownika, co zmienia ścieżkę folderu domowego i tym samym pozwala na **obejście TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Pozwala modyfikować pliki wewnątrz pakietów aplikacji (wewnątrz app.app), co jest **domyślnie zabronione**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Można sprawdzić, kto ma ten dostęp w _Ustawienia systemowe_ > _Prywatność i bezpieczeństwo_ > _Zarządzanie aplikacjami_.

### `kTCCServiceAccessibility`

Proces będzie mógł **nadużywać funkcje dostępności macOS**, co oznacza, że na przykład będzie mógł naciskać klawisze. Może poprosić o dostęp do kontrolowania aplikacji, takiej jak Finder, i zatwierdzić okno dialogowe z tym uprawnieniem.

## Średni

### `com.apple.security.cs.allow-jit`

To uprawnienie pozwala **tworzyć pamięć, która jest zapisywalna i wykonywalna**, przekazując flagę `MAP_JIT` do funkcji systemowej `mmap()`. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

To uprawnienie pozwala na **nadpisanie lub łatanie kodu C**, używanie długo przestarzałej funkcji **`NSCreateObjectFileImageFromMemory`** (która jest fundamentalnie niebezpieczna) lub korzystanie z frameworku **DVDPlayback**. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Uwzględnienie tego uprawnienia narazia Twoją aplikację na powszechne podatności w językach kodu nieszczepnego w pamięci. Rozważ dokładnie, czy Twoja aplikacja potrzebuje tej wyjątkowej zgody.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

To uprawnienie pozwala na **modyfikowanie sekcji własnych plików wykonywalnych** na dysku w celu wymuszenia wyjścia. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Uprawnienie Wyłącz Ochronę Strony Wykonywalnej to skrajne uprawnienie, które usuwa podstawową ochronę bezpieczeństwa z Twojej aplikacji, umożliwiając atakującemu przepisanie kodu wykonywalnego Twojej aplikacji bez wykrycia. Jeśli to możliwe, preferuj węższe uprawnienia.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

To uprawnienie pozwala na zamontowanie systemu plików nullfs (domyślnie zabronione). Narzędzie: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Zgodnie z tym wpisem na blogu, to uprawnienie TCC zazwyczaj znajduje się w formie:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Zezwól procesowi na **poproszenie o wszystkie uprawnienia TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
