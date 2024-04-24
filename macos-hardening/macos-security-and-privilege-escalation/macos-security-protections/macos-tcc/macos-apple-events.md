# macOS Apple Events

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

**Zdarzenia Apple** to funkcja w systemie macOS firmy Apple, która umożliwia aplikacjom komunikację między sobą. Są one częścią **Menedżera Zdarzeń Apple**, który jest komponentem systemu operacyjnego macOS odpowiedzialnym za obsługę komunikacji międzyprocesowej. Ten system umożliwia jednej aplikacji wysłanie wiadomości do innej aplikacji w celu wykonania określonej operacji, takiej jak otwarcie pliku, pobranie danych lub wykonanie polecenia.

Demony mina to `/System/Library/CoreServices/appleeventsd`, który rejestruje usługę `com.apple.coreservices.appleevents`.

Każda aplikacja, która może odbierać zdarzenia, sprawdzi to z demonem, dostarczając mu swój Apple Event Mach Port. A kiedy aplikacja chce wysłać zdarzenie do niego, aplikacja będzie prosić ten port od demona.

Zastosowane aplikacje wymagają uprawnień takich jak `allow appleevent-send` i `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, aby móc wysyłać zdarzenia. Zauważ, że uprawnienia takie jak `com.apple.security.temporary-exception.apple-events` mogą ograniczać dostęp do wysyłania zdarzeń, co będzie wymagać uprawnień takich jak `com.apple.private.appleevents`.

{% hint style="success" %}
Możliwe jest użycie zmiennej środowiskowej **`AEDebugSends`** w celu zapisania informacji o wysłanej wiadomości:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną na HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
