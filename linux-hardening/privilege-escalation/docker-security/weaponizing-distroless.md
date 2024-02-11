# Uzbrajanie Distroless

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

## Czym jest Distroless

Kontener Distroless to rodzaj kontenera, który **zawiera tylko niezbędne zależności do uruchomienia określonej aplikacji**, bez dodatkowego oprogramowania ani narzędzi, które nie są wymagane. Kontenery te są zaprojektowane tak, aby były jak **lekkie** i **bezpieczne** jak to możliwe, i mają na celu **minimalizację powierzchni ataku** poprzez usunięcie zbędnych komponentów.

Kontenery Distroless są często używane w **środowiskach produkcyjnych, gdzie bezpieczeństwo i niezawodność są najważniejsze**.

Niektóre **przykłady** **kontenerów Distroless** to:

* Udostępniane przez **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Udostępniane przez **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Uzbrajanie Distroless

Celem uzbrajania kontenera Distroless jest możliwość **wykonywania dowolnych binarnych plików i ładunków nawet przy ograniczeniach** wynikających z **Distroless** (brak powszechnych binarnych plików w systemie) oraz zabezpieczeń często spotykanych w kontenerach, takich jak **tylko do odczytu** lub **brak wykonania** w `/dev/shm`.

### Przez pamięć

Wkrótce, około 2023 roku...

### Za pomocą istniejących binarnych plików

#### openssl

****[**W tym poście**](https://www.form3.tech/engineering/content/exploiting-distroless-images) wyjaśniono, że binarny plik **`openssl`** często występuje w tych kontenerach, prawdopodobnie dlatego, że jest **potrzebny** przez oprogramowanie, które będzie uruchamiane wewnątrz kontenera.

Wykorzystując binarny plik **`openssl`**, można **wykonywać dowolne rzeczy**.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
