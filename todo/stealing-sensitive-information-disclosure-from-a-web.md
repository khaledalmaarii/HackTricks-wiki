# Kradzież ujawnienia wrażliwych informacji z sieci

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

Jeśli w pewnym momencie znajdziesz **stronę internetową, która prezentuje wrażliwe informacje na podstawie twojej sesji**: Może to być odzwierciedlenie ciasteczek, lub drukowanie szczegółów karty kredytowej lub innych wrażliwych informacji, możesz spróbować je ukraść.\
Oto główne sposoby, które możesz spróbować osiągnąć:

* [**CORS bypass**](../pentesting-web/cors-bypass.md): Jeśli możesz obejść nagłówki CORS, będziesz w stanie ukraść informacje, wykonując żądanie Ajax do złośliwej strony.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Jeśli znajdziesz lukę XSS na stronie, możesz być w stanie ją wykorzystać do kradzieży informacji.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Jeśli nie możesz wstrzyknąć tagów XSS, nadal możesz być w stanie ukraść informacje, używając innych standardowych tagów HTML.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Jeśli nie ma ochrony przed tym atakiem, możesz być w stanie oszukać użytkownika, aby wysłał ci wrażliwe dane (przykład [tutaj](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
