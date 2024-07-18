# Kradzież Ujawnienia Wrażliwych Informacji z Sieci

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) oraz [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

Jeśli w pewnym momencie znajdziesz **stronę internetową prezentującą wrażliwe informacje na podstawie Twojej sesji**: Może to być odzwierciedlenie plików cookie, wydruk lub szczegóły karty kredytowej lub inne wrażliwe informacje, możesz spróbować je ukraść.\
Oto główne sposoby, które możesz spróbować zastosować:

* [**Ominięcie CORS**](pentesting-web/cors-bypass.md): Jeśli możesz ominąć nagłówki CORS, będziesz mógł ukraść informacje wykonując żądanie Ajax dla złośliwej strony.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): Jeśli znajdziesz podatność XSS na stronie, możesz ją wykorzystać do kradzieży informacji.
* [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): Jeśli nie możesz wstrzyknąć tagów XSS, nadal możesz ukraść informacje, używając innych zwykłych tagów HTML.
* [**Clickjaking**](pentesting-web/clickjacking.md): Jeśli nie ma ochrony przed tym atakiem, możesz oszukać użytkownika, aby przesłał Ci wrażliwe dane (przykład [tutaj](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) oraz [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}
