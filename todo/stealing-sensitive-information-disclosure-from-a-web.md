# Kradzież Ujawnienia Wrażliwych Informacji z Sieci

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

Jeśli w pewnym momencie znajdziesz **stronę internetową prezentującą wrażliwe informacje na podstawie Twojej sesji**: Może to być odzwierciedlenie plików cookie, wydruk lub dane karty kredytowej lub inne wrażliwe informacje, możesz spróbować je ukraść.\
Oto główne sposoby, które możesz wypróbować, aby to osiągnąć:

* [**Ominięcie CORS**](../pentesting-web/cors-bypass.md): Jeśli możesz ominąć nagłówki CORS, będziesz mógł ukraść informacje wykonując żądanie Ajax dla złośliwej strony.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Jeśli znajdziesz podatność XSS na stronie, możesz ją wykorzystać do kradzieży informacji.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Jeśli nie możesz wstrzyknąć tagów XSS, nadal możesz ukraść informacje, używając innych zwykłych tagów HTML.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Jeśli nie ma ochrony przed tym atakiem, możesz oszukać użytkownika, aby przesłał Ci wrażliwe dane (przykład [tutaj](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).
