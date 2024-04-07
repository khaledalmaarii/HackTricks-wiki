# Inne Triki Dotyczące Sieci

<details>

<summary><strong>Zacznij od zera i stań się ekspertem w hakowaniu AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

### Nagłówek Host

W niektórych przypadkach serwer zaufa **nagłówkowi Host** do wykonania pewnych akcji. Na przykład, może użyć jego wartości jako **domeny do wysłania resetu hasła**. Gdy otrzymasz e-mail z linkiem do zresetowania hasła, domeną używaną jest ta, którą podałeś w nagłówku Host. Następnie możesz poprosić o zresetowanie hasła innych użytkowników i zmienić domenę na kontrolowaną przez ciebie, aby ukraść ich kody resetowania hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Zauważ, że możliwe jest, że nie musisz nawet czekać, aż użytkownik kliknie na link resetujący hasło, aby uzyskać token, ponieważ być może nawet **filtry antyspamowe lub inne urządzenia/boty pośredniczące klikną na niego, aby go przeanalizować**.
{% endhint %}

### Sesyjne wartości logiczne

Czasami, gdy poprawnie przejdziesz weryfikację, serwer **po prostu doda wartość "True" do atrybutu bezpieczeństwa twojej sesji**. Następnie inny punkt końcowy będzie wiedział, czy pomyślnie przeszedłeś tę weryfikację.\
Jednak jeśli **zaliczysz weryfikację** i twoja sesja otrzyma tę wartość "True" w atrybucie bezpieczeństwa, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcjonalność Rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj również użyć równoważnych znaków (kropki, dużo spacji i Unicode).

### Przejęcie e-maili

Zarejestruj e-mail, zanim go potwierdzisz, zmień e-mail, a następnie, jeśli nowy e-mail potwierdzający zostanie wysłany na pierwszy zarejestrowany e-mail, możesz przejąć dowolny e-mail. Lub jeśli możesz włączyć drugi e-mail potwierdzający pierwszy, możesz również przejąć dowolne konto.

### Dostęp do wewnętrznego serwisu pomocy firm korzystających z atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metoda TRACE

Deweloperzy mogą zapomnieć wyłączyć różne opcje debugowania w środowisku produkcyjnym. Na przykład metoda HTTP `TRACE` jest przeznaczona do celów diagnostycznych. Jeśli jest włączona, serwer WWW będzie odpowiadał na żądania korzystające z metody `TRACE`, odbijając w odpowiedzi dokładne żądanie, które zostało odebrane. To zachowanie często jest nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwa wewnętrznych nagłówków uwierzytelniania, które mogą być dołączane do żądań przez serwery proxy odwrotne.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)
