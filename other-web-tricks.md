# Inne Triki Dotyczące Sieci

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

### Nagłówek Host

Wiele razy back-end ufa **nagłówkowi Host** do wykonania pewnych akcji. Na przykład, może użyć jego wartości jako **domeny do wysłania resetu hasła**. Kiedy otrzymasz e-mail z linkiem do zresetowania hasła, domeną używaną jest ta, którą podałeś w nagłówku Host. Wtedy możesz zażądać resetu hasła innych użytkowników i zmienić domenę na kontrolowaną przez ciebie, aby ukraść ich kody resetowania hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Zauważ, że możliwe jest, że nie musisz nawet czekać, aż użytkownik kliknie w link resetujący hasło, aby uzyskać token, ponieważ być może nawet **filtry antyspamowe lub inne urządzenia/boty pośredniczące klikną w niego, aby go przeanalizować**.
{% endhint %}

### Sesja z wartościami logicznymi

Czasami, gdy poprawnie przejdziesz weryfikację, back-end po prostu **dodaje wartość "True" do atrybutu bezpieczeństwa twojej sesji**. Następnie inny punkt końcowy będzie wiedział, czy pomyślnie przeszedłeś tę weryfikację.\
Jednakże, jeśli **zaliczysz weryfikację** i twoja sesja otrzyma tę wartość "True" w atrybucie bezpieczeństwa, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcjonalność Rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj również użyć równoważnych znaków (kropki, dużo spacji i Unicode).

### Przejęcie e-maili

Zarejestruj e-mail, zanim go potwierdzisz, zmień e-mail, a następnie, jeśli nowy e-mail potwierdzający zostanie wysłany na pierwszy zarejestrowany e-mail, możesz przejąć dowolny e-mail. Lub jeśli możesz włączyć drugi e-mail potwierdzający pierwszy, możesz również przejąć dowolne konto.

### Dostęp do wewnętrznego serwisu pomocy firm korzystających z atlassian

{% embed url="https://nazwafirmy.atlassian.net/servicedesk/customer/user/login" %}

### Metoda TRACE

Programiści mogą zapomnieć wyłączyć różne opcje debugowania w środowisku produkcyjnym. Na przykład metoda HTTP `TRACE` jest przeznaczona do celów diagnostycznych. Jeśli jest włączona, serwer WWW będzie odpowiadał na żądania korzystające z metody `TRACE`, odbijając w odpowiedzi dokładne żądanie, które zostało odebrane. To zachowanie często jest nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwa wewnętrznych nagłówków uwierzytelniania, które mogą być dołączane do żądań przez proksy odwracające.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}
