# Inne Triki Dotyczące Stron Internetowych

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia dla HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

### Nagłówek Host

Często serwer back-endowy polega na nagłówku **Host** do wykonania pewnych akcji. Na przykład, może używać jego wartości jako **domeny do wysłania resetu hasła**. Kiedy otrzymasz e-mail z linkiem do zresetowania hasła, domena używana jest ta, którą wpisujesz w nagłówku Host. W takim przypadku możesz zażądać resetu hasła innych użytkowników i zmienić domenę na taką, którą kontrolujesz, aby ukraść ich kody resetu hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Należy zauważyć, że możliwe jest, że nie musisz nawet czekać, aż użytkownik kliknie na link resetujący hasło, aby uzyskać token, ponieważ **filtry spamu lub inne urządzenia/boty pośredniczące mogą na niego kliknąć, aby go przeanalizować**.
{% endhint %}

### Sesyjne wartości logiczne

Czasami, gdy poprawnie przejdziesz pewną weryfikację, serwer back-endowy **dodaje tylko wartość logiczną "True" do atrybutu zabezpieczeń Twojej sesji**. Następnie inny punkt końcowy będzie wiedział, czy pomyślnie przeszedłeś tę weryfikację.\
Jednak jeśli **zaliczysz weryfikację** i Twoja sesja otrzyma tę wartość "True" w atrybucie zabezpieczeń, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale na które **nie powinieneś mieć uprawnień**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcjonalność rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj również używać równoważnych znaków (kropki, dużo spacji i Unicode).

### Przejęcie e-maili

Zarejestruj e-mail, a przed potwierdzeniem go zmień e-mail. Następnie, jeśli nowy e-mail potwierdzający zostanie wysłany na pierwszy zarejestrowany e-mail, możesz przejąć dowolny e-mail. Lub jeśli możesz włączyć drugi e-mail, potwierdzając pierwszy, możesz również przejąć dowolne konto.

### Dostęp do wewnętrznego serwisu pomocy firm korzystających z atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metoda TRACE

Programiści czasami zapominają wyłączyć różne opcje debugowania w środowisku produkcyjnym. Na przykład, metoda HTTP `TRACE` jest przeznaczona do celów diagnostycznych. Jeśli jest włączona, serwer internetowy odpowie na żądania korzystające z metody `TRACE`, powtarzając w odpowiedzi dokładne żądanie, które zostało otrzymane. Zachowanie to często jest nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwa wewnętrznych nagłówków uwierzytelniania, które mogą być dołączane do żądań przez odwrotne serwery proxy.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia dla HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
