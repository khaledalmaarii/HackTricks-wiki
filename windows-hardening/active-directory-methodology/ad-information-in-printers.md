{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


Istnieje kilka blogów w Internecie, które **podkreślają niebezpieczeństwa związane z pozostawieniem drukarek skonfigurowanych z LDAP z domyślnymi/słabymi** danymi logowania.\
Dzieje się tak, ponieważ atakujący może **oszukać drukarkę, aby uwierzytelniła się w fałszywym serwerze LDAP** (zazwyczaj `nc -vv -l -p 444` wystarczy) i przechwycić **dane logowania drukarki w postaci czystego tekstu**.

Ponadto, wiele drukarek będzie zawierać **dzienniki z nazwami użytkowników** lub może nawet być w stanie **pobierać wszystkie nazwy użytkowników** z kontrolera domeny.

Wszystkie te **wrażliwe informacje** oraz powszechny **brak bezpieczeństwa** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Niektóre blogi na ten temat:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Konfiguracja drukarki
- **Lokalizacja**: Lista serwerów LDAP znajduje się w: `Sieć > Ustawienia LDAP > Konfiguracja LDAP`.
- **Zachowanie**: Interfejs pozwala na modyfikacje serwera LDAP bez ponownego wprowadzania danych logowania, co ma na celu wygodę użytkownika, ale stwarza ryzyko bezpieczeństwa.
- **Eksploatacja**: Eksploatacja polega na przekierowaniu adresu serwera LDAP do kontrolowanej maszyny i wykorzystaniu funkcji "Testuj połączenie" do przechwycenia danych logowania.

## Przechwytywanie danych logowania

**Aby uzyskać bardziej szczegółowe kroki, zapoznaj się z oryginalnym [źródłem](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metoda 1: Nasłuchiwacz Netcat
Prosty nasłuchiwacz netcat może wystarczyć:
```bash
sudo nc -k -v -l -p 386
```
Jednak sukces tej metody jest różny.

### Metoda 2: Pełny serwer LDAP z Slapd
Bardziej niezawodne podejście polega na skonfigurowaniu pełnego serwera LDAP, ponieważ drukarka wykonuje null bind, a następnie zapytanie przed próbą powiązania poświadczeń.

1. **Konfiguracja serwera LDAP**: Przewodnik opiera się na krokach z [tego źródła](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Kluczowe kroki**:
- Zainstaluj OpenLDAP.
- Skonfiguruj hasło administratora.
- Importuj podstawowe schematy.
- Ustaw nazwę domeny w bazie danych LDAP.
- Skonfiguruj LDAP TLS.
3. **Wykonanie usługi LDAP**: Po skonfigurowaniu, usługę LDAP można uruchomić za pomocą:
```bash
slapd -d 2
```
## Odniesienia
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
