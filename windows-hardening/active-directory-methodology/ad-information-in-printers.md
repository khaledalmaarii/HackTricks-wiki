<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


W Internecie istnieje wiele blogów, które **podkreślają niebezpieczeństwo pozostawienia drukarek skonfigurowanych z LDAP z domyślnymi/słabymi** danymi logowania.\
Jest to dlatego, że atakujący może **oszukać drukarkę, aby uwierzyła w fałszywy serwer LDAP** (zwykle wystarczy `nc -vv -l -p 444`) i przechwycić dane uwierzytelniające drukarki **w postaci tekstu jawnego**.

Ponadto, wiele drukarek zawiera **dzienniki z nazwami użytkowników** lub nawet może **pobrać wszystkie nazwy użytkowników** z kontrolera domeny.

Wszystkie te **wrażliwe informacje** i powszechne **braki w zabezpieczeniach** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Kilka blogów na ten temat:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Konfiguracja drukarki
- **Lokalizacja**: Lista serwerów LDAP znajduje się w: `Sieć > Ustawienia LDAP > Konfiguracja LDAP`.
- **Zachowanie**: Interfejs umożliwia modyfikację serwera LDAP bez ponownego wprowadzania danych uwierzytelniających, co ma na celu wygodę użytkownika, ale stwarza ryzyko bezpieczeństwa.
- **Wykorzystanie**: Wykorzystanie polega na przekierowaniu adresu serwera LDAP do kontrolowanego komputera i wykorzystaniu funkcji "Testuj połączenie" do przechwycenia danych uwierzytelniających.

## Przechwytywanie danych uwierzytelniających

**Aby uzyskać bardziej szczegółowe kroki, odwołaj się do oryginalnego [źródła](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metoda 1: Słuchacz Netcat
Prosty słuchacz Netcat może wystarczyć:
```bash
sudo nc -k -v -l -p 386
```
Jednak sukces tej metody jest zmienny.

### Metoda 2: Pełny serwer LDAP z Slapd
Bardziej niezawodne podejście polega na skonfigurowaniu pełnego serwera LDAP, ponieważ drukarka wykonuje puste powiązanie, a następnie zapytanie przed próbą powiązania poświadczeń.

1. **Konfiguracja serwera LDAP**: Przewodnik krok po kroku znajduje się w [tym źródle](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Kluczowe kroki**:
- Zainstaluj OpenLDAP.
- Skonfiguruj hasło administratora.
- Zaimportuj podstawowe schematy.
- Ustaw nazwę domeny w bazie danych LDAP.
- Skonfiguruj TLS LDAP.
3. **Uruchomienie usługi LDAP**: Po skonfigurowaniu usługi LDAP można ją uruchomić za pomocą:
```bash
slapd -d 2
```
## Odwołania
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
