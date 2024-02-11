# FZ - Podczerwień

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Wprowadzenie <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Aby uzyskać więcej informacji na temat działania podczerwieni, sprawdź:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Odbiornik sygnału podczerwieni w Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper używa cyfrowego odbiornika sygnału podczerwieni TSOP, który **pozwala przechwytywać sygnały z pilotów podczerwieni**. Istnieją niektóre **smartfony**, takie jak Xiaomi, które również posiadają port podczerwieni, ale należy pamiętać, że **większość z nich może tylko transmitować** sygnały i nie są w stanie ich **odbierać**.

Odbiornik podczerwieni Flippera jest dość wrażliwy. Możesz nawet **przechwycić sygnał**, pozostając **gdzieś pomiędzy** pilotem a telewizorem. Bezpośrednie skierowanie pilota na port podczerwieni Flippera jest zbędne. Jest to przydatne, gdy ktoś zmienia kanały, stojąc blisko telewizora, a zarówno ty, jak i Flipper znajdujecie się w pewnej odległości.

Ponieważ **dekodowanie sygnału podczerwieni** odbywa się po stronie **oprogramowania**, Flipper Zero potencjalnie obsługuje **odbieranie i transmitowanie dowolnych kodów pilota podczerwieni**. W przypadku **nieznanych** protokołów, które nie mogły zostać rozpoznane, Flipper **zapisuje i odtwarza** surowy sygnał dokładnie tak, jak został odebrany.

## Działania

### Uniwersalne pilotaże

Flipper Zero może być używany jako **uniwersalny pilot do sterowania dowolnym telewizorem, klimatyzatorem lub centrum multimedialnym**. W tym trybie Flipper **przeprowadza atak brutalnej siły** na wszystkie **znane kody** wszystkich obsługiwanych producentów **zgodnie z słownikiem z karty SD**. Nie musisz wybierać konkretnego pilota, aby wyłączyć telewizor w restauracji.

Wystarczy nacisnąć przycisk zasilania w trybie Uniwersalnego Pilota, a Flipper będzie **sekwencyjnie wysyłał polecenia "Wyłącz"** do wszystkich telewizorów, które zna: Sony, Samsung, Panasonic... i tak dalej. Gdy telewizor odbierze sygnał, zareaguje i się wyłączy.

Taki atak brutalnej siły zajmuje czas. Im większy słownik, tym dłużej potrwa zakończenie. Niemożliwe jest ustalenie, który dokładnie sygnał telewizor rozpoznał, ponieważ nie ma żadnego sprzężenia zwrotnego z telewizora.

### Nauka nowego pilota

Możliwe jest **przechwycenie sygnału podczerwieni** za pomocą Flippera Zero. Jeśli Flipper **znajdzie sygnał w bazie danych**, automatycznie **rozpozna, jakie urządzenie to jest** i pozwoli ci z nim interakcjonować.\
Jeśli nie, Flipper może **zapisać** sygnał i pozwolić ci go **odtworzyć**.

## Odwołania

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
