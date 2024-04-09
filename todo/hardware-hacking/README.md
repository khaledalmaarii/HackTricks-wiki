# Hacking sprzętowy

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## JTAG

JTAG pozwala na przeprowadzenie skanowania granicznego. Skanowanie graniczne analizuje określoną układankę, w tym wbudowane komórki skanowania granicznego i rejestry dla każdego pinu.

Standard JTAG definiuje **konkretne polecenia do przeprowadzania skanowania granicznego**, w tym:

* **BYPASS** pozwala przetestować określony układ bez konieczności przechodzenia przez inne układy.
* **SAMPLE/PRELOAD** pobiera próbkę danych wchodzących i wychodzących z urządzenia, gdy jest w normalnym trybie działania.
* **EXTEST** ustawia i odczytuje stany pinów.

Może również obsługiwać inne polecenia, takie jak:

* **IDCODE** do identyfikacji urządzenia
* **INTEST** do wewnętrznego testowania urządzenia

Możesz natknąć się na te instrukcje, gdy używasz narzędzia takiego jak JTAGulator.

### Port dostępu do testów

Skanowanie graniczne obejmuje testy czteroprzewodowego **Portu Dostępu do Testów (TAP)**, portu ogólnego przeznaczenia zapewniającego **dostęp do funkcji wsparcia testów JTAG** wbudowanych w komponent. TAP wykorzystuje następujące pięć sygnałów:

* Wejście zegara testowego (**TCK**) TCK to **zegar**, który definiuje, jak często kontroler TAP podejmie pojedynczą akcję (innymi słowy, przejdzie do następnego stanu w maszynie stanów).
* Wejście wyboru trybu testowego (**TMS**) TMS kontroluje **maszynę stanów skończonych**. Przy każdym taktowaniu zegara kontroler TAP JTAG urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest poniżej określonego progu, sygnał jest uważany za niski i interpretowany jako 0, natomiast jeśli napięcie jest powyżej określonego progu, sygnał jest uważany za wysoki i interpretowany jako 1.
* Wejście danych testowych (**TDI**) TDI to pin, który wysyła **dane do układu za pośrednictwem komórek skanowania**. Każdy producent jest odpowiedzialny za określenie protokołu komunikacyjnego przez ten pin, ponieważ JTAG tego nie definiuje.
* Wyjście danych testowych (**TDO**) TDO to pin, który wysyła **dane z układu**.
* Wejście resetowania testowego (**TRST**) Opcjonalne TRST resetuje maszynę stanów skończonych **do znanego dobrego stanu**. Alternatywnie, jeśli TMS jest utrzymywane na 1 przez pięć kolejnych cykli zegara, wywołuje reset, tak samo jak pin TRST, dlatego TRST jest opcjonalny.

Czasami będziesz w stanie znaleźć te piny oznaczone na PCB. W innych sytuacjach możesz potrzebować ich **znalezienia**.

### Identyfikacja pinów JTAG

Najszybszym, ale najdroższym sposobem wykrywania portów JTAG jest użycie **JTAGulatora**, urządzenia stworzonego specjalnie w tym celu (choć może **również wykrywać układy UART**).

Posiada **24 kanały**, które można podłączyć do pinów płytek. Następnie wykonuje **atak BF** wszystkich możliwych kombinacji wysyłając polecenia skanowania granicznego **IDCODE** i **BYPASS**. Jeśli otrzyma odpowiedź, wyświetla kanał odpowiadający każdemu sygnałowi JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikacji pinów JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) załadowanego na mikrokontrolerze kompatybilnym z Arduino.

Korzystając z **JTAGenum**, najpierw musisz **zdefiniować piny urządzenia sondującego**, które będziesz używać do wyliczenia. Musisz odnieść się do schematu pinów urządzenia, a następnie połączyć te piny z punktami testowymi na docelowym urządzeniu.

**Trzecim sposobem** identyfikacji pinów JTAG jest **inspekcja PCB** w poszukiwaniu jednego z pinów. W niektórych przypadkach PCB mogą wygodnie dostarczyć **interfejs Tag-Connect**, co stanowi jasny sygnał, że płyta ma również złącze JTAG. Możesz zobaczyć, jak wygląda ten interfejs na stronie [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Dodatkowo, inspekcja **arkuszy danych chipsetów na PCB** może ujawnić schematy pinów wskazujące na interfejsy JTAG.

## SDW

SWD to protokół specyficzny dla ARM zaprojektowany do debugowania.

Interfejs SWD wymaga **dwóch pinów**: dwukierunkowego sygnału **SWDIO**, który jest odpowiednikiem pinów **TDI i TDO w JTAG** oraz zegara, oraz **SWCLK**, który jest odpowiednikiem **TCK** w JTAG. Wiele urządzeń obsługuje **Port Szeregowy lub Port Debugowania JTAG (SWJ-DP)**, łączny interfejs JTAG i SWD, który umożliwia podłączenie sondy SWD lub JTAG do celu.

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
