<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


#

# JTAG

JTAG umożliwia przeprowadzenie skanu granicznego. Skan graniczny analizuje określone układy, w tym wbudowane komórki i rejestry skanu granicznego dla każdego pinu.

Standard JTAG definiuje **konkretne polecenia do przeprowadzania skanów granicznych**, w tym:

* **BYPASS** pozwala na przetestowanie określonego układu bez konieczności przechodzenia przez inne układy.
* **SAMPLE/PRELOAD** pobiera próbkę danych wchodzących i wychodzących z urządzenia, gdy jest w normalnym trybie działania.
* **EXTEST** ustawia i odczytuje stany pinów.

Może również obsługiwać inne polecenia, takie jak:

* **IDCODE** do identyfikacji urządzenia
* **INTEST** do wewnętrznego testowania urządzenia

Możesz natknąć się na te instrukcje, gdy korzystasz z narzędzia takiego jak JTAGulator.

## Port dostępu testowego

Skanowanie graniczne obejmuje testy czteroprzewodowego **Portu Dostępu Testowego (TAP)**, uniwersalnego portu zapewniającego **dostęp do funkcji wsparcia testu JTAG** wbudowanych w komponent. TAP wykorzystuje następujące pięć sygnałów:

* Wejście zegara testowego (**TCK**) TCK to **zegar**, który definiuje, jak często kontroler TAP będzie podejmował pojedynczą akcję (innymi słowy, przejście do następnego stanu w maszynie stanów).
* Wybór trybu testowego (**TMS**) wejście TMS kontroluje **maszynę stanów skończonych**. Przy każdym taktowaniu zegara kontroler TAP JTAG urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest poniżej określonego progu, sygnał jest uważany za niski i interpretowany jako 0, natomiast jeśli napięcie jest powyżej określonego progu, sygnał jest uważany za wysoki i interpretowany jako 1.
* Wejście danych testowych (**TDI**) TDI to pin, który **wysyła dane do układu za pomocą komórek skanujących**. Każdy producent jest odpowiedzialny za zdefiniowanie protokołu komunikacyjnego przez ten pin, ponieważ JTAG tego nie definiuje.
* Wyjście danych testowych (**TDO**) TDO to pin, który **wysyła dane z układu**.
* Wejście resetowania testowego (**TRST**) Opcjonalne TRST resetuje **maszynę stanów skończonych do znanego stanu**. Alternatywnie, jeśli TMS jest utrzymywane na wartości 1 przez pięć kolejnych cykli zegara, wywołuje reset, tak samo jak pin TRST, dlatego TRST jest opcjonalny.

Czasami będziesz w stanie znaleźć te piny oznaczone na PCB. W innych przypadkach może być konieczne **odnalezienie ich**.

## Identyfikowanie pinów JTAG

Najszybszym, ale najdroższym sposobem wykrywania portów JTAG jest użycie **JTAGulatora**, urządzenia stworzonego specjalnie w tym celu (choć może **również wykrywać układy UART**).

Posiada **24 kanały**, które można podłączyć do pinów płytek. Następnie wykonuje atak **BF** wszystkich możliwych kombinacji, wysyłając polecenia skanu granicznego **IDCODE** i **BYPASS**. Jeśli otrzyma odpowiedź, wyświetla kanał odpowiadający każdemu sygnałowi JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikacji pinów JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) załadowanego na mikrokontrolerze kompatybilnym z Arduino.

Korzystając z **JTAGenum**, najpierw **zdefiniujesz piny sondowania** urządzenia, które będziesz używać do wyliczenia. Musisz odwołać się do diagramu pinów urządzenia, a następnie połączyć te piny z punktami testowymi na docelowym urządzeniu.

Trzecim sposobem identyfikacji pinów JTAG jest **sprawdzenie PCB** pod kątem jednego z pinów. W niektórych przypadkach PCB mogą wygodnie dostarczać **interfejs Tag-Connect**, który jest wyraźnym wskazaniem, że płyta posiada złącze JTAG. Możesz zobaczyć, jak wygląda ten interfejs na stronie [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Dodatkowo, przeglądanie **kart katalogowych układów scalonych na PCB** może ujawnić diagramy pinów wskazujące na interfejsy JTAG.

# SDW

SWD to protokół specyficzny dla ARM, zaprojektowany do debugowania.

Interfejs SWD wymaga **dwóch pinów**: dwukierunkowego sygnału **SWDIO**, który jest odpowiednikiem pinów **TDI i TDO w JTAG**, oraz zegara **SWCLK**, który jest odpowiednikiem **TCK** w JTAG. Wiele urządzeń obsługuje **Port Debugowania Serial Wire lub JTAG (SWJ-DP)**, łączny interfejs JTAG i SWD, który umożliwia podłączenie sondy SWD lub JTAG do docelowego urządzenia.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
