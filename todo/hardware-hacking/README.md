# Hardware Hacking

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## JTAG

JTAG pozwala na przeprowadzenie skanowania granic. Skanowanie granic analizuje określone obwody, w tym wbudowane komórki skanowania granic i rejestry dla każdego pinu.

Standard JTAG definiuje **specyficzne polecenia do przeprowadzania skanowania granic**, w tym następujące:

* **BYPASS** pozwala na testowanie konkretnego układu bez obciążenia przechodzenia przez inne układy.
* **SAMPLE/PRELOAD** pobiera próbkę danych wchodzących i wychodzących z urządzenia, gdy działa w normalnym trybie.
* **EXTEST** ustawia i odczytuje stany pinów.

Może również wspierać inne polecenia, takie jak:

* **IDCODE** do identyfikacji urządzenia
* **INTEST** do wewnętrznego testowania urządzenia

Możesz natknąć się na te instrukcje, gdy używasz narzędzia takiego jak JTAGulator.

### Port dostępu do testów

Skanowanie granic obejmuje testy czteroprzewodowego **Portu Dostępu do Testów (TAP)**, ogólnego portu, który zapewnia **dostęp do funkcji wsparcia testów JTAG** wbudowanych w komponent. TAP używa następujących pięciu sygnałów:

* Wejście zegara testowego (**TCK**) TCK to **zegarek**, który definiuje, jak często kontroler TAP podejmie pojedynczą akcję (innymi słowy, przeskoczy do następnego stanu w maszynie stanów).
* Wejście wyboru trybu testowego (**TMS**) TMS kontroluje **maszynę stanów skończonych**. Przy każdym uderzeniu zegara kontroler TAP JTAG urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest poniżej określonego progu, sygnał jest uważany za niski i interpretowany jako 0, natomiast jeśli napięcie jest powyżej określonego progu, sygnał jest uważany za wysoki i interpretowany jako 1.
* Wejście danych testowych (**TDI**) TDI to pin, który wysyła **dane do układu przez komórki skanowania**. Każdy producent jest odpowiedzialny za zdefiniowanie protokołu komunikacyjnego przez ten pin, ponieważ JTAG tego nie definiuje.
* Wyjście danych testowych (**TDO**) TDO to pin, który wysyła **dane z układu**.
* Wejście resetu testowego (**TRST**) Opcjonalny TRST resetuje maszynę stanów skończonych **do znanego dobrego stanu**. Alternatywnie, jeśli TMS jest utrzymywany na 1 przez pięć kolejnych cykli zegara, wywołuje reset, w ten sam sposób, w jaki zrobiłby to pin TRST, dlatego TRST jest opcjonalny.

Czasami będziesz mógł znaleźć te piny oznaczone na PCB. W innych przypadkach możesz potrzebować **je znaleźć**.

### Identyfikacja pinów JTAG

Naj szybszym, ale najdroższym sposobem na wykrycie portów JTAG jest użycie **JTAGulator**, urządzenia stworzonego specjalnie w tym celu (choć może **również wykrywać pinouty UART**).

Ma **24 kanały**, które możesz podłączyć do pinów płyty. Następnie wykonuje **atak BF** wszystkich możliwych kombinacji, wysyłając polecenia skanowania granic **IDCODE** i **BYPASS**. Jeśli otrzyma odpowiedź, wyświetla kanał odpowiadający każdemu sygnałowi JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikacji pinów JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) załadowanego na mikrokontrolerze kompatybilnym z Arduino.

Używając **JTAGenum**, najpierw **zdefiniujesz piny urządzenia sondy**, które będziesz używać do enumeracji. Musisz odwołać się do diagramu pinów urządzenia, a następnie połączyć te piny z punktami testowymi na docelowym urządzeniu.

**Trzecim sposobem** identyfikacji pinów JTAG jest **inspekcja PCB** w poszukiwaniu jednego z pinoutów. W niektórych przypadkach PCB mogą wygodnie zapewniać **interfejs Tag-Connect**, co jest wyraźnym wskazaniem, że płyta ma również złącze JTAG. Możesz zobaczyć, jak ten interfejs wygląda na [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Dodatkowo, inspekcja **kart katalogowych chipsetów na PCB** może ujawnić diagramy pinów wskazujące na interfejsy JTAG.

## SDW

SWD to protokół specyficzny dla ARM zaprojektowany do debugowania.

Interfejs SWD wymaga **dwóch pinów**: dwukierunkowego sygnału **SWDIO**, który jest odpowiednikiem pinów **TDI i TDO JTAG** oraz zegara, i **SWCLK**, który jest odpowiednikiem **TCK** w JTAG. Wiele urządzeń wspiera **Port Debugowania Szeregowego lub Port Debugowania JTAG (SWJ-DP)**, połączony interfejs JTAG i SWD, który umożliwia podłączenie sondy SWD lub JTAG do celu.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
