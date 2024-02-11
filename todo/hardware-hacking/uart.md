<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Podstawowe informacje

UART to protokół szeregowy, co oznacza, że przesyła dane między komponentami po jednym bicie na raz. W przeciwieństwie do tego, równoległe protokoły komunikacyjne przesyłają dane jednocześnie przez wiele kanałów. Powszechnie stosowane protokoły szeregowe to RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express i USB.

Zazwyczaj linia jest utrzymywana na wysokim poziomie (wartość logiczna 1) podczas gdy UART jest w stanie bezczynności. Następnie, aby sygnalizować rozpoczęcie transferu danych, nadajnik wysyła bit startu do odbiornika, podczas którego sygnał jest utrzymywany na niskim poziomie (wartość logiczna 0). Następnie nadajnik wysyła pięć do ośmiu bitów danych zawierających rzeczywistą wiadomość, po których następuje opcjonalny bit parzystości i jeden lub dwa bity stopu (o wartości logicznej 1), w zależności od konfiguracji. Bit parzystości, używany do sprawdzania błędów, rzadko jest stosowany w praktyce. Bity stopu (lub bity) oznaczają koniec transmisji.

Najczęściej stosowaną konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład, jeśli chcielibyśmy wysłać znak C, czyli 0x43 w kodzie ASCII, w konfiguracji UART 8N1, wysłalibyśmy następujące bity: 0 (bit startu); 0, 1, 0, 0, 0, 0, 1, 1 (wartość 0x43 w kodzie binarnym) i 0 (bit stopu).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Narzędzia sprzętowe do komunikacji z UART:

* Adapter USB-serial
* Adaptery z układami CP2102 lub PL2303
* Uniwersalne narzędzie, takie jak: Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

## Identyfikacja portów UART

UART ma 4 porty: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) i **GND** (Ground). Możesz być w stanie znaleźć 4 porty z literami **`TX`** i **`RX`** **napisanymi** na PCB. Jeśli jednak nie ma oznaczenia, możesz spróbować znaleźć je samodzielnie za pomocą **multimetru** lub **analizatora logicznego**.

Z użyciem **multimetru** i wyłączonym urządzeniem:

* Aby zidentyfikować pin **GND**, użyj trybu **Testu ciągłości**, umieść tylną sondę w ziemi i przetestuj czerwoną sondę, aż usłyszysz dźwięk z multimetru. Na PCB można znaleźć kilka pinów GND, więc możesz znaleźć lub nie ten należący do UART.
* Aby zidentyfikować port **VCC**, ustaw tryb **napięcia stałego** i ustaw go na 20 V napięcia. Czarna sonda na ziemi, a czerwona sonda na pinie. Włącz urządzenie. Jeśli multimetr mierzy stałe napięcie 3,3 V lub 5 V, znalazłeś pin Vcc. Jeśli otrzymasz inne napięcia, spróbuj z innymi portami.
* Aby zidentyfikować port **TX**, ustaw tryb **napięcia stałego** do 20 V napięcia, czarna sonda na ziemi, a czerwona sonda na pinie i włącz urządzenie. Jeśli napięcie fluktuuje przez kilka sekund, a następnie ustabilizuje się na wartości Vcc, najprawdopodobniej znalazłeś port TX. Dzieje się tak, ponieważ podczas uruchamiania wysyła pewne dane debugowania.
* Port **RX** będzie najbliższy do pozostałych 3, ma najmniejsze fluktuacje napięcia i najniższą wartość spośród wszystkich pinów UART.

Możesz pomylić porty TX i RX i nic się nie stanie, ale jeśli pomylić porty GND i VCC, możesz uszkodzić obwód.

Z użyciem analizatora logicznego:

## Identyfikacja prędkości transmisji UART

Najłatwiejszym sposobem na zidentyfikowanie poprawnej prędkości transmisji jest spojrzenie na wyjście pinu **TX i próba odczytania danych**. Jeśli otrzymywane dane nie są czytelne, przejdź do następnej możliwej prędkości transmisji, aż dane staną się czytelne. Możesz do tego użyć adaptera USB-serial lub uniwersalnego urządzenia, takiego jak Bus Pirate, w połączeniu z pomocnym skryptem, na przykład [baudrate.py](https://github.com/devttys0/baudrate/). Najczęściej stosowane prędkości transmisji to 9600, 38400, 19200, 57600 i 115200.

{% hint style="danger" %}
Ważne jest zauważenie, że w tym protokole musisz połączyć TX jednego urządzenia z RX drugiego!
{% endhint %}

# Bus Pirate

W tym scenariuszu będziemy podsłuchiwać komunikację UART Arduino, który wysyła wszystkie wydruki programu do Monitora szeregowego.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
