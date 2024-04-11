# UART

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

UART to protokół szeregowy, co oznacza, że przesyła dane między komponentami po jednym bicie na raz. W przeciwieństwie do tego, protokoły komunikacji równoległej przesyłają dane jednocześnie przez wiele kanałów. Powszechne protokoły szeregowe obejmują RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express i USB.

Zazwyczaj linia jest utrzymywana na wysokim poziomie (o wartości logicznej 1), gdy UART znajduje się w stanie bezczynności. Następnie, aby sygnalizować rozpoczęcie transferu danych, nadajnik wysyła bit startowy do odbiornika, podczas którego sygnał jest utrzymywany na niskim poziomie (o wartości logicznej 0). Następnie nadajnik wysyła pięć do ośmiu bitów danych zawierających rzeczywistą wiadomość, a następnie opcjonalny bit parzystości i jeden lub dwa bity stopu (o wartości logicznej 1), w zależności od konfiguracji. Bit parzystości, używany do sprawdzania błędów, rzadko jest widoczny w praktyce. Bit(y) stopu oznaczają koniec transmisji.

Najczęściej stosowaną konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład, jeśli chcielibyśmy wysłać znak C, czyli 0x43 w ASCII, w konfiguracji UART 8N1, wysłalibyśmy następujące bity: 0 (bit startowy); 0, 1, 0, 0, 0, 0, 1, 1 (wartość 0x43 w systemie binarnym) i 0 (bit stopu).

![](<../../.gitbook/assets/image (761).png>)

Narzędzia sprzętowe do komunikacji z UART:

* Adapter USB-do-szeregowy
* Adaptery z układami CP2102 lub PL2303
* Narzędzie wielofunkcyjne, takie jak: Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikacja portów UART

UART ma 4 porty: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage) i **GND**(Ground). Możesz znaleźć 4 porty z literami **`TX`** i **`RX`** **napisanymi** na PCB. Jeśli nie ma wskazówek, możesz spróbować znaleźć je samodzielnie, używając **multimetru** lub **analizatora logicznego**.

Z **multimetrem** i wyłączonym urządzeniem:

* Aby zidentyfikować pin **GND**, użyj trybu **Testu ciągłości**, umieść tylną sondę w uziemieniu i przetestuj czerwoną sondą, aż usłyszysz dźwięk z multimetru. Na PCB można znaleźć kilka pinów GND, więc możesz znaleźć lub nie ten należący do UART.
* Aby zidentyfikować port **VCC**, ustaw tryb **napięcia stałego** i ustaw go na 20 V napięcia. Czarna sonda na uziemieniu, a czerwona sonda na pinie. Włącz urządzenie. Jeśli multimetr mierzy stałe napięcie 3,3 V lub 5 V, znalazłeś pin Vcc. Jeśli otrzymasz inne napięcia, spróbuj z innymi portami.
* Aby zidentyfikować port **TX**, tryb **napięcia stałego** do 20 V napięcia, czarna sonda na uziemieniu, a czerwona sonda na pinie, i włącz urządzenie. Jeśli napięcie zmienia się przez kilka sekund, a następnie ustabilizuje się na wartości Vcc, najprawdopodobniej znalazłeś port TX. Dzieje się tak, ponieważ podczas włączania wysyła pewne dane diagnostyczne.
* Port **RX** będzie najbliższy pozostałym 3, ma najmniejsze wahania napięcia i najniższą ogólną wartość ze wszystkich pinów UART.

Możesz pomylić porty TX i RX i nic się nie stanie, ale jeśli pomyliłbyś port GND z portem VCC, możesz uszkodzić obwód.

W niektórych urządzeniach docelowych port UART jest wyłączony przez producenta poprzez wyłączenie RX lub TX lub nawet obu. W takim przypadku pomocne może być śledzenie połączeń na płycie drukowanej i znalezienie punktu rozgałęzienia. Silnym wskazaniem potwierdzającym brak wykrycia UART i przerwania obwodu jest sprawdzenie gwarancji urządzenia. Jeśli urządzenie zostało dostarczone z jakąś gwarancją, producent pozostawia pewne interfejsy diagnostyczne (w tym przypadku UART) i dlatego musiał odłączyć UART i ponownie go podłączyć podczas debugowania. Te piny rozgałęzienia można połączyć przez lutowanie lub przewody mostkujące.

### Identyfikacja szybkości transmisji UART

Najłatwiejszym sposobem zidentyfikowania poprawnej szybkości transmisji jest spojrzenie na **wyjście pinu TX i próba odczytania danych**. Jeśli otrzymywane dane nie są czytelne, przełącz się na następną możliwą szybkość transmisji, aż dane staną się czytelne. Możesz użyć adaptera USB-do-szeregowy lub urządzenia wielofunkcyjnego, takiego jak Bus Pirate, w połączeniu z pomocniczym skryptem, takim jak [baudrate.py](https://github.com/devttys0/baudrate/). Najczęstsze szybkości transmisji to 9600, 38400, 19200, 57600 i 115200.

{% hint style="danger" %}
Ważne jest zauważenie, że w tym protokole musisz połączyć TX jednego urządzenia z RX drugiego!
{% endhint %}

## Adapter UART CP210X do TTY

Układ Chip CP210X jest używany w wielu płytach prototypowych, takich jak NodeMCU (z esp8266) do komunikacji szeregowej. Te adaptery są stosunkowo niedrogie i mogą być używane do połączenia z interfejsem UART celu. Urządzenie ma 5 pinów: 5V, GND, RXD, TXD, 3.3V. Upewnij się, że podłączasz napięcie zgodnie z obsługiwanym przez cel, aby uniknąć uszkodzeń. Na koniec podłącz pin RXD adaptera do pinu TXD celu i pin TXD adaptera do pinu RXD celu.

Jeśli adapter nie jest wykrywany, upewnij się, że sterowniki CP210X są zainstalowane w systemie hosta. Po wykryciu i podłączeniu adaptera można użyć narzędzi takich jak picocom, minicom lub screen.

Aby wyświetlić podłączone urządzenia w systemach Linux/MacOS:
```
ls /dev/
```
Do podstawowej interakcji z interfejsem UART użyj następującej komendy:
```
picocom /dev/<adapter> --baud <baudrate>
```
Dla minicom użyj poniższej komendy, aby go skonfigurować:
```
minicom -s
```
Skonfiguruj ustawienia takie jak szybkość transmisji (baudrate) i nazwę urządzenia w opcji `Konfiguracja portu szeregowego`.

Po skonfigurowaniu użyj polecenia `minicom`, aby uruchomić konsolę UART.

## UART za pośrednictwem Arduino UNO R3 (Płytki z wymiennym układem Atmel 328p)

W przypadku braku dostępności adapterów UART Serial to USB, można użyć Arduino UNO R3 z szybkim hackiem. Ponieważ Arduino UNO R3 jest zazwyczaj dostępny wszędzie, może to zaoszczędzić dużo czasu.

Arduino UNO R3 ma wbudowany adapter USB do szeregowego na płycie. Aby uzyskać połączenie UART, wystarczy wyjąć mikrokontroler Atmel 328p z płytki. Ten hack działa na wariantach Arduino UNO R3, w których układ Atmel 328p nie jest przylutowany do płytki (w wersji SMD jest używany). Połącz pin RX Arduino (Pin cyfrowy 0) z pinem TX interfejsu UART oraz pin TX Arduino (Pin cyfrowy 1) z pinem RX interfejsu UART.

W końcu zaleca się korzystanie z Arduino IDE, aby uzyskać Konsolę Szeregową. W sekcji `narzędzia` w menu wybierz opcję `Konsola szeregowa` i ustaw szybkość transmisji zgodnie z interfejsem UART.

## Bus Pirate

W tym scenariuszu będziemy podsłuchiwać komunikację UART Arduino, która wysyła wszystkie wydruki programu do Monitora Szeregowego.
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
## Zrzucanie oprogramowania układowego za pomocą konsoli UART

Konsola UART zapewnia doskonały sposób pracy z oprogramowaniem układowym w środowisku uruchomieniowym. Jednak gdy dostęp do konsoli UART jest tylko do odczytu, może to wprowadzić wiele ograniczeń. W wielu urządzeniach wbudowanych oprogramowanie układowe jest przechowywane w pamięci EEPROM i wykonywane w procesorach posiadających pamięć ulotną. Dlatego oprogramowanie układowe jest przechowywane w trybie tylko do odczytu, ponieważ oryginalne oprogramowanie układowe podczas produkcji znajduje się w samej pamięci EEPROM, a jakiekolwiek nowe pliki mogą zostać utracone z powodu pamięci ulotnej. Dlatego zrzucanie oprogramowania układowego jest cennym wysiłkiem podczas pracy z oprogramowaniem wbudowanym.

Istnieje wiele sposobów, aby to zrobić, a sekcja SPI obejmuje metody wyodrębniania oprogramowania bezpośrednio z pamięci EEPROM za pomocą różnych urządzeń. Chociaż zaleca się najpierw spróbować zrzucić oprogramowanie za pomocą UART, ponieważ zrzucanie oprogramowania za pomocą fizycznych urządzeń i interakcji zewnętrznych może być ryzykowne.

Zrzucanie oprogramowania z konsoli UART wymaga najpierw uzyskania dostępu do bootloaderów. Wielu popularnych producentów korzysta z <b>uboot</b> (Uniwersalny Bootloader) jako swojego bootloadera do ładowania systemu Linux. Dlatego uzyskanie dostępu do <b>uboot</b> jest konieczne.

Aby uzyskać dostęp do bootloadera <b>boot</b>, podłącz port UART do komputera i użyj dowolnego narzędzia konsoli szeregowej, a zasilanie urządzenia pozostaw odłączone. Gdy konfiguracja jest gotowa, naciśnij klawisz Enter i przytrzymaj go. Na koniec podłącz zasilanie do urządzenia i pozwól mu się uruchomić.

Działanie to przerwie ładowanie <b>uboot</b> i spowoduje wyświetlenie menu. Zaleca się zrozumienie poleceń <b>uboot</b> i skorzystanie z menu pomocy, aby je wyświetlić. Może to być polecenie `help`. Ponieważ różni producenci używają różnych konfiguracji, konieczne jest zrozumienie każdej z nich osobno.

Zazwyczaj poleceniem do zrzucenia oprogramowania jest:
```
md
```
który oznacza "zrzut pamięci". Spowoduje to wyświetlenie zawartości pamięci (EEPROM) na ekranie. Zaleca się zapisanie danych z konsoli szeregowej przed rozpoczęciem procedury, aby przechwycić zrzut pamięci.

Na koniec wystarczy usunąć wszystkie zbędne dane z pliku dziennika i zapisać plik jako `nazwapliku.rom` oraz użyć narzędzia binwalk do wyodrębnienia zawartości:
```
binwalk -e <filename.rom>
```
To wyświetli możliwe zawartości z EEPROM zgodnie z sygnaturami znalezionymi w pliku szesnastkowym.

Należy jednak zauważyć, że nie zawsze <b>uboot</b> jest odblokowany, nawet jeśli jest używany. Jeśli klawisz Enter nic nie robi, sprawdź inne klawisze, takie jak klawisz Spacji, itp. Jeśli bootloader jest zablokowany i nie zostanie przerwany, ta metoda nie zadziała. Aby sprawdzić, czy <b>uboot</b> jest bootloaderem urządzenia, sprawdź wynik na konsoli UART podczas uruchamiania urządzenia. Może wspominać o <b>uboot</b> podczas uruchamiania.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
