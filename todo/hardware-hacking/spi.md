# SPI

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

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczny protokół komunikacji szeregowej używany w systemach wbudowanych do komunikacji na krótkie odległości między układami scalonymi (IC). Protokół komunikacji SPI wykorzystuje architekturę master-slave, która jest sterowana przez sygnał zegara i sygnał wyboru układu. Architektura master-slave składa się z mastera (zwykle mikroprocesora), który zarządza zewnętrznymi urządzeniami peryferyjnymi, takimi jak EEPROM, czujniki, urządzenia sterujące itp., które są uważane za niewolników.

Wielu niewolników może być podłączonych do mastera, ale niewolnicy nie mogą komunikować się ze sobą. Niewolnicy są zarządzani przez dwa piny: zegar i wybór układu. Ponieważ SPI jest synchronicznym protokołem komunikacji, piny wejściowe i wyjściowe podążają za sygnałami zegara. Wybór układu jest używany przez mastera do wyboru niewolnika i interakcji z nim. Gdy wybór układu jest wysoki, urządzenie niewolnika nie jest wybrane, natomiast gdy jest niski, układ został wybrany, a master będzie interagował z niewolnikiem.

MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) są odpowiedzialne za wysyłanie i odbieranie danych. Dane są wysyłane do urządzenia niewolnika przez pin MOSI, podczas gdy wybór układu jest utrzymywany na niskim poziomie. Dane wejściowe zawierają instrukcje, adresy pamięci lub dane zgodnie z kartą katalogową dostawcy urządzenia niewolnika. Po poprawnym wejściu pin MISO jest odpowiedzialny za przesyłanie danych do mastera. Dane wyjściowe są wysyłane dokładnie w następnym cyklu zegara po zakończeniu wejścia. Piny MISO przesyłają dane, aż dane zostaną w pełni przesłane lub master ustawi pin wyboru układu na wysoki (w takim przypadku niewolnik przestanie przesyłać, a master nie będzie słuchał po tym cyklu zegara).

## Zrzut oprogramowania układowego z EEPROM

Zrzut oprogramowania układowego może być przydatny do analizy oprogramowania i znajdowania w nim luk. Często oprogramowanie układowe nie jest dostępne w Internecie lub jest nieistotne z powodu różnych czynników, takich jak numer modelu, wersja itp. Dlatego wydobycie oprogramowania układowego bezpośrednio z fizycznego urządzenia może być pomocne w poszukiwaniu zagrożeń.

Uzyskanie konsoli szeregowej może być pomocne, ale często zdarza się, że pliki są tylko do odczytu. Ogranicza to analizę z różnych powodów. Na przykład, narzędzia, które są wymagane do wysyłania i odbierania pakietów, mogą nie być obecne w oprogramowaniu układowym. Dlatego wydobycie binarnych plików do inżynierii odwrotnej nie jest wykonalne. Dlatego posiadanie całego oprogramowania układowego zrzutowanego na systemie i wydobycie binarnych plików do analizy może być bardzo pomocne.

Ponadto, podczas red teaming i uzyskiwania fizycznego dostępu do urządzeń, zrzut oprogramowania układowego może pomóc w modyfikacji plików lub wstrzykiwaniu złośliwych plików, a następnie ponownym wgrywaniu ich do pamięci, co może być pomocne w implantacji tylnej furtki w urządzeniu. Dlatego istnieje wiele możliwości, które można odblokować dzięki zrzutom oprogramowania układowego.

### Programator i czytnik EEPROM CH341A

To urządzenie jest niedrogim narzędziem do zrzutowania oprogramowania układowego z EEPROM i ponownego wgrywania ich z plikami oprogramowania układowego. To popularny wybór do pracy z chipami BIOS komputerów (które są po prostu EEPROM). To urządzenie łączy się przez USB i wymaga minimalnych narzędzi, aby rozpocząć. Ponadto zazwyczaj szybko wykonuje zadanie, więc może być pomocne również w przypadku fizycznego dostępu do urządzenia.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Podłącz pamięć EEPROM do programatora CH341a i podłącz urządzenie do komputera. W przypadku, gdy urządzenie nie jest wykrywane, spróbuj zainstalować sterowniki na komputerze. Upewnij się również, że EEPROM jest podłączony w odpowiedniej orientacji (zwykle umieść pin VCC w odwrotnej orientacji do złącza USB), w przeciwnym razie oprogramowanie nie będzie w stanie wykryć układu. W razie potrzeby zapoznaj się z diagramem:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Na koniec użyj oprogramowania takiego jak flashrom, G-Flash (GUI) itp. do zrzutu oprogramowania układowego. G-Flash to minimalne narzędzie GUI, które jest szybkie i automatycznie wykrywa EEPROM. Może to być pomocne, gdy oprogramowanie układowe musi być szybko wydobyte, bez zbytniego grzebania w dokumentacji.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Po zrzucie oprogramowania układowego analiza może być przeprowadzona na plikach binarnych. Narzędzia takie jak strings, hexdump, xxd, binwalk itp. mogą być używane do wydobywania wielu informacji o oprogramowaniu układowym, a także o całym systemie plików.

Aby wydobyć zawartość z oprogramowania układowego, można użyć binwalk. Binwalk analizuje sygnatury hex i identyfikuje pliki w pliku binarnym oraz jest w stanie je wydobyć.
```
binwalk -e <filename>
```
Może to być .bin lub .rom w zależności od używanych narzędzi i konfiguracji.

{% hint style="danger" %}
Należy pamiętać, że ekstrakcja oprogramowania układowego jest delikatnym procesem i wymaga dużo cierpliwości. Każde niewłaściwe postępowanie może potencjalnie uszkodzić oprogramowanie układowe lub nawet całkowicie je usunąć, co sprawi, że urządzenie stanie się bezużyteczne. Zaleca się dokładne zapoznanie się z konkretnym urządzeniem przed próbą ekstrakcji oprogramowania układowego.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Należy pamiętać, że nawet jeśli PINOUT Pirata Bus wskazuje piny dla **MOSI** i **MISO** do podłączenia do SPI, niektóre SPIs mogą wskazywać piny jako DI i DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

W systemie Windows lub Linux możesz użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom) do zrzutu zawartości pamięci flash, uruchamiając coś takiego:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
