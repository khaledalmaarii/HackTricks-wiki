# SPI

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczny protokół komunikacji szeregowej używany w systemach wbudowanych do komunikacji na krótkie odległości między układami scalonymi (IC). Protokół komunikacji SPI wykorzystuje architekturę master-slave, którą sterują sygnały zegara i wyboru układu. Architektura master-slave składa się z mastera (zwykle mikroprocesora), który zarządza zewnętrznymi urządzeniami peryferyjnymi, takimi jak EEPROM, sensory, urządzenia sterujące, itp., które są uważane za slave'y.

Do mastera można podłączyć wiele slave'ów, ale slave'y nie mogą komunikować się ze sobą. Slave'y są zarządzane przez dwa piny, zegar i wybór układu. Ponieważ SPI to protokół komunikacji synchronicznej, piny wejściowe i wyjściowe podążają za sygnałami zegara. Wybór układu jest używany przez mastera do wyboru slave'a i interakcji z nim. Gdy wybór układu jest wysoki, urządzenie slave nie jest wybrane, podczas gdy gdy jest niski, układ został wybrany i master będzie interagować ze slave'em.

Piny MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) są odpowiedzialne za wysyłanie i odbieranie danych. Dane są wysyłane do urządzenia slave poprzez pin MOSI, podczas gdy wybór układu jest utrzymywany na niskim poziomie. Dane wejściowe zawierają instrukcje, adresy pamięci lub dane zgodnie z kartą katalogową dostawcy urządzenia slave. Po poprawnym wejściu pin MISO jest odpowiedzialny za przesyłanie danych do mastera. Dane wyjściowe są wysyłane dokładnie w następnym cyklu zegara po zakończeniu danych wejściowych. Piny MISO przesyłają dane do momentu, aż dane zostaną w pełni przesłane lub master ustawi pin wyboru układu na wysoki (w takim przypadku slave przestanie przesyłać dane, a master nie będzie słuchał po tym cyklu zegara).

## Wydobywanie oprogramowania z EEPROMów

Wydobywanie oprogramowania może być przydatne do analizy oprogramowania i znajdowania w nich podatności. Często oprogramowanie nie jest dostępne w internecie lub jest nieistotne z powodu różnych czynników, takich jak numer modelu, wersja, itp. Dlatego wydobycie oprogramowania bezpośrednio z fizycznego urządzenia może być pomocne, aby być bardziej konkretnym podczas poszukiwania zagrożeń.

Uzyskanie konsoli szeregowej może być pomocne, ale często zdarza się, że pliki są tylko do odczytu. Ogranicza to analizę z różnych powodów. Na przykład narzędzia wymagane do wysyłania i odbierania pakietów nie będą dostępne w oprogramowaniu. Dlatego wydobycie binariów w celu ich zreverse engineeringu nie jest wykonalne. Dlatego posiadanie całego oprogramowania wydobytego na systemie i wydobycie binariów do analizy może być bardzo pomocne.

Ponadto, podczas czerwonego reamingu i uzyskiwania fizycznego dostępu do urządzeń, wydobycie oprogramowania może pomóc w modyfikowaniu plików lub wstrzykiwaniu złośliwych plików, a następnie ponowne wgrywanie ich do pamięci, co może być pomocne przy implantacji tylnych drzwi do urządzenia. Dlatego istnieje wiele możliwości, które można odblokować dzięki wydobyciu oprogramowania.

### Programator i czytnik EEPROM CH341A

To urządzenie to niedrogi narzędzie do wydobywania oprogramowania z EEPROMów oraz ponownego wgrywania ich z plikami oprogramowania. Było to popularnym wyborem do pracy z chipami BIOS komputerów (które są po prostu EEPROMami). To urządzenie łączy się przez USB i potrzebuje minimalnych narzędzi do rozpoczęcia pracy. Ponadto zazwyczaj szybko wykonuje zadanie, więc może być pomocne także przy dostępie do fizycznego urządzenia.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Podłącz pamięć EEPROM z programatorem CH341a i podłącz urządzenie do komputera. Jeśli urządzenie nie jest wykrywane, spróbuj zainstalować sterowniki do komputera. Upewnij się również, że EEPROM jest podłączony we właściwej orientacji (zazwyczaj umieść pin VCC w odwróconej orientacji do złącza USB), w przeciwnym razie oprogramowanie nie będzie w stanie wykryć układu. W razie potrzeby odwołaj się do schematu:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Na koniec użyj oprogramowania takiego jak flashrom, G-Flash (GUI), itp. do wydobycia oprogramowania. G-Flash to minimalne narzędzie GUI, które działa szybko i automatycznie wykrywa EEPROM. Może to być pomocne, jeśli oprogramowanie musi zostać szybko wydobyte, bez zbytniego majstrowania z dokumentacją.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Po wydobyciu oprogramowania, analizę można przeprowadzić na plikach binarnych. Narzędzia takie jak strings, hexdump, xxd, binwalk, itp. mogą być używane do wydobycia wielu informacji na temat oprogramowania oraz całego systemu plików również.

Aby wydobyć zawartość z oprogramowania, można użyć narzędzia binwalk. Binwalk analizuje sygnatury szesnastkowe i identyfikuje pliki w pliku binarnym oraz jest zdolny do ich wydobycia.
```
binwalk -e <filename>
```
Plik może być .bin lub .rom w zależności od użytych narzędzi i konfiguracji.

{% hint style="danger" %}
Należy pamiętać, że ekstrakcja oprogramowania układowego jest delikatnym procesem i wymaga dużo cierpliwości. Dowolne niewłaściwe obchodzenie się z tym procesem może potencjalnie uszkodzić oprogramowanie układowe lub nawet całkowicie je usunąć, co sprawi, że urządzenie będzie niezdatne do użytku. Zaleca się dokładne zbadanie konkretnego urządzenia przed próbą ekstrakcji oprogramowania układowego.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Należy zauważyć, że nawet jeśli PINOUT Pirate Bus wskazuje piny dla **MOSI** i **MISO** do podłączenia do SPI, niektóre SPI mogą wskazywać piny jako DI i DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

W systemie Windows lub Linux można użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom), aby zrzucić zawartość pamięci flash, uruchamiając coś w rodzaju:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
