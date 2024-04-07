# SPI

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczny protokół komunikacji szeregowej używany w systemach wbudowanych do komunikacji na krótkie odległości między układami scalonymi (ICs). Protokół komunikacji SPI wykorzystuje architekturę master-slave, którą sterują sygnały zegara i wyboru układu. Architektura master-slave składa się z mastera (zwykle mikroprocesora), który zarządza zewnętrznymi urządzeniami peryferyjnymi, takimi jak EEPROM, sensory, urządzenia sterujące, itp., które są uważane za slave'y.

Do mastera można podłączyć wiele slave'ów, ale slave'y nie mogą ze sobą komunikować. Slave'y są zarządzane przez dwa piny, zegar i wybór układu. Ponieważ SPI to protokół komunikacji synchronicznej, piny wejściowe i wyjściowe podążają za sygnałami zegara. Wybór układu jest używany przez mastera do wyboru slave'a i interakcji z nim. Gdy wybór układu jest wysoki, urządzenie slave nie jest wybrane, podczas gdy gdy jest niski, układ został wybrany i master będzie interagować ze slave'em.

Piny MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) są odpowiedzialne za wysyłanie i odbieranie danych. Dane są wysyłane do urządzenia slave'a przez pin MOSI, podczas gdy wybór układu jest niski. Dane wejściowe zawierają instrukcje, adresy pamięci lub dane zgodnie z kartą danych dostawcy urządzenia slave. Po poprawnym wejściu, pin MISO jest odpowiedzialny za przesyłanie danych do mastera. Dane wyjściowe są wysyłane dokładnie w następnym cyklu zegara po zakończeniu danych wejściowych. Piny MISO przesyłają dane do momentu, gdy dane są w pełni przesłane lub master ustawia pin wyboru układu na wysoki (w takim przypadku slave przestanie przesyłać dane, a master nie będzie słuchał po tym cyklu zegara).

## Dump Flash

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Należy zauważyć, że nawet jeśli PINOUT Pirate Bus wskazuje piny dla **MOSI** i **MISO** do podłączenia do SPI, niektóre SPI mogą wskazywać piny jako DI i DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

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

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
