<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

Poniższe kroki są zalecane do modyfikacji konfiguracji uruchamiania urządzenia i bootloaderów, takich jak U-boot:

1. **Dostęp do interpretera powłoki bootloadera**:
- Podczas uruchamiania naciśnij "0", spację lub inne zidentyfikowane "magiczne kody", aby uzyskać dostęp do interpretera powłoki bootloadera.

2. **Modyfikacja argumentów uruchamiania**:
- Wykonaj następujące polecenia, aby dodać '`init=/bin/sh`' do argumentów uruchamiania, umożliwiając wykonanie polecenia powłoki:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Skonfiguruj serwer TFTP**:
- Skonfiguruj serwer TFTP do ładowania obrazów przez lokalną sieć:
%%%
#setenv ipaddr 192.168.2.2 #lokalny adres IP urządzenia
#setenv serverip 192.168.2.1 #adres IP serwera TFTP
#saveenv
#reset
#ping 192.168.2.1 #sprawdź dostęp do sieci
#tftp ${loadaddr} uImage-3.6.35 #loadaddr przyjmuje adres, pod którym ma zostać załadowany plik oraz nazwę pliku obrazu na serwerze TFTP
%%%

4. **Wykorzystaj `ubootwrite.py`**:
- Użyj `ubootwrite.py`, aby zapisać obraz U-boota i przesłać zmodyfikowane oprogramowanie w celu uzyskania dostępu root.

5. **Sprawdź funkcje debugowania**:
- Sprawdź, czy są włączone funkcje debugowania, takie jak szczegółowe rejestrowanie, ładowanie dowolnych jąder lub uruchamianie z niezaufanych źródeł.

6. **Ostrożność przy ingerencji w sprzęt**:
- Bądź ostrożny, łącząc jedno złącze z masą i oddziałując na układy SPI lub NAND flash podczas sekwencji uruchamiania urządzenia, szczególnie przed dekompresją jądra. Przed zwieraniem pinów skonsultuj się z kartą danych układu NAND flash.

7. **Skonfiguruj podstępny serwer DHCP**:
- Skonfiguruj podstępny serwer DHCP z złośliwymi parametrami, które urządzenie przyjmie podczas rozruchu PXE. Wykorzystaj narzędzia takie jak pomocniczy serwer DHCP Metasploita (MSF). Zmodyfikuj parametr 'FILENAME' za pomocą poleceń wstrzyknięcia poleceń takich jak `'a";/bin/sh;#'`, aby przetestować walidację danych wejściowych dla procedur uruchamiania urządzenia.

**Uwaga**: Kroki związane z fizycznym oddziaływaniem na piny urządzenia (*oznaczone gwiazdką) należy podchodzić z najwyższą ostrożnością, aby uniknąć uszkodzenia urządzenia.


## Referencje
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
