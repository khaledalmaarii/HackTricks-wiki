<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Narzędzia do odzyskiwania danych

Więcej narzędzi na stronie [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Najczęściej używanym narzędziem w forensyce do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz go, zainstaluj i skonfiguruj, aby znaleźć "ukryte" pliki. Należy zauważyć, że Autopsy jest przeznaczony do obsługi obrazów dysków i innych rodzajów obrazów, ale nie prostych plików.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizy plików binarnych w celu znalezienia osadzonej zawartości. Można go zainstalować za pomocą `apt`, a jego źródło znajduje się na [GitHubie](https://github.com/ReFirmLabs/binwalk).

**Przydatne polecenia**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Innym powszechnie stosowanym narzędziem do wyszukiwania ukrytych plików jest **foremost**. Konfigurację narzędzia foremost można znaleźć w pliku `/etc/foremost.conf`. Jeśli chcesz wyszukać tylko określone pliki, odkomentuj je. Jeśli nie odkomentujesz niczego, foremost będzie wyszukiwać domyślnie skonfigurowane typy plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** to kolejne narzędzie, które można użyć do wyszukiwania i wyodrębniania **plików osadzonych w pliku**. W tym przypadku będziesz musiał odkomentować z pliku konfiguracyjnego (_/etc/scalpel/scalpel.conf_) typy plików, które chcesz wyodrębnić.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Ten narzędzie jest dostępne w Kali, ale można je znaleźć tutaj: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

To narzędzie może przeskanować obraz i **wyodrębnić pliki pcap** z niego, **informacje sieciowe (adresy URL, domeny, adresy IP, adresy MAC, maile)** oraz **inne pliki**. Wystarczy tylko:
```
bulk_extractor memory.img -o out_folder
```
Przejdź przez **wszystkie informacje**, które narzędzie zgromadziło (hasła?), **analizuj** **pakiety** (czytaj [**Analiza Pcap**](../pcap-inspection/)), szukaj **dziwnych domen** (domeny związane z **malware** lub **nieistniejące**).

## PhotoRec

Możesz go znaleźć pod adresem [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Dostępne są wersje z interfejsem graficznym i wiersza poleceń. Możesz wybrać **typy plików**, które PhotoRec ma przeszukać.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) i [narzędzie na stronie internetowej](https://binvis.io/#/).

### Funkcje BinVis

* Wizualizacja i aktywny **podgląd struktury**
* Wiele wykresów dla różnych punktów skupienia
* Skupianie się na fragmentach próbki
* **Wykrywanie ciągów znaków i zasobów**, w plikach wykonywalnych PE lub ELF, na przykład
* Uzyskiwanie **wzorców** do kryptanalizy plików
* **Wykrywanie** algorytmów pakowania lub kodowania
* **Identyfikacja** steganografii na podstawie wzorców
* **Wizualne** porównywanie binarne

BinVis to doskonały **punkt wyjścia do zapoznania się z nieznanym celem** w scenariuszu black-boxing.

# Narzędzia do odzyskiwania konkretnych danych

## FindAES

Wyszukuje klucze AES, szukając ich harmonogramów kluczy. Może znaleźć klucze o długości 128, 192 i 256 bitów, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

# Narzędzia uzupełniające

Możesz użyć [**viu**](https://github.com/atanunq/viu), aby wyświetlać obrazy z poziomu terminala.\
Możesz użyć narzędzia wiersza poleceń **pdftotext** w systemie Linux, aby przekształcić plik PDF na tekst i go odczytać.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajduj podatności, które mają największe znaczenie, abyś mógł je szybko naprawić. Intruder śledzi Twoją powierzchnię ataku, wykonuje skanowanie zagrożeń proaktywnych, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **na GitHubie.**

</details>
