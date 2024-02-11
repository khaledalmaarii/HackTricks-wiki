<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Narzędzia do wycinania

## Autopsy

Najczęściej używanym narzędziem w forensyce do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz go, zainstaluj i spraw, aby przetwarzał plik w celu znalezienia "ukrytych" plików. Należy zauważyć, że Autopsy jest przeznaczony do obsługi obrazów dysków i innych rodzajów obrazów, ale nie prostych plików.

## Binwalk <a id="binwalk"></a>

**Binwalk** to narzędzie do wyszukiwania plików binarnych, takich jak obrazy i pliki dźwiękowe, zawierających osadzone pliki i dane.
Można go zainstalować za pomocą `apt`, jednak [źródło](https://github.com/ReFirmLabs/binwalk) można znaleźć na githubie.
**Przydatne polecenia**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Innym powszechnie stosowanym narzędziem do wyszukiwania ukrytych plików jest **foremost**. Konfigurację narzędzia foremost można znaleźć w `/etc/foremost.conf`. Jeśli chcesz wyszukać tylko określone pliki, odkomentuj je. Jeśli nie odkomentujesz niczego, foremost będzie wyszukiwać domyślnie skonfigurowane typy plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** to kolejne narzędzie, które można użyć do wyszukiwania i wyodrębniania **plików osadzonych w pliku**. W tym przypadku będziesz musiał odkomentować z pliku konfiguracyjnego \(_/etc/scalpel/scalpel.conf_\) typy plików, które chcesz wyodrębnić.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Ten narzędzie jest dostępne w Kali, ale można je znaleźć tutaj: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

To narzędzie może przeskanować obraz i **wyodrębnić pliki pcap** z niego, **informacje sieciowe \(adresy URL, domeny, adresy IP, adresy MAC, maile\)** oraz inne **pliki**. Wystarczy tylko wykonać:
```text
bulk_extractor memory.img -o out_folder
```
Przeanalizuj **wszystkie informacje**, które narzędzie zgromadziło \(hasła?\), **analizuj** pakiety \(czytaj [**analizę Pcaps**](../pcap-inspection/)\), szukaj **dziwnych domen** \(domeny związane z **malware** lub **nieistniejące**\).

## PhotoRec

Możesz go znaleźć pod adresem [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dostępna jest wersja z interfejsem graficznym (GUI) i wiersza poleceń (CLI). Możesz wybrać **typy plików**, które PhotoRec ma przeszukać.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Narzędzia do wycinania konkretnych danych

## FindAES

Wyszukuje klucze AES, szukając ich harmonogramów kluczy. Potrafi znaleźć klucze o długości 128, 192 i 256 bitów, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

# Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby wyświetlać obrazy w terminalu.
Możesz użyć narzędzia wiersza poleceń **pdftotext** w systemie Linux, aby przekształcić plik PDF na tekst i go odczytać.



<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
