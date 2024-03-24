# Narzędzia do wycinania i odzyskiwania danych

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Narzędzia do wycinania i odzyskiwania

Więcej narzędzi na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najczęściej używanym narzędziem w dziedzinie kryminalistyki do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz go, zainstaluj i spraw, aby przetworzył plik w celu znalezienia "ukrytych" plików. Zauważ, że Autopsy jest przeznaczony do obsługi obrazów dysków i innych rodzajów obrazów, ale nie prostych plików.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizy plików binarnych w celu znalezienia osadzonej zawartości. Można je zainstalować za pomocą `apt`, a jego źródło znajduje się na [GitHub](https://github.com/ReFirmLabs/binwalk).

**Przydatne polecenia**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Innym powszechnie używanym narzędziem do znajdowania ukrytych plików jest **foremost**. Konfigurację foremost można znaleźć w pliku `/etc/foremost.conf`. Jeśli chcesz wyszukać określone pliki, odkomentuj je. Jeśli nic nie odkomentujesz, foremost będzie przeszukiwał domyślnie skonfigurowane typy plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** to kolejne narzędzie, które można użyć do znalezienia i wyodrębnienia **plików osadzonych w pliku**. W tym przypadku będziesz musiał odkomentować z pliku konfiguracyjnego (_/etc/scalpel/scalpel.conf_) typy plików, które chcesz wyodrębnić.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

To narzędzie znajduje się w Kali, ale można je znaleźć tutaj: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

To narzędzie może przeskanować obraz i **wydobyć pcapy** wewnątrz niego, **informacje sieciowe (adresy URL, domeny, adresy IP, adresy MAC, maile)** oraz więcej **plików**. Wystarczy tylko:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

Możesz go znaleźć pod adresem [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Posiada wersje z interfejsem graficznym i wiersza poleceń. Możesz wybrać **typy plików**, które chcesz, aby PhotoRec wyszukał.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) oraz [narzędzie na stronie internetowej](https://binvis.io/#/).

#### Funkcje BinVis

* Wizualizator **struktury** plików
* Wiele wykresów dla różnych punktów skupienia
* Skupienie na fragmentach próbki
* **Wykrywanie ciągów znaków i zasobów**, w plikach wykonywalnych PE lub ELF, np.
* Uzyskiwanie **wzorców** do kryptografii plików
* **Wykrywanie** algorytmów pakowania lub kodowania
* **Identyfikacja** steganografii poprzez wzorce
* **Wizualne** porównywanie binarne

BinVis to świetne **miejsce początkowe, aby zapoznać się z nieznanym celem** w scenariuszu black-boxing.

## Konkretne narzędzia do odzyskiwania danych

### FindAES

Wyszukuje klucze AES, szukając ich harmonogramów kluczy. Potrafi znaleźć klucze 128, 192 i 256 bitowe, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

## Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby zobaczyć obrazy z terminala.\
Możesz użyć narzędzia wiersza poleceń systemu Linux **pdftotext**, aby przekształcić plik PDF na tekst i go przeczytać.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
