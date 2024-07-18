{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}


# Narzędzia do wycinania

## Autopsy

Najczęściej używanym narzędziem w dziedzinie kryminalistyki do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz go, zainstaluj i spraw, aby przetworzył plik w celu znalezienia "ukrytych" plików. Zauważ, że Autopsy jest przeznaczony do obsługi obrazów dysków i innych rodzajów obrazów, ale nie prostych plików.

## Binwalk <a id="binwalk"></a>

**Binwalk** to narzędzie do przeszukiwania plików binarnych, takich jak obrazy i pliki dźwiękowe, w poszukiwaniu osadzonych plików i danych.
Można go zainstalować za pomocą `apt`, jednak [źródło](https://github.com/ReFirmLabs/binwalk) można znaleźć na githubie.
**Przydatne polecenia**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Kolejnym powszechnie stosowanym narzędziem do znajdowania ukrytych plików jest **foremost**. Konfigurację foremost można znaleźć w pliku `/etc/foremost.conf`. Jeśli chcesz wyszukać określone pliki, odkomentuj je. Jeśli nic nie odkomentujesz, foremost będzie przeszukiwał domyślnie skonfigurowane typy plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** to kolejne narzędzie, które może być użyte do znalezienia i wyodrębnienia **plików osadzonych w pliku**. W tym przypadku będziesz musiał odkomentować z pliku konfiguracyjnego \(_/etc/scalpel/scalpel.conf_\) typy plików, które chcesz wyodrębnić.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

To narzędzie znajduje się w Kali, ale można je znaleźć tutaj: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

To narzędzie może przeskanować obraz i **wydobyć pliki pcaps** wewnątrz niego, **informacje sieciowe \(adresy URL, domeny, adresy IP, adresy MAC, maile\)** oraz więcej **plików**. Wystarczy tylko:
```text
bulk_extractor memory.img -o out_folder
```
Przejdź przez **wszystkie informacje**, które narzędzie zgromadziło \(hasła?\), **analizuj** pakiety \(czytaj[ **Analiza Pcap**](../pcap-inspection/)\), szukaj **dziwnych domen** \(domeny związane z **malware** lub **nieistniejące**\).

## PhotoRec

Możesz go znaleźć pod adresem [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dostępny jest w wersji z interfejsem graficznym i wiersza poleceń. Możesz wybrać **typy plików**, które chcesz, aby PhotoRec wyszukiwał.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Konkretne narzędzia do wycinania danych

## FindAES

Wyszukuje klucze AES, szukając ich harmonogramów kluczy. Potrafi znaleźć klucze 128, 192 i 256 bitowe, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

# Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby zobaczyć obrazy z terminala.
Możesz użyć narzędzia wiersza poleceń systemu Linux **pdftotext**, aby przekształcić plik pdf na tekst i go przeczytać.



{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
