# Triki Stego

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Wyciąganie danych z plików**

### **Binwalk**
Narzędzie do wyszukiwania ukrytych plików i danych osadzonych w plikach binarnych. Jest instalowane za pomocą `apt`, a jego źródło jest dostępne na [GitHubie](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Odzyskuje pliki na podstawie ich nagłówków i stopki, przydatne dla obrazów png. Zainstalowany za pomocą `apt` z źródłem na [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Pomaga w przeglądaniu metadanych plików, dostępny [tutaj](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Podobnie jak exiftool, służy do przeglądania metadanych. Można go zainstalować za pomocą `apt`, źródło dostępne na [GitHub](https://github.com/Exiv2/exiv2), a także posiada [oficjalną stronę internetową](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Plik**
Zidentyfikuj rodzaj pliku, z którym masz do czynienia.

### **Ciągi znaków**
Wyciąga czytelne ciągi znaków z plików, używając różnych ustawień kodowania do filtrowania wyników.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Porównanie (cmp)**
Przydatne do porównywania zmodyfikowanego pliku z jego oryginalną wersją znalezioną online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Wyciąganie Ukrytych Danych z Tekstu**

### **Ukryte Dane w Spacjach**
Niewidoczne znaki w pozornie pustych spacjach mogą ukrywać informacje. Aby wyciągnąć te dane, odwiedź [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Wyciąganie Danych z Obrazów**

### **Identyfikowanie Szczegółów Obrazu za pomocą GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) służy do określania typów plików obrazów i identyfikowania potencjalnych uszkodzeń. Wykonaj poniższą komendę, aby sprawdzić obraz:
```bash
./magick identify -verbose stego.jpg
```
Aby spróbować naprawić uszkodzony obraz, dodanie komentarza metadanych może pomóc:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide do ukrywania danych**

Steghide ułatwia ukrywanie danych w plikach `JPEG, BMP, WAV i AU`, umożliwiając osadzanie i wyodrębnianie zaszyfrowanych danych. Instalacja jest prosta za pomocą `apt`, a [kod źródłowy jest dostępny na GitHubie](https://github.com/StefanoDeVuono/steghide).

**Polecenia:**
- `steghide info plik` ujawnia, czy plik zawiera ukryte dane.
- `steghide extract -sf plik [--passphrase hasło]` wyodrębnia ukryte dane, hasło jest opcjonalne.

Aby wykonać ekstrakcję za pomocą przeglądarki internetowej, odwiedź [tę stronę](https://futureboy.us/stegano/decinput.html).

**Atak brutalnej siły za pomocą Stegcracker:**
- Aby spróbować złamać hasło Steghide, użyj [stegcracker](https://github.com/Paradoxis/StegCracker.git) w następujący sposób:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg dla plików PNG i BMP**

zsteg specjalizuje się w odkrywaniu ukrytych danych w plikach PNG i BMP. Instalacja odbywa się za pomocą `gem install zsteg`, a [źródło znajduje się na GitHubie](https://github.com/zed-0xff/zsteg).

**Polecenia:**
- `zsteg -a plik` stosuje wszystkie metody wykrywania na pliku.
- `zsteg -E plik` określa ładunek dla ekstrakcji danych.

### **StegoVeritas i Stegsolve**

**stegoVeritas** sprawdza metadane, wykonuje transformacje obrazu i stosuje siłowe łamanie LSB, między innymi. Użyj `stegoveritas.py -h`, aby uzyskać pełną listę opcji, a `stegoveritas.py stego.jpg` do wykonania wszystkich sprawdzeń.

**Stegsolve** stosuje różne filtry kolorów, aby odkryć ukryte teksty lub wiadomości w obrazach. Jest dostępny na [GitHubie](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT do wykrywania ukrytej zawartości**

Techniki Fast Fourier Transform (FFT) mogą ujawnić ukrytą zawartość w obrazach. Przydatne zasoby to:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic na GitHubie](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy dla plików dźwiękowych i obrazów**

Stegpy umożliwia osadzanie informacji w plikach obrazów i dźwięku, obsługując formaty takie jak PNG, BMP, GIF, WebP i WAV. Jest dostępny na [GitHubie](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck do analizy plików PNG**

Aby analizować pliki PNG lub sprawdzać ich autentyczność, użyj:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatkowe narzędzia do analizy obrazów**

Aby przeprowadzić dalsze badania, rozważ odwiedzenie:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Wyciąganie danych z plików audio**

**Steganografia audio** oferuje unikalną metodę ukrywania informacji w plikach dźwiękowych. Do osadzania lub odzyskiwania ukrytej zawartości wykorzystuje się różne narzędzia.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide to wszechstronne narzędzie przeznaczone do ukrywania danych w plikach JPEG, BMP, WAV i AU. Szczegółowe instrukcje znajdują się w [dokumentacji trików steganograficznych](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
To narzędzie jest kompatybilne z różnymi formatami, w tym PNG, BMP, GIF, WebP i WAV. Aby uzyskać więcej informacji, odwołaj się do [sekcji Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
ffmpeg jest niezbędny do oceny integralności plików audio, podkreślania szczegółowych informacji i wykrywania wszelkich niezgodności.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg doskonale nadaje się do ukrywania i wydobywania danych w plikach WAV, korzystając z strategii najmniej znaczącego bitu. Jest dostępny na [GitHub](https://github.com/ragibson/Steganography#WavSteg). Polecenia obejmują:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound umożliwia szyfrowanie i wykrywanie informacji w plikach dźwiękowych za pomocą AES-256. Można go pobrać ze [strony oficjalnej](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
Niezastąpione narzędzie do wizualnej i analitycznej inspekcji plików dźwiękowych, Sonic Visualizer może odkryć ukryte elementy, które są niewykrywalne innymi środkami. Odwiedź [oficjalną stronę](https://www.sonicvisualiser.org/) po więcej informacji.

### **DTMF Tones - Sygnały wybierania**
Wykrywanie sygnałów DTMF w plikach dźwiękowych można osiągnąć za pomocą narzędzi online, takich jak [ten detektor DTMF](https://unframework.github.io/dtmf-detect/) i [DialABC](http://dialabc.com/sound/detect/index.html).

## **Inne techniki**

### **Binary Length SQRT - Kod QR**
Dane binarne, które dają liczbę całkowitą po podniesieniu do kwadratu, mogą reprezentować kod QR. Skorzystaj z tego fragmentu kodu, aby sprawdzić:
```python
import math
math.sqrt(2500) #50
```
Do konwersji binarnej na obraz, sprawdź [dcode](https://www.dcode.fr/binary-image). Aby odczytać kody QR, użyj [tego czytnika kodów kreskowych online](https://online-barcode-reader.inliteresearch.com/).

### **Tłumaczenie Braille'a**
Do tłumaczenia Braille'a, doskonałym narzędziem jest [Branah Braille Translator](https://www.branah.com/braille-translator).

## **Odnośniki**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi Twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
