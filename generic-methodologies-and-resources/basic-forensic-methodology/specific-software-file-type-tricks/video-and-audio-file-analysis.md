<details>

<summary><strong>Zacznij od zera i stań się ekspertem w hakowaniu AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną na HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

**Manipulacja plikami audio i wideo** jest podstawą w **wyzwaniach z zakresu forensyki CTF**, wykorzystując **steganografię** i analizę metadanych do ukrywania lub odkrywania tajnych wiadomości. Narzędzia takie jak **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** są niezbędne do sprawdzania metadanych plików i identyfikowania typów treści.

W przypadku wyzwań związanych z dźwiękiem, **[Audacity](http://www.audacityteam.org/)** wyróżnia się jako wiodące narzędzie do przeglądania przebiegów falowych i analizy spektrogramów, niezbędnych do odkrywania tekstu zakodowanego w dźwięku. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** jest bardzo polecany do szczegółowej analizy spektrogramów. **Audacity** umożliwia manipulację dźwiękiem, taką jak zwalnianie lub odwracanie ścieżek, aby wykryć ukryte wiadomości. **[Sox](http://sox.sourceforge.net/)**, narzędzie wiersza poleceń, doskonale sprawdza się w konwersji i edycji plików audio.

Manipulacja **najmniej znaczącymi bitami (LSB)** to powszechna technika w steganografii dźwiękowej i wideo, wykorzystująca stałe fragmenty plików multimedialnych do dyskretnego osadzania danych. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** jest przydatny do dekodowania wiadomości ukrytych jako sygnały **DTMF** lub **alfabet Morse'a**.

Wyzwania wideo często dotyczą formatów kontenerów, które łączą strumienie audio i wideo. **[FFmpeg](http://ffmpeg.org/)** jest narzędziem do analizy i manipulacji tych formatów, zdolnym do demultipleksacji i odtwarzania treści. Dla programistów **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integruje możliwości FFmpeg'a z Pythonem do zaawansowanych interakcji skryptowych.

Ten zestaw narzędzi podkreśla wszechstronność wymaganą w wyzwaniach CTF, gdzie uczestnicy muszą stosować szeroki zakres technik analizy i manipulacji, aby odkryć ukryte dane w plikach audio i wideo.

## Referencje
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<details>

<summary><strong>Zacznij od zera i stań się ekspertem w hakowaniu AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną na HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
