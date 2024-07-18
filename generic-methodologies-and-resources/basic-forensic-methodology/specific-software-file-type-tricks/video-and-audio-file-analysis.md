{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}

**Manipulacja plikami audio i wideo** jest podstawą wyzwań **forensycznych CTF**, wykorzystując **steganografię** i analizę metadanych do ukrywania lub odkrywania tajnych wiadomości. Narzędzia takie jak **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** są niezbędne do sprawdzania metadanych plików i identyfikacji typów treści.

W przypadku wyzwań związanych z dźwiękiem, **[Audacity](http://www.audacityteam.org/)** wyróżnia się jako wiodące narzędzie do przeglądania przebiegów fal i analizy spektrogramów, niezbędnych do odkrywania tekstu zakodowanego w dźwięku. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** jest bardzo polecany do szczegółowej analizy spektrogramów. **Audacity** pozwala na manipulację dźwiękiem, taką jak zwalnianie lub odwracanie ścieżek, aby wykryć ukryte wiadomości. **[Sox](http://sox.sourceforge.net/)**, narzędzie wiersza poleceń, doskonale sprawdza się w konwersji i edycji plików audio.

Manipulacja **najmniej znaczącymi bitami (LSB)** to powszechna technika w steganografii dźwiękowej i wideo, wykorzystująca stałe rozmiary fragmentów plików multimedialnych do dyskretnego osadzania danych. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** jest przydatny do dekodowania wiadomości ukrytych jako **tony DTMF** lub **alfabet Morse'a**.

Wyzwania wideo często dotyczą formatów kontenerów, które łączą strumienie audio i wideo. **[FFmpeg](http://ffmpeg.org/)** jest narzędziem do analizy i manipulacji tych formatów, zdolnym do demultipleksacji i odtwarzania treści. Dla programistów, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integruje możliwości FFmpeg'a z Pythonem do zaawansowanych interakcji skryptowych.

Ten zestaw narzędzi podkreśla wszechstronność wymaganą w wyzwaniach CTF, gdzie uczestnicy muszą stosować szeroki zakres technik analizy i manipulacji, aby odkryć ukryte dane w plikach audio i wideo.

## Referencje
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
  
{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
