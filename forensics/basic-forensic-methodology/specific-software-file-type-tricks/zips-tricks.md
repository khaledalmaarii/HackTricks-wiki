# Sztuczki z plikami ZIP

{% hint style="success" %}
Dowiedz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
{% endhint %}

**Narzędzia wiersza poleceń** do zarządzania **plikami ZIP** są niezbędne do diagnozowania, naprawiania i łamania plików ZIP. Oto kilka kluczowych narzędzi:

- **`unzip`**: Ujawnia przyczyny, dla których plik ZIP może nie zostać zdekompresowany.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu pliku ZIP.
- **`zipinfo`**: Wyświetla zawartość pliku ZIP bez ich wypakowywania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki ZIP.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brutalnego łamania haseł plików ZIP, skuteczne dla haseł do około 7 znaków.

Specyfikacja [formatu pliku ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera szczegółowe informacje na temat struktury i standardów plików ZIP.

Należy zauważyć, że pliki ZIP zabezpieczone hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz, co stanowi lukę w zabezpieczeniach, nieobecną w plikach RAR lub 7z, które szyfrują te informacje. Ponadto pliki ZIP zaszyfrowane starszą metodą ZipCrypto są podatne na **atak na tekst jawnie**, jeśli dostępna jest niezaszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znane treści do złamania hasła pliku ZIP, podatność ta została opisana w artykule [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalej wyjaśniona w [tym artykule naukowym](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Jednak pliki ZIP zabezpieczone szyfrowaniem **AES-256** są odporne na ten atak na tekst jawnie, co pokazuje znaczenie wyboru bezpiecznych metod szyfrowania dla danych poufnych.

## Referencje
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/) 

{% hint style="success" %}
Dowiedz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
{% endhint %}
