# Triki dotyczące plików ZIP

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

**Narzędzia wiersza poleceń** do zarządzania **plikami ZIP** są niezbędne do diagnozowania, naprawiania i łamania plików ZIP. Oto kilka kluczowych narzędzi:

- **`unzip`**: Ujawnia przyczyny, dla których plik ZIP może nie zostać zdekompresowany.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu pliku ZIP.
- **`zipinfo`**: Wyświetla zawartość pliku ZIP bez ich wypakowywania.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki ZIP.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do brutalnego łamania haseł plików ZIP, skuteczne dla haseł do około 7 znaków.

Specyfikacja [formatu pliku ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zawiera szczegółowe informacje na temat struktury i standardów plików ZIP.

Należy zauważyć, że zabezpieczone hasłem pliki ZIP **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz, co stanowi lukę w zabezpieczeniach, która nie jest wspólna dla plików RAR ani 7z, które szyfrują te informacje. Ponadto pliki ZIP zaszyfrowane starszą metodą ZipCrypto są podatne na **atak na tekst jawnie dostępny**, jeśli dostępna jest niezaszyfrowana kopia skompresowanego pliku. Ten atak wykorzystuje znane treści do złamania hasła pliku ZIP, podatność ta została szczegółowo opisana w [artykule HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalej wyjaśniona w [tym artykule naukowym](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Jednak pliki ZIP zabezpieczone szyfrowaniem **AES-256** są odporne na ten atak na tekst jawnie dostępny, co pokazuje znaczenie wyboru bezpiecznych metod szyfrowania dla danych poufnych.

## Referencje
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
