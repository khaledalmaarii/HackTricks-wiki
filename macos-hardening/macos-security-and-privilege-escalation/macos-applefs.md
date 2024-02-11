# macOS AppleFS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Apple Propietary File System (APFS)

**Apple File System (APFS)** to nowoczesny system plików zaprojektowany w celu zastąpienia Hierarchical File System Plus (HFS+). Jego rozwój był napędzany potrzebą **poprawy wydajności, bezpieczeństwa i efektywności**.

Niektóre ważne cechy APFS to:

1. **Dzielenie przestrzeni**: APFS umożliwia wielu woluminom **dzielenie tej samej wolnej przestrzeni** na jednym fizycznym urządzeniu. Umożliwia to bardziej efektywne wykorzystanie przestrzeni, ponieważ woluminy mogą dynamicznie rosnąć i zmniejszać się bez konieczności ręcznego zmieniania rozmiaru lub partycjonowania.
1. Oznacza to, w porównaniu do tradycyjnych partycji na dyskach plików, **że w APFS różne partycje (woluminy) dzielą całą przestrzeń dyskową**, podczas gdy zwykła partycja zazwyczaj miała ustalony rozmiar.
2. **Snapshoty**: APFS obsługuje **tworzenie snapshotów**, które są **tylko do odczytu**, punktami w czasie instancji systemu plików. Snapshoty umożliwiają efektywne tworzenie kopii zapasowych i łatwe przywracanie systemu, ponieważ zużywają minimalną dodatkową przestrzeń dyskową i można je szybko tworzyć lub przywracać.
3. **Klony**: APFS może **tworzyć klony plików lub katalogów, które dzielą tę samą przestrzeń dyskową** co oryginał, dopóki klon lub oryginalny plik nie zostanie zmodyfikowany. Ta funkcja zapewnia efektywny sposób tworzenia kopii plików lub katalogów bez duplikowania przestrzeni dyskowej.
4. **Szyfrowanie**: APFS **natywnie obsługuje szyfrowanie całego dysku**, a także szyfrowanie na poziomie pliku i katalogu, zwiększając bezpieczeństwo danych w różnych przypadkach użycia.
5. **Ochrona przed awariami**: APFS używa schematu metadanych **kopiuj przy zapisie**, który zapewnia spójność systemu plików nawet w przypadku nagłej utraty zasilania lub awarii systemu, zmniejszając ryzyko uszkodzenia danych.

Ogólnie APFS oferuje bardziej nowoczesny, elastyczny i wydajny system plików dla urządzeń Apple, skupiając się na poprawie wydajności, niezawodności i bezpieczeństwa.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Wolumin `Data` jest zamontowany w **`/System/Volumes/Data`** (możesz to sprawdzić za pomocą polecenia `diskutil apfs list`).

Lista firmlinksów znajduje się w pliku **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
Na **lewo** znajduje się ścieżka katalogu na **woluminie Systemowym**, a na **prawo** ścieżka katalogu, gdzie jest mapowany na **wolumin Danych**. Więc `/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
