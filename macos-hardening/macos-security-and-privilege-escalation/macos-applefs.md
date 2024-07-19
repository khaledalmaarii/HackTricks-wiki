# macOS AppleFS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** to nowoczesny system plików zaprojektowany w celu zastąpienia Hierarchical File System Plus (HFS+). Jego rozwój był napędzany potrzebą **poprawy wydajności, bezpieczeństwa i efektywności**.

Niektóre z istotnych cech APFS to:

1. **Współdzielenie przestrzeni**: APFS pozwala wielu woluminom na **współdzielenie tej samej podstawowej wolnej przestrzeni** na jednym fizycznym urządzeniu. Umożliwia to bardziej efektywne wykorzystanie przestrzeni, ponieważ woluminy mogą dynamicznie rosnąć i kurczyć się bez potrzeby ręcznego zmieniania rozmiaru lub ponownego partycjonowania.
1. Oznacza to, w porównaniu do tradycyjnych partycji na dyskach plikowych, **że w APFS różne partycje (woluminy) dzielą całą przestrzeń dyskową**, podczas gdy zwykła partycja miała zazwyczaj stały rozmiar.
2. **Migawki**: APFS obsługuje **tworzenie migawek**, które są **tylko do odczytu**, punktowymi instancjami systemu plików. Migawki umożliwiają efektywne tworzenie kopii zapasowych i łatwe przywracanie systemu, ponieważ zajmują minimalną dodatkową przestrzeń i mogą być szybko tworzone lub przywracane.
3. **Klonowanie**: APFS może **tworzyć klony plików lub katalogów, które dzielą tę samą przestrzeń** z oryginałem, aż do momentu, gdy klon lub oryginalny plik zostanie zmodyfikowany. Ta funkcja zapewnia efektywny sposób tworzenia kopii plików lub katalogów bez duplikowania przestrzeni dyskowej.
4. **Szyfrowanie**: APFS **natywnie obsługuje szyfrowanie całego dysku** oraz szyfrowanie na poziomie pliku i katalogu, co zwiększa bezpieczeństwo danych w różnych zastosowaniach.
5. **Ochrona przed awarią**: APFS wykorzystuje **schemat metadanych copy-on-write, który zapewnia spójność systemu plików** nawet w przypadku nagłej utraty zasilania lub awarii systemu, co zmniejsza ryzyko uszkodzenia danych.

Ogólnie rzecz biorąc, APFS oferuje nowocześniejszy, elastyczniejszy i bardziej efektywny system plików dla urządzeń Apple, z naciskiem na poprawę wydajności, niezawodności i bezpieczeństwa.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Wolumin `Data` jest zamontowany w **`/System/Volumes/Data`** (możesz to sprawdzić za pomocą `diskutil apfs list`).

Lista firmlinków znajduje się w pliku **`/usr/share/firmlinks`**.
```bash
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
