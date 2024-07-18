# Analiza plików PDF

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pdf-file-analysis), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pdf-file-analysis" %}

**Aby uzyskać więcej szczegółów, sprawdź:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Format PDF jest znany ze swojej złożoności i potencjału do ukrywania danych, co czyni go punktem centralnym dla wyzwań w zakresie forensyki CTF. Łączy elementy tekstowe z obiektami binarnymi, które mogą być skompresowane lub zaszyfrowane, i mogą zawierać skrypty w językach takich jak JavaScript lub Flash. Aby zrozumieć strukturę PDF, można odwołać się do [materiałów wprowadzających Didier'a Stevens'a](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), lub użyć narzędzi takich jak edytor tekstu lub edytor specyficzny dla PDF, taki jak Origami.

Do dogłębnego badania lub manipulacji plikami PDF dostępne są narzędzia takie jak [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Ukryte dane w plikach PDF mogą być ukryte w:

* Niewidocznych warstwach
* Formacie metadanych XMP od Adobe
* Inkrementalnych generacjach
* Tekście w tym samym kolorze co tło
* Tekście za obrazami lub nakładających się obrazach
* Niewyświetlanych komentarzach

Do niestandardowej analizy PDF można użyć bibliotek Pythona, takich jak [PeepDF](https://github.com/jesparza/peepdf), aby stworzyć własne skrypty do analizy. Ponadto potencjał PDF do przechowywania ukrytych danych jest tak ogromny, że zasoby takie jak przewodnik NSA dotyczący ryzyk i środków zaradczych związanych z PDF, chociaż już niehostowany w pierwotnej lokalizacji, nadal oferują cenne informacje. [Kopia przewodnika](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) oraz zbiór [sztuczek formatu PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autorstwa Ange Albertini mogą dostarczyć dalszej lektury na ten temat.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
