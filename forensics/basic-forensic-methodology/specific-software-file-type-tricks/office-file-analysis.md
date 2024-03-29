# Analiza plików biurowych

<details>

<summary><strong>Zacznij od zera i stań się ekspertem AWS w dziedzinie hakerskiej dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** z wykorzystaniem najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Aby uzyskać dalsze informacje, sprawdź [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Oto tylko streszczenie:

Microsoft stworzył wiele formatów dokumentów biurowych, z dwoma głównymi typami: **formaty OLE** (takie jak RTF, DOC, XLS, PPT) i **formaty Office Open XML (OOXML)** (takie jak DOCX, XLSX, PPTX). Te formaty mogą zawierać makra, co czyni je celem phishingu i złośliwego oprogramowania. Pliki OOXML są strukturalnie jako kontenery zip, co pozwala na ich inspekcję poprzez rozpakowanie, ujawniając strukturę plików i folderów oraz zawartość plików XML.

Aby zbadać struktury plików OOXML, podano polecenie do rozpakowania dokumentu oraz strukturę wynikową. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na ciągłe innowacje w ukrywaniu danych w ramach wyzwań CTF.

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Te narzędzia pomagają w identyfikowaniu i analizowaniu osadzonych makr, które często służą jako wektory dostarczania złośliwego oprogramowania, zwykle pobierające i wykonujące dodatkowe złośliwe ładunki. Analizę makr VBA można przeprowadzić bez użycia pakietu Microsoft Office, korzystając z Libre Office, co pozwala na debugowanie za pomocą punktów przerwania i zmiennych obserwowanych.

Instalacja i użycie **oletools** są proste, a polecenia są dostarczone do instalacji za pomocą pip oraz do wyodrębniania makr z dokumentów. Automatyczne wykonanie makr jest wyzwalane przez funkcje takie jak `AutoOpen`, `AutoExec` lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez najbardziej zaawansowane narzędzia społecznościowe na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
