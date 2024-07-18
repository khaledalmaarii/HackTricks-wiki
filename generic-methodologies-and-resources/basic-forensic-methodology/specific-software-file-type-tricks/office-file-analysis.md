# Analiza plików Office

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Aby uzyskać więcej informacji, sprawdź [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To tylko podsumowanie:

Microsoft stworzył wiele formatów dokumentów biurowych, z dwoma głównymi typami będącymi **formatami OLE** (takimi jak RTF, DOC, XLS, PPT) oraz **formatami Office Open XML (OOXML)** (takimi jak DOCX, XLSX, PPTX). Te formaty mogą zawierać makra, co czyni je celem dla phishingu i złośliwego oprogramowania. Pliki OOXML są strukturalnie zorganizowane jako kontenery zip, co umożliwia inspekcję poprzez rozpakowanie, ujawniając hierarchię plików i folderów oraz zawartość plików XML.

Aby zbadać struktury plików OOXML, podano polecenie do rozpakowania dokumentu oraz strukturę wyjściową. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na ciągłą innowację w ukrywaniu danych w ramach wyzwań CTF.

Do analizy, **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają w identyfikacji i analizie osadzonych makr, które często służą jako wektory dostarczania złośliwego oprogramowania, zazwyczaj pobierając i uruchamiając dodatkowe złośliwe ładunki. Analizę makr VBA można przeprowadzić bez Microsoft Office, wykorzystując Libre Office, które umożliwia debugowanie z punktami przerwania i zmiennymi obserwacyjnymi.

Instalacja i użycie **oletools** są proste, z podanymi poleceniami do instalacji za pomocą pip i ekstrakcji makr z dokumentów. Automatyczne uruchamianie makr jest wyzwalane przez funkcje takie jak `AutoOpen`, `AutoExec` lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
