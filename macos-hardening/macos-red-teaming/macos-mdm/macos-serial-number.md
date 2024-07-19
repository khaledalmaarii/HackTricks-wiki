# macOS Numer seryjny

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

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
{% endhint %}


## Podstawowe informacje

Urządzenia Apple po 2010 roku mają numery seryjne składające się z **12 znaków alfanumerycznych**, z których każdy segment przekazuje konkretne informacje:

- **Pierwsze 3 znaki**: Wskazują na **miejsce produkcji**.
- **Znaki 4 i 5**: Oznaczają **rok i tydzień produkcji**.
- **Znaki 6 do 8**: Służą jako **unikalny identyfikator** dla każdego urządzenia.
- **Ostatnie 4 znaki**: Określają **numer modelu**.

Na przykład, numer seryjny **C02L13ECF8J2** podąża za tą strukturą.

### **Miejsca produkcji (pierwsze 3 znaki)**
Niektóre kody reprezentują konkretne fabryki:
- **FC, F, XA/XB/QP/G8**: Różne lokalizacje w USA.
- **RN**: Meksyk.
- **CK**: Cork, Irlandia.
- **VM**: Foxconn, Czechy.
- **SG/E**: Singapur.
- **MB**: Malezja.
- **PT/CY**: Korea.
- **EE/QT/UV**: Tajwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Różne lokalizacje w Chinach.
- **C0, C3, C7**: Konkretne miasta w Chinach.
- **RM**: Odnowione urządzenia.

### **Rok produkcji (4. znak)**
Ten znak zmienia się od 'C' (reprezentujący pierwszą połowę 2010 roku) do 'Z' (drugą połowę 2019 roku), przy czym różne litery oznaczają różne półroczne okresy.

### **Tydzień produkcji (5. znak)**
Cyfry 1-9 odpowiadają tygodniom 1-9. Litery C-Y (z wyjątkiem samogłosk i 'S') reprezentują tygodnie 10-27. Dla drugiej połowy roku dodaje się 26 do tej liczby.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

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
{% endhint %}
</details>
{% endhint %}sztukami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

{% endhint %}
</details>
{% endhint %}
