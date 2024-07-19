# FZ - 125kHz RFID

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Wprowadzenie

Aby uzyskać więcej informacji na temat działania tagów 125kHz, sprawdź:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Akcje

Aby uzyskać więcej informacji na temat tych typów tagów [**przeczytaj to wprowadzenie**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Odczyt

Próbuje **odczytać** informacje z karty. Następnie może ją **emulować**.

{% hint style="warning" %}
Zauważ, że niektóre domofony próbują chronić się przed duplikowaniem kluczy, wysyłając polecenie zapisu przed odczytem. Jeśli zapis się powiedzie, ten tag jest uważany za fałszywy. Gdy Flipper emuluje RFID, nie ma sposobu, aby czytnik odróżnił go od oryginału, więc takie problemy nie występują.
{% endhint %}

### Dodaj ręcznie

Możesz stworzyć **fałszywe karty w Flipper Zero, wskazując dane** ręcznie, a następnie je emulować.

#### ID na kartach

Czasami, gdy otrzymasz kartę, znajdziesz ID (lub jego część) napisane na widocznej stronie karty.

* **EM Marin**

Na przykład w tej karcie EM-Marin na fizycznej karcie można **odczytać ostatnie 3 z 5 bajtów w postaci jawnej**.\
Pozostałe 2 można odgadnąć, jeśli nie możesz ich odczytać z karty.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

To samo dzieje się w tej karcie HID, gdzie tylko 2 z 3 bajtów można znaleźć wydrukowane na karcie.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuluj/Zapisz

Po **skopiowaniu** karty lub **ręcznym wprowadzeniu** ID, można ją **emulować** za pomocą Flipper Zero lub **zapisać** na prawdziwej karcie.

## Odniesienia

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
