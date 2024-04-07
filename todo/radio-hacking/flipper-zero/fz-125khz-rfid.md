# FZ - 125kHz RFID

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Wprowadzenie

Aby uzyskać więcej informacji na temat działania tagów 125kHz, sprawdź:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Działania

Aby uzyskać więcej informacji na temat tych rodzajów tagów, [**przeczytaj to wprowadzenie**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Odczyt

Próbuje **odczytać** informacje z karty. Następnie może je **emulować**.

{% hint style="warning" %}
Zauważ, że niektóre domofony próbują się chronić przed kopiowaniem kluczy, wysyłając polecenie zapisu przed odczytem. Jeśli zapis się powiedzie, ten tag jest uważany za fałszywy. Kiedy Flipper emuluje RFID, czytnik nie może go odróżnić od oryginalnego, więc takie problemy nie występują.
{% endhint %}

### Dodaj ręcznie

Możesz stworzyć **fałszywe karty w Flipper Zero, wskazując dane** ręcznie, a następnie je emulować.

#### ID na kartach

Czasami, gdy dostajesz kartę, znajdziesz ID (lub jego część) napisane na karcie.

* **EM Marin**

Na przykład w tej karcie EM-Marin na fizycznej karcie można **odczytać ostatnie 3 z 5 bajtów w czytelny sposób**.\
Pozostałe 2 można złamać siłowo, jeśli nie można ich odczytać z karty.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

* **HID**

To samo dzieje się w tej karcie HID, gdzie tylko 2 z 3 bajtów można znaleźć wydrukowane na karcie

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Emuluj/Zapisz

Po **skopiowaniu** karty lub **ręcznym wprowadzeniu** ID można ją **emulować** za pomocą Flipper Zero lub **zapisać** na rzeczywistej karcie.

## Odnośniki

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
