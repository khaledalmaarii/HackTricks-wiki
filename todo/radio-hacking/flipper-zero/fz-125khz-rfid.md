# FZ - 125kHz RFID

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wprowadzenie

Aby uzyskać więcej informacji na temat działania tagów 125kHz, sprawdź:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Działania

Aby uzyskać więcej informacji na temat tych typów tagów, [**przeczytaj to wprowadzenie**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Odczyt

Próbuje **odczytać** informacje z karty. Następnie może je **emulować**.

{% hint style="warning" %}
Należy zauważyć, że niektóre domofony próbują się chronić przed kopiowaniem kluczy, wysyłając polecenie zapisu przed odczytem. Jeśli zapis się powiedzie, oznacza to, że dany tag jest fałszywy. Kiedy Flipper emuluje RFID, czytnik nie może go odróżnić od oryginalnego, więc takie problemy nie występują.
{% endhint %}

### Dodaj ręcznie

Możesz utworzyć **fałszywe karty w Flipper Zero, podając ręcznie dane**, a następnie je emulować.

#### ID na kartach

Czasami, gdy otrzymasz kartę, znajdziesz ID (lub jego część) zapisane na karcie.

* **EM Marin**

Na przykład na tej karcie EM-Marin na fizycznej karcie można **odczytać ostatnie 3 z 5 bajtów w postaci jawnej**.\
Pozostałe 2 można złamać metodą brute-force, jeśli nie można ich odczytać z karty.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

To samo dzieje się na tej karcie HID, gdzie tylko 2 z 3 bajtów można znaleźć wydrukowane na karcie.

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Emuluj/Zapisz

Po **skopiowaniu** karty lub **ręcznym wprowadzeniu** ID można go **emulować** za pomocą Flipper Zero lub **zapisać** na prawdziwej karcie.

## Odwołania

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
