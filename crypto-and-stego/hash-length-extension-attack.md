# Atak rozszerzenia długości hasha

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark-web**, która oferuje **darmowe** funkcjonalności do sprawdzenia, czy firma lub jej klienci zostali **skompromentowani** przez **złośliwe oprogramowanie kradnące**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

***

## Podsumowanie ataku

Wyobraź sobie serwer, który **podpisuje** jakieś **dane**, **dodając** **sekret** do znanych danych w postaci tekstu jawnego, a następnie haszując te dane. Jeśli znasz:

* **Długość sekretu** (można to również wypróbować z danego zakresu długości)
* **Dane w postaci tekstu jawnego**
* **Algorytm (i jest podatny na ten atak)**
* **Padding jest znany**
* Zwykle używany jest domyślny, więc jeśli pozostałe 3 wymagania są spełnione, to również jest
* Padding różni się w zależności od długości sekretu + danych, dlatego długość sekretu jest potrzebna

Wtedy możliwe jest, aby **atakujący** **dodał** **dane** i **wygenerował** ważny **podpis** dla **poprzednich danych + dodanych danych**.

### Jak?

Zasadniczo podatne algorytmy generują hashe, najpierw **haszując blok danych**, a następnie, **z** **wcześniej** utworzonego **hasha** (stanu), **dodają następny blok danych** i **haszują go**.

Wyobraź sobie, że sekret to "secret", a dane to "data", MD5 "secretdata" to 6036708eba0d11f6ef52ad44e8b74d5b.\
Jeśli atakujący chce dodać ciąg "append", może:

* Wygenerować MD5 z 64 "A"
* Zmienić stan wcześniej zainicjowanego hasha na 6036708eba0d11f6ef52ad44e8b74d5b
* Dodać ciąg "append"
* Zakończyć haszowanie, a wynikowy hash będzie **ważny dla "secret" + "data" + "padding" + "append"**

### **Narzędzie**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Odniesienia

Możesz znaleźć ten atak dobrze wyjaśniony w [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark-web**, która oferuje **darmowe** funkcjonalności do sprawdzenia, czy firma lub jej klienci zostali **skompromentowani** przez **złośliwe oprogramowanie kradnące**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
