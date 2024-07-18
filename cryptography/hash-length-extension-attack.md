{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcji**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}


# Podsumowanie ataku

Wyobraź sobie serwer, który **podpisuje** pewne **dane**, **dodając** do nich **tajny klucz** i następnie haszując te dane. Jeśli znasz:

* **Długość tajnego klucza** (można to również przeprowadzić metodą brutalnej siły w określonym zakresie długości)
* **Dane w postaci tekstu jawnego**
* **Algorytm (podatny na ten atak)**
* **Padding jest znany**
* Zazwyczaj używany jest domyślny, więc jeśli spełnione są pozostałe 3 wymagania, to również jest znany
* Padding różni się w zależności od długości tajnego klucza+danych, dlatego potrzebna jest długość tajnego klucza

W takim przypadku **atakujący** może **dodać** **dane** i **wygenerować** poprawny **podpis** dla **poprzednich danych + dodanych danych**.

## Jak to działa?

W podatnych algorytmach haszowanie odbywa się poprzez **najpierw zahaszowanie bloku danych**, a następnie, **z** **wcześniej** utworzonego **hasza** (stanu), **dodanie następnego bloku danych** i **ponowne zahaszowanie**.

Wyobraź sobie, że tajny klucz to "tajny" a dane to "dane", MD5 z "tajnydane" to 6036708eba0d11f6ef52ad44e8b74d5b.\
Jeśli atakujący chce dodać ciąg znaków "dodaj" może:

* Wygenerować MD5 z 64 "A"
* Zmienić stan wcześniej zainicjowanego hasha na 6036708eba0d11f6ef52ad44e8b74d5b
* Dodać ciąg znaków "dodaj"
* Zakończyć haszowanie, a wynikowy hash będzie **poprawny dla "tajny" + "dane" + "padding" + "dodaj"**

## **Narzędzie**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referencje

Możesz znaleźć dobrze wyjaśniony ten atak na stronie [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcji**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
