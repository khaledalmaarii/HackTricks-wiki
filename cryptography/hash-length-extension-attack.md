<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>


# Podsumowanie ataku

Wyobraź sobie serwer, który **podpisuje** pewne **dane**, **dołączając** do nich **tajemnicę**, a następnie haszując te dane. Jeśli znasz:

* **Długość tajemnicy** (może być również przeprowadzony bruteforce z określonego zakresu długości)
* **Dane jasne**
* **Algorytm (i jest podatny na ten atak)**
* **Padding jest znany**
* Zazwyczaj używany jest domyślny, więc jeśli spełnione są pozostałe 3 wymagania, to również jest znany
* Padding różni się w zależności od długości tajemnicy+danych, dlatego potrzebna jest długość tajemnicy

W takim przypadku **atakujący** może **dołączyć** **dane** i **wygenerować** prawidłowy **podpis** dla **poprzednich danych + dołączonych danych**.

## Jak?

Podatne algorytmy generują hashe, najpierw **haszując blok danych**, a następnie, **z** wcześniej utworzonego **hasza** (stanu), **dodają następny blok danych** i **haszują go**.

Wyobraź sobie, że tajemnica to "tajemnica", a dane to "dane", MD5 z "tajemnicadanych" to 6036708eba0d11f6ef52ad44e8b74d5b.\
Jeśli atakujący chce dołączyć ciąg znaków "dołącz", może:

* Wygenerować MD5 z 64 "A"
* Zmienić stan wcześniej zainicjalizowanego hasza na 6036708eba0d11f6ef52ad44e8b74d5b
* Dołączyć ciąg znaków "dołącz"
* Zakończyć haszowanie, a wynikowy hasz będzie **prawidłowy dla "tajemnica" + "dane" + "padding" + "dołącz"**

## **Narzędzie**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referencje

Możesz znaleźć dobrze wyjaśniony ten atak na stronie [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
