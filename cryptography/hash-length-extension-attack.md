<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFTów**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>


# Podsumowanie ataku

Wyobraź sobie serwer, który **podpisuje** pewne **dane**, **dodając** do nich **tajny klucz** i następnie haszując te dane. Jeśli znasz:

* **Długość tajnego klucza** (może być również złamana metodą bruteforce z zakresu długości)
* **Dane w postaci tekstu jawnego**
* **Algorytm (podatny na ten atak)**
* **Padding jest znany**
* Zazwyczaj używany jest domyślny, więc jeśli spełnione są pozostałe 3 wymagania, to również jest znany
* Padding różni się w zależności od długości tajnego klucza+danych, dlatego potrzebna jest długość tajnego klucza

W takim przypadku **atakujący** może **dodać** **dane** i **wygenerować** poprawny **podpis** dla **poprzednich danych + dodanych danych**.

## Jak?

W podatnych algorytmach haszowanie odbywa się poprzez najpierw **haszowanie bloku danych**, a następnie, **z** wcześniej **utworzonego hasha** (stanu), dodają **następny blok danych** i **haszują go**.

Wyobraź sobie, że tajny klucz to "tajne" a dane to "dane", MD5 z "tajnedane" to 6036708eba0d11f6ef52ad44e8b74d5b.\
Jeśli atakujący chce dodać ciąg "dodaj" może:

* Wygenerować MD5 z 64 "A"
* Zmienić stan wcześniej zainicjowanego hasha na 6036708eba0d11f6ef52ad44e8b74d5b
* Dodać ciąg "dodaj"
* Zakończyć haszowanie, a wynikowy hash będzie **poprawny dla "tajne" + "dane" + "padding" + "dodaj"**

## **Narzędzie**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referencje

Możesz znaleźć dobrze wyjaśniony ten atak na stronie [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFTów**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
