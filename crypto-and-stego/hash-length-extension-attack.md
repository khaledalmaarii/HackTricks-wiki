# Hash Length Extension Attack

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Podsumowanie ataku

Wyobraź sobie serwer, który **podpisuje** jakieś **dane**, **dodając** **sekret** do znanych danych tekstowych i następnie haszując te dane. Jeśli wiesz:

* **Długość sekretu** (można to również wywnioskować z podanego zakresu długości)
* **Dane tekstowe**
* **Algorytm (i jest podatny na ten atak)**
* **Padding jest znany**
* Zwykle używany jest domyślny, więc jeśli spełnione są pozostałe 3 wymagania, to również jest
* Padding różni się w zależności od długości sekretu + danych, dlatego długość sekretu jest potrzebna

Wtedy możliwe jest, aby **atakujący** **dodał** **dane** i **wygenerował** ważny **podpis** dla **poprzednich danych + dodanych danych**.

### Jak?

Zasadniczo podatne algorytmy generują hashe, najpierw **haszując blok danych**, a następnie, **z** **wcześniej** utworzonego **hasha** (stanu), **dodają następny blok danych** i **haszują go**.

Wyobraź sobie, że sekret to "secret", a dane to "data", MD5 "secretdata" to 6036708eba0d11f6ef52ad44e8b74d5b.\
Jeśli atakujący chce dodać ciąg "append", może:

* Wygenerować MD5 64 "A"
* Zmienić stan wcześniej zainicjowanego hasha na 6036708eba0d11f6ef52ad44e8b74d5b
* Dodać ciąg "append"
* Zakończyć haszowanie, a wynikowy hash będzie **ważny dla "secret" + "data" + "padding" + "append"**

### **Narzędzie**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Referencje

Możesz znaleźć ten atak dobrze wyjaśniony w [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
