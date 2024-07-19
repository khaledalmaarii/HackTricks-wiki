# JTAG

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)je alat koji se može koristiti sa Raspberry PI ili Arduinom da pronađe JTAG pinove sa nepoznatog čipa.\
U **Arduinu**, povežite **pinove od 2 do 11 sa 10 pinova koji potencijalno pripadaju JTAG-u**. Učitajte program u Arduino i on će pokušati da bruteforce sve pinove da vidi da li neki pin pripada JTAG-u i koji je koji.\
U **Raspberry PI** možete koristiti samo **pinove od 1 do 6** (6 pinova, tako da ćete sporije testirati svaki potencijalni JTAG pin).

### Arduino

U Arduinu, nakon povezivanja kablova (pin 2 do 11 sa JTAG pinovima i Arduino GND sa GND matične ploče), **učitajte JTAGenum program u Arduino** i u Serial Monitor pošaljite **`h`** (komanda za pomoć) i trebali biste videti pomoć:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Konfigurišite **"No line ending" i 115200baud**.\
Pošaljite komandu s da započnete skeniranje:

![](<../../.gitbook/assets/image (774).png>)

Ako kontaktirate JTAG, pronaći ćete jedan ili više **redova koji počinju sa FOUND!** koji označavaju pinove JTAG-a.

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
