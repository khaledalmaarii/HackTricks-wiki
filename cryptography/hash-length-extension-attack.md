{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


# Rezime napada

Zamislite server koji **potpisuje** neke **podatke** tako što dodaje **tajnu vrednost** na neke poznate čiste tekstualne podatke, a zatim hešira te podatke. Ako znate:

* **Dužinu tajne** (ovo takođe može biti probijeno iz datog opsega dužine)
* **Čiste tekstualne podatke**
* **Algoritam (i ranjiv je na ovaj napad)**
* **Padding je poznat**
* Obično se koristi podrazumevani, pa ako su ispunjeni i drugi 3 zahteva, i ovaj je
* Padding varira u zavisnosti od dužine tajne+podataka, zbog čega je potrebna dužina tajne

Onda je moguće da **napadač** doda **podatke** i **generiše** validan **potpis** za **prethodne podatke + dodate podatke**.

## Kako?

Osnovno, ranjivi algoritmi generišu hešove tako što prvo **heširaju blok podataka**, a zatim, **iz** prethodno **kreiranog heša** (stanja), dodaju **sledeći blok podataka** i **heširaju ga**.

Zamislite da je tajna "tajna" i podaci su "podaci", MD5 od "tajnapodaci" je 6036708eba0d11f6ef52ad44e8b74d5b.\
Ako napadač želi da doda string "dodatak" može:

* Generisati MD5 od 64 "A"
* Promeniti stanje prethodno inicijalizovanog heša u 6036708eba0d11f6ef52ad44e8b74d5b
* Dodati string "dodatak"
* Završiti heš i rezultujući heš će biti **validan za "tajna" + "podaci" + "padding" + "dodatak"**

## **Alat**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Reference

Ovaj napad možete pronaći dobro objašnjen na [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
