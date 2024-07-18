# Krađa Osetljivih Informacija sa Veba

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

Ako u nekom trenutku pronađete **vеб stranicu koja vam prikazuje osetljive informacije na osnovu vaše sesije**: Možda odražava kolačiće, ili štampa ili CC detalje ili bilo koje druge osetljive informacije, možete pokušati da ih ukradete.\
Ovde vam predstavljam glavne načine na koje možete pokušati da to postignete:

* [**CORS zaobilaženje**](../pentesting-web/cors-bypass.md): Ako možete da zaobiđete CORS zaglavlja, moći ćete da ukradete informacije izvršavajući Ajax zahtev za zloćudnu stranicu.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Ako pronađete XSS ranjivost na stranici, možda ćete moći da je iskoristite da ukradete informacije.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Ako ne možete da injektujete XSS oznake, i dalje možete da ukradete informacije koristeći druge regularne HTML oznake.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Ako ne postoji zaštita protiv ovog napada, možda ćete moći da prevarite korisnika da vam pošalje osetljive podatke (primer [ovde](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)). 

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
