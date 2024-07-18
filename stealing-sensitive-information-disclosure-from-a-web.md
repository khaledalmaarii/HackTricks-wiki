# Krađa Otkrivanja Osetljivih Informacija sa Veba

{% hint style="success" %}
Učite i vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

Ako u nekom trenutku pronađete **veb stranicu koja vam prikazuje osetljive informacije na osnovu vaše sesije**: Možda reflektuje kolačiće, ili štampa CC detalje ili bilo koje druge osetljive informacije, možete pokušati da ih ukradete.\
Ovde vam predstavljam glavne načine kako to možete pokušati postići:

* [**CORS zaobilaženje**](pentesting-web/cors-bypass.md): Ako možete zaobići CORS zaglavlja, moći ćete ukrasti informacije izvršavajući Ajax zahtev ka zlonamernoj stranici.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): Ako pronađete XSS ranjivost na stranici, možda ćete moći da je zloupotrebite kako biste ukrali informacije.
* [**Dangling Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): Ako ne možete ubaciti XSS oznake, možda ćete i dalje moći ukrasti informacije koristeći druge redovne HTML oznake.
* [**Clickjaking**](pentesting-web/clickjacking.md): Ako nema zaštite protiv ovog napada, možda ćete moći da prevarite korisnika da vam pošalje osetljive podatke (primer [ovde](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Učite i vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
