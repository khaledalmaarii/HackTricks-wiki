# iButton

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Uvod

iButton je generički naziv za elektronski identifikacioni ključ upakovan u **kovitlani metalni kontejner**. Takođe se naziva **Dallas Touch** Memory ili kontakt memorija. Iako se često pogrešno naziva "magnetnim" ključem, u njemu **nema ničeg magnetnog**. Zapravo, unutra je skriven potpuno razvijen **mikročip** koji radi na digitalnom protokolu.

<figure><img src="../../.gitbook/assets/image (912).png" alt=""><figcaption></figcaption></figure>

### Šta je iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Obično, iButton podrazumeva fizički oblik ključa i čitača - okrugli novčić sa dva kontakta. Za okvir koji ga okružuje, postoji mnogo varijacija od najčešćeg plastičnog držača sa rupom do prstenova, privezaka, itd.

<figure><img src="../../.gitbook/assets/image (1075).png" alt=""><figcaption></figcaption></figure>

Kada ključ dođe do čitača, **kontakti se dodirnu** i ključ se napaja da **prebaci** svoj ID. Ponekad ključ **nije odmah pročitan** jer je **kontakt PSD interfona veći** nego što bi trebalo da bude. U tom slučaju, moraćete pritisnuti ključ preko jednog od zidova čitača.

<figure><img src="../../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas ključevi razmenjuju podatke koristeći 1-wire protokol. Sa samo jednim kontaktom za prenos podataka (!!) u oba smera, od mastera ka robovima i obrnuto. 1-wire protokol funkcioniše prema modelu Master-Rob. U ovoj topologiji, Master uvek inicira komunikaciju, a Rob sprovodi njegove instrukcije.

Kada ključ (Rob) kontaktira interfonski uređaj (Master), čip unutar ključa se uključuje, napajan od strane interfona, i ključ se inicijalizuje. Nakon toga, interfon zahteva ID ključa. Zatim ćemo detaljnije pogledati ovaj proces.

Flipper može raditi i u Master i u Slave režimu. U režimu čitanja ključa, Flipper deluje kao čitač, odnosno radi kao Master. A u režimu emulacije ključa, Flipper se pretvara da je ključ, tj. u režimu je Rob.

### Dallas, Cyfral & Metakom ključevi

Za informacije o tome kako ovi ključevi funkcionišu, pogledajte stranicu [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Napadi

iButton-ima se može napasti pomoću Flipper Zero uređaja:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Reference

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
