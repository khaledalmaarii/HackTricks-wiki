# iButton

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

## Intro

iButton je generički naziv za elektronski identifikacioni ključ smešten u **metalnu posudu u obliku novčića**. Takođe se naziva **Dallas Touch** memorija ili kontaktna memorija. Iako se često pogrešno naziva "magnetnim" ključem, u njemu **nema ničega magnetskog**. U stvari, unutra se nalazi potpuno funkcionalni **mikročip** koji radi na digitalnom protokolu.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### Šta je iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Obično, iButton podrazumeva fizički oblik ključa i čitača - okrugli novčić sa dva kontakta. Za okvir koji ga okružuje, postoji mnogo varijacija od najčešćeg plastičnog držača sa rupom do prstenova, privjesaka itd.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Kada ključ dođe do čitača, **kontakti se dodiruju** i ključ se napaja da **prenese** svoj ID. Ponekad ključ **nije odmah pročitan** jer je **kontakt PSD interkoma veći** nego što bi trebao biti. Tako spoljašnji konturi ključa i čitača nisu mogli da se dodirnu. Ako je to slučaj, moraćete da pritisnete ključ na jednu od zidova čitača.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas ključevi razmenjuju podatke koristeći 1-wire protokol. Sa samo jednim kontaktom za prenos podataka (!!) u oba pravca, od mastera do sluge i obrnuto. 1-wire protokol funkcioniše prema Master-Slave modelu. U ovoj topologiji, Master uvek inicira komunikaciju, a Slave prati njegove instrukcije.

Kada ključ (Slave) kontaktira interkom (Master), čip unutar ključa se uključuje, napajan od strane interkoma, i ključ se inicijalizuje. Nakon toga, interkom zahteva ID ključa. Sledeće, detaljnije ćemo pogledati ovaj proces.

Flipper može raditi i u Master i u Slave režimu. U režimu čitanja ključeva, Flipper deluje kao čitač, to jest, radi kao Master. A u režimu emulacije ključeva, flipper se pretvara da je ključ, u Slave režimu.

### Dallas, Cyfral & Metakom ključevi

Za informacije o tome kako ovi ključevi funkcionišu, pogledajte stranicu [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Napadi

iButtons se mogu napasti sa Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Reference

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
