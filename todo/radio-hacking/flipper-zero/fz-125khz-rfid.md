# FZ - 125kHz RFID

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Uvod

Za više informacija o tome kako 125kHz oznake funkcionišu, proverite:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Akcije

Za više informacija o ovim tipovima oznaka [**pročitajte ovaj uvod**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Čitanje

Pokušava da **pročita** informacije sa kartice. Zatim može da je **emulira**.

{% hint style="warning" %}
Imajte na umu da neki interkomi pokušavaju da se zaštite od dupliranja ključeva slanjem komande za pisanje pre čitanja. Ako pisanje uspe, ta oznaka se smatra lažnom. Kada Flipper emulira RFID, ne postoji način za čitač da je razlikuje od originalne, tako da takvi problemi ne nastaju.
{% endhint %}

### Dodaj Ručno

Možete kreirati **lažne kartice u Flipper Zero označavajući podatke** koje ručno unesete, a zatim ih emulirati.

#### ID-ovi na karticama

Ponekad, kada dobijete karticu, pronaći ćete ID (ili deo) napisano na kartici vidljivo.

* **EM Marin**

Na primer, na ovoj EM-Marin kartici na fizičkoj kartici je moguće **pročitati poslednja 3 od 5 bajtova u čistom obliku**.\
Ostala 2 se mogu probiti ako ih ne možete pročitati sa kartice.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Isto se dešava na ovoj HID kartici gde se samo 2 od 3 bajta mogu pronaći odštampana na kartici.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emuliraj/Piši

Nakon **kopiranja** kartice ili **unošenja** ID-a **ručno**, moguće je **emulirati** je sa Flipper Zero ili **pisati** je na pravoj kartici.

## Reference

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
