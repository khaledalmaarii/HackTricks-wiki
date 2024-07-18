# FZ - NFC

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

## Uvod <a href="#id-9wrzi" id="id-9wrzi"></a>

Za informacije o RFID i NFC proverite sledeću stranicu:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Podržane NFC kartice <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Osim NFC kartica, Flipper Zero podržava **drugi tip visokofrekventnih kartica** kao što su nekoliko **Mifare** Classic i Ultralight i **NTAG**.
{% endhint %}

Novi tipovi NFC kartica biće dodati na listu podržanih kartica. Flipper Zero podržava sledeće **NFC kartice tip A** (ISO 14443A):

* ﻿**Bankovne kartice (EMV)** — samo čitanje UID, SAK i ATQA bez čuvanja.
* ﻿**Nepoznate kartice** — čitanje (UID, SAK, ATQA) i emulacija UID.

Za **NFC kartice tip B, tip F i tip V**, Flipper Zero može da pročita UID bez čuvanja.

### NFC kartice tip A <a href="#uvusf" id="uvusf"></a>

#### Bankovna kartica (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero može samo da pročita UID, SAK, ATQA i sačuvane podatke na bankovnim karticama **bez čuvanja**.

Ekran za čitanje bankovnih karticaFlipper Zero može samo da pročita podatke **bez čuvanja i emulacije**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Nepoznate kartice <a href="#id-37eo8" id="id-37eo8"></a>

Kada Flipper Zero **nije u mogućnosti da odredi tip NFC kartice**, tada se može **pročitati i sačuvati** samo **UID, SAK i ATQA**.

Ekran za čitanje nepoznatih karticaZa nepoznate NFC kartice, Flipper Zero može emulirati samo UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartice tipa B, F i V <a href="#wyg51" id="wyg51"></a>

Za **NFC kartice tipa B, F i V**, Flipper Zero može samo **pročitati i prikazati UID** bez čuvanja.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Akcije

Za uvod o NFC [**pročitajte ovu stranicu**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Čitanje

Flipper Zero može **čitati NFC kartice**, međutim, **ne razume sve protokole** koji se zasnivaju na ISO 14443. Međutim, pošto je **UID niska nivo atribut**, možete se naći u situaciji kada je **UID već pročitan, ali je visoko nivo protokol za prenos podataka još uvek nepoznat**. Možete čitati, emulirati i ručno unositi UID koristeći Flipper za primitivne čitače koji koriste UID za autorizaciju.

#### Čitanje UID VS Čitanje podataka unutar <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

U Flipperu, čitanje 13.56 MHz oznaka može se podeliti na dva dela:

* **Nisko nivo čitanje** — čita samo UID, SAK i ATQA. Flipper pokušava da pogodi visoko nivo protokol na osnovu ovih podataka pročitanih sa kartice. Ne možete biti 100% sigurni u ovo, jer je to samo pretpostavka zasnovana na određenim faktorima.
* **Visoko nivo čitanje** — čita podatke iz memorije kartice koristeći specifičan visoko nivo protokol. To bi bilo čitanje podataka na Mifare Ultralight, čitanje sektora sa Mifare Classic, ili čitanje atributa kartice sa PayPass/Apple Pay.

### Čitaj Specifično

U slučaju da Flipper Zero nije u mogućnosti da pronađe tip kartice iz niskonivo podataka, u `Dodatnim Akcijama` možete odabrati `Pročitaj Specifičan Tip Kartice` i **ručno** **naznačiti tip kartice koju želite da pročitate**.

#### EMV Bankovne Kartice (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Osim jednostavnog čitanja UID-a, možete izvući mnogo više podataka sa bankovne kartice. Moguće je **dobiti puni broj kartice** (16 cifara na prednjoj strani kartice), **datum važenja**, i u nekim slučajevima čak i **ime vlasnika** zajedno sa listom **najnovijih transakcija**.\
Međutim, ne možete na ovaj način pročitati CVV (3 cifre na poleđini kartice). Takođe, **bankovne kartice su zaštićene od replay napada**, tako da kopiranje sa Flipperom i zatim pokušaj emulacije za plaćanje ne funkcioniše.

## Reference

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

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
