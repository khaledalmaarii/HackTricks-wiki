# FZ - NFC

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celokupnom tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Uvod <a href="#9wrzi" id="9wrzi"></a>

Za informacije o RFID i NFC proverite sledeću stranicu:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Podržane NFC kartice <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Osim NFC kartica, Flipper Zero podržava **druge vrste kartica visoke frekvencije** kao što su nekoliko **Mifare** Classic i Ultralight i **NTAG**.
{% endhint %}

Nove vrste NFC kartica će biti dodate na listu podržanih kartica. Flipper Zero podržava sledeće **NFC kartice tipa A** (ISO 14443A):

* ﻿**Bankovne kartice (EMV)** - samo čitanje UID-a, SAK-a i ATQA bez čuvanja.
* ﻿**Nepoznate kartice** - čitanje (UID, SAK, ATQA) i emulacija UID-a.

Za **NFC kartice tipa B, tipa F i tipa V**, Flipper Zero može čitati UID bez čuvanja.

### NFC kartice tipa A <a href="#uvusf" id="uvusf"></a>

#### Bankovna kartica (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero može samo čitati UID, SAK, ATQA i sačuvane podatke na bankovnim karticama **bez čuvanja**.

Ekran za čitanje bankovne karticeZa bankovne kartice, Flipper Zero može samo čitati podatke **bez čuvanja i emuliranja**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Nepoznate kartice <a href="#37eo8" id="37eo8"></a>

Kada Flipper Zero **nije u mogućnosti da odredi tip NFC kartice**, tada se može **čitati i sačuvati samo UID, SAK i ATQA**.

Ekran za čitanje nepoznate karticeZa nepoznate NFC kartice, Flipper Zero može samo emulirati UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartice tipova B, F i V <a href="#wyg51" id="wyg51"></a>

Za **NFC kartice tipova B, F i V**, Flipper Zero može samo **čitati i prikazivati UID** bez čuvanja.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Akcije

Za uvod o NFC-u [**pročitajte ovu stranicu**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Čitanje

Flipper Zero može **čitati NFC kartice**, međutim, **ne razume sve protokole** koji se baziraju na ISO 14443. Međutim, pošto je **UID niska atributa**, možete se naći u situaciji kada je **UID već pročitan, ali visokonivo protokol prenosa podataka je još uvek nepoznat**. Možete čitati, emulirati i ručno uneti UID koristeći Flipper za primitivne čitače koji koriste UID za autorizaciju.

#### Čitanje UID-a VS Čitanje Podataka Unutra <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

U Flipperu, čitanje oznaka na 13.56 MHz se može podeliti na dva dela:

* **Čitanje na niskom nivou** - čita samo UID, SAK i ATQA. Flipper pokušava da pretpostavi visokonivo protokol na osnovu ovih podataka pročitanih sa kartice. Ne možete biti 100% sigurni u to, jer je to samo pretpostavka zasnovana na određenim faktorima.
* **Čitanje na visokom nivou** - čita podatke iz memorije kartice koristeći određeni visokonivo protokol. To bi bilo čitanje podataka na Mifare Ultralight, čitanje sektora sa Mifare Classic ili čitanje atributa kartice iz PayPass/Apple Pay.

### Čitanje Specifično

U slučaju da Flipper Zero nije sposoban da pronađe tip kartice na osnovu podataka na niskom nivou, u `Extra Actions` možete odabrati `Read Specific Card Type` i **ručno** **naznačiti tip kartice koji želite da pročitate**.
#### EMV Bankarske Kartice (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Osim što možete jednostavno pročitati UID, možete izvući mnogo više podataka sa bankarske kartice. Moguće je **dobiti pun broj kartice** (16 cifara na prednjoj strani kartice), **datum važenja**, a u nekim slučajevima čak i **ime vlasnika** zajedno sa listom **najnovijih transakcija**.\
Međutim, **ne možete pročitati CVV na ovaj način** (3 cifre na poleđini kartice). Takođe, **bankarske kartice su zaštićene od replay napada**, pa kopiranje kartice pomoću Flippera i pokušaj emulacije za plaćanje neće uspeti.

## Reference

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li videti **vašu kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
