# FZ - Sub-GHz

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje pretnji, pronalazi probleme u celom vašem tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Uvod <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero može **primati i prenositi radio frekvencije u opsegu od 300-928 MHz** sa svojim ugrađenim modulom, koji može čitati, čuvati i emulirati daljinske upravljače. Ovi upravljači se koriste za interakciju sa kapijama, rampama, radio bravama, prekidačima daljinskog upravljanja, bežičnim zvoncima za vrata, pametnim svetlima i još mnogo toga. Flipper Zero vam može pomoći da saznate da li je vaša bezbednost ugrožena.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardver <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ima ugrađeni sub-1 GHz modul zasnovan na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 čipu](https://www.ti.com/lit/ds/symlink/cc1101.pdf) i radio anteni (maksimalni domet je 50 metara). I CC1101 čip i antena su dizajnirani da rade na frekvencijama u opsezima 300-348 MHz, 387-464 MHz i 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Akcije

### Analizator frekvencija

{% hint style="info" %}
Kako pronaći koju frekvenciju koristi daljinski upravljač
{% endhint %}

Prilikom analize, Flipper Zero skenira jačinu signala (RSSI) na svim dostupnim frekvencijama u konfiguraciji frekvencija. Flipper Zero prikazuje frekvenciju sa najvišom vrednošću RSSI, sa jačinom signala većom od -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Da biste odredili frekvenciju daljinskog upravljača, uradite sledeće:

1. Postavite daljinski upravljač vrlo blizu leve strane Flipper Zero-a.
2. Idite na **Glavni meni** **→ Sub-GHz**.
3. Izaberite **Analizator frekvencija**, zatim pritisnite i držite dugme na daljinskom upravljaču koji želite analizirati.
4. Pregledajte vrednost frekvencije na ekranu.

### Čitanje

{% hint style="info" %}
Pronađite informacije o korišćenoj frekvenciji (takođe još jedan način za pronalaženje korištene frekvencije)
{% endhint %}

Opcija **Čitanje** **sluša na konfigurisanoj frekvenciji** na naznačenoj modulaciji: 433.92 AM prema podrazumevanim podešavanjima. Ako se **nešto pronađe** prilikom čitanja, **informacije se prikazuju** na ekranu. Ove informacije mogu se koristiti za replikaciju signala u budućnosti.

Dok se koristi opcija Čitanje, moguće je pritisnuti **levi taster** i **konfigurisati je**.\
Trenutno ima **4 modulacije** (AM270, AM650, FM328 i FM476), i **nekoliko relevantnih frekvencija** je sačuvano:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Možete postaviti **bilo koju koja vas zanima**, međutim, ako niste **sigurni koja frekvencija** može biti ona koju koristi daljinski upravljač koji imate, **postavite Hopping na ON** (podrazumevano je isključeno) i pritisnite dugme nekoliko puta dok Flipper ne uhvati signal i pruži vam informacije koje su vam potrebne za podešavanje frekvencije.

{% hint style="danger" %}
Prebacivanje između frekvencija traje neko vreme, stoga signali koji se prenose u trenutku prebacivanja mogu biti propušteni. Za bolji prijem signala, postavite fiksnu frekvenciju određenu Analizatorom frekvencija.
{% endhint %}

### **Čitanje sirovih podataka**

{% hint style="info" %}
Ukradite (i reprodukujte) signal na konfigurisanoj frekvenciji
{% endhint %}

Opcija **Čitanje sirovih podataka** **snima signale** poslate na frekvenciji na kojoj se sluša. Ovo se može koristiti za **ukradanje** signala i **ponovno slanje**.

Podrazumevano, **Čitanje sirovih podataka je takođe na 433.92 u AM650**, ali ako ste sa opcijom Čitanje pronašli da vas zanima signal na **drugoj frekvenciji/modulaciji, takođe je možete promeniti** pritiskom na levo dugme (dok ste unutar opcije Čitanje sirovih podataka).

### Brute-Force

Ako znate protokol koji se koristi, na primer za garažna vrata, moguće je **generisati sve kodove i poslati ih sa Flipper Zero-om**. Ovo je primer koji podržava opšte uobičajene vrste garaža: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Ručno dodavanje

{% hint style="info" %}
Dodajte signale iz konfigurisane liste protokola
{% endhint %}

#### Lista [podržanih protokola](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (radi sa većinom statičkih kodnih sistema) | 433.92 | Statički |
| ------------------------------------------------------- | ------ | -------- |
| Nice Flo 12bit\_433
### Podržani prodavci Sub-GHz

Proverite listu na [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Podržane frekvencije po regionima

Proverite listu na [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Dobijte dBm vrednosti sačuvanih frekvencija
{% endhint %}

## Reference

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
