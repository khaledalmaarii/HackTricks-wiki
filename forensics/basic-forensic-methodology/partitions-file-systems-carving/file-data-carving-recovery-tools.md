<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju oglašenu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celokupnom tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Alati za izdvajanje i oporavak podataka

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Najčešći alat koji se koristi u forenzici za izdvajanje fajlova iz slika je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte ga i omogućite mu da obradi fajl kako bi pronašao "skrivene" fajlove. Imajte na umu da je Autopsy napravljen da podržava disk slike i druge vrste slika, ali ne i obične fajlove.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih fajlova kako bi pronašao ugrađeni sadržaj. Može se instalirati putem `apt`-a, a izvorni kod se nalazi na [GitHub-u](https://github.com/ReFirmLabs/binwalk).

**Korisne komande**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Još jedan čest alat za pronalaženje skrivenih datoteka je **foremost**. Konfiguracionu datoteku za foremost možete pronaći u `/etc/foremost.conf`. Ako želite samo da pretražujete određene datoteke, uklonite komentare sa njih. Ako ne uklonite komentare, foremost će pretraživati podrazumevane konfigurisane vrste datoteka.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Skalpel**

**Skalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **datoteka ugrađenih u datoteku**. U ovom slučaju, trebaće vam da uklonite komentare iz konfiguracione datoteke (_/etc/scalpel/scalpel.conf_) za vrste datoteka koje želite da izdvojite.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Ovaj alat dolazi unutar Kali operativnog sistema, ali ga možete pronaći i ovde: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Ovaj alat može skenirati sliku i **izvući pcaps** unutar nje, **informacije o mreži (URL-ovi, domeni, IP adrese, MAC adrese, e-pošte)** i još **datoteke**. Samo trebate:
```
bulk_extractor memory.img -o out_folder
```
Pregledajte **sve informacije** koje je alat prikupio (lozinke?), **analizirajte** pakete (pročitajte [**Pcaps analizu**](../pcap-inspection/)), tražite **čudne domene** (domene povezane sa **malverom** ili **ne-postojeće**).

## PhotoRec

Možete ga pronaći na [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Dolazi sa verzijama GUI i CLI. Možete odabrati **vrste datoteka** koje želite da PhotoRec pretražuje.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Proverite [kod](https://code.google.com/archive/p/binvis/) i [web stranicu alata](https://binvis.io/#/).

### Funkcionalnosti BinVis-a

* Vizuelni i aktivni **pregled strukture**
* Višestruki prikazi za različite fokusne tačke
* Fokusiranje na delove uzorka
* **Vidljive niske i resursi**, u PE ili ELF izvršnim datotekama, na primer
* Dobijanje **uzoraka** za kriptoanalizu datoteka
* **Prepoznavanje** pakera ili enkoder algoritama
* **Identifikacija** steganografije prema uzorcima
* **Vizuelno** binarno poređenje

BinVis je odlično **polazište za upoznavanje nepoznatog cilja** u scenariju crne kutije.

# Specifični alati za izvlačenje podataka

## FindAES

Pretražuje AES ključeve pretraživanjem njihovih rasporeda ključeva. Može pronaći ključeve od 128, 192 i 256 bita, kao što su oni koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

# Komplementarni alati

Možete koristiti [**viu**](https://github.com/atanunq/viu) da vidite slike sa terminala.\
Možete koristiti linux komandnu liniju alat **pdftotext** da pretvorite PDF u tekst i pročitate ga.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i sistemima u oblaku. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
