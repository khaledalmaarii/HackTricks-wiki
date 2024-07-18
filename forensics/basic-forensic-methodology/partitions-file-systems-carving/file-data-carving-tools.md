{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


# Alati za izdvajanje podataka

## Autopsija

Najčešći alat koji se koristi u forenzici za izdvajanje fajlova iz slika je [**Autopsija**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte ga i podesite da obradi fajl kako bi pronašao "skrivene" fajlove. Imajte na umu da je Autopsija napravljena da podržava disk slike i druge vrste slika, ali ne i obične fajlove.

## Binwalk <a id="binwalk"></a>

**Binwalk** je alat za pretragu binarnih fajlova poput slika i audio fajlova za ugrađene fajlove i podatke.
Može se instalirati pomoću `apt` međutim [izvor](https://github.com/ReFirmLabs/binwalk) se može pronaći na github-u.
**Korisne komande**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Još jedan čest alat za pronalaženje skrivenih datoteka je **foremost**. Konfiguracionu datoteku za foremost možete pronaći u `/etc/foremost.conf`. Ako želite da pretražujete samo određene datoteke, uklonite komentare ispred njih. Ako ne uklonite komentare, foremost će pretraživati prema svojim podrazumevanim konfigurisanim tipovima datoteka.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Skalpel**

**Skalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **datoteka ugrađenih u datoteku**. U ovom slučaju, moraćete da uklonite komentare iz konfiguracione datoteke \(_/etc/scalpel/scalpel.conf_\) za vrste datoteka koje želite da izdvojite.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Ovaj alat dolazi unutar kali distribucije, ali ga možete pronaći ovde: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Ovaj alat može skenirati sliku i **izdvojiti pcaps** unutar nje, **mrežne informacije \(URL-ove, domene, IP adrese, MAC adrese, mejlove\)** i više **datoteka**. Samo treba da uradite:
```text
bulk_extractor memory.img -o out_folder
```
Prođite kroz **sve informacije** koje je alat prikupio \(lozinke?\), **analizirajte** **pakete** \(pročitajte [**Analiza Pcap datoteka**](../pcap-inspection/)\), tražite **čudne domene** \(domene povezane sa **malverom** ili **ne-postojeće**\).

## PhotoRec

Možete ga pronaći na [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dolazi sa GUI i CLI verzijom. Možete odabrati **tipove datoteka** koje želite da PhotoRec pretražuje.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Specifični alati za izdvajanje podataka

## FindAES

Pretražuje AES ključeve tražeći njihove rasporede ključeva. Može pronaći 128, 192 i 256 bitne ključeve, poput onih koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

# Komplementarni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu) da vidite slike iz terminala.
Možete koristiti linux komandnu liniju alat **pdftotext** da pretvorite pdf u tekst i pročitate ga.



{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
