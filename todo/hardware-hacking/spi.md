# SPI

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

SPI (Serial Peripheral Interface) je sinhroni serijski komunikacioni protokol koji se koristi u ugrađenim sistemima za komunikaciju na kratkim rastojanjima između IC-ova (Integrisanih kola). SPI komunikacioni protokol koristi arhitekturu master-slave koju orkestrira Clock i Chip Select Signal. Arhitektura master-slave sastoji se od mastera (obično mikroprocesora) koji upravlja spoljnim perifernim uređajima poput EEPROM-a, senzora, kontrolnih uređaja, itd. koji se smatraju robovima.

Više robova može biti povezano sa masterom, ali robovi ne mogu komunicirati međusobno. Robovi se upravljaju sa dva pina, clock i chip select. Budući da je SPI sinhroni komunikacioni protokol, ulazni i izlazni pinovi prate signale sata. Chip select se koristi od strane mastera da odabere roba i da komunicira sa njim. Kada je chip select visok, uređaj roba nije izabran, dok je kada je nizak, čip je izabran i master će komunicirati sa robovima.

MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) su odgovorni za slanje i primanje podataka. Podaci se šalju uređaju roba putem pina MOSI dok je chip select nizak. Ulazni podaci sadrže instrukcije, memorijske adrese ili podatke prema listi podataka dobavljača uređaja roba. Nakon važećeg unosa, pin MISO je odgovoran za slanje podataka masteru. Izlazni podaci se šalju tačno na sledećem ciklusu sata nakon završetka unosa. Pin MISO prenosi podatke dok se podaci potpuno ne prenesu ili master postavi chip select pin na visok (u tom slučaju, roba će prestati sa prenosom i master neće slušati nakon tog ciklusa sata).

## Dumpovanje firmware-a sa EEPROM-a

Dumpovanje firmware-a može biti korisno za analizu firmware-a i pronalaženje ranjivosti u njima. Često se dešava da firmware nije dostupan na internetu ili je irelevantan zbog različitih faktora poput broja modela, verzije, itd. Stoga, ekstrahovanje firmware-a direktno sa fizičkog uređaja može biti korisno kako bi se bilo precizniji prilikom traženja pretnji.

Dobijanje serijske konzole može biti korisno, ali često se dešava da su datoteke samo za čitanje. To ograničava analizu iz različitih razloga. Na primer, alati koji su potrebni za slanje i primanje paketa neće biti dostupni u firmware-u. Stoga, ekstrahovanje binarnih fajlova radi njihovog reverznog inženjeringa nije izvodljivo. Stoga, imati ceo firmware dumpovan na sistemu i ekstrahovanje binarnih fajlova radi analize može biti veoma korisno.

Takođe, tokom crvenog tima i dobijanja fizičkog pristupa uređajima, dumpovanje firmware-a može pomoći u modifikovanju datoteka ili ubacivanju zlonamernih datoteka, a zatim ponovnom flasovanju u memoriju što bi moglo biti korisno za ugradnju tajnih vrata u uređaj. Stoga, postoji mnogo mogućnosti koje se mogu otključati dumpovanjem firmware-a.

### CH341A EEPROM Programer i Čitač

Ovaj uređaj je jeftin alat za dumpovanje firmware-a sa EEPROM-a i takođe ponovno flasovanje sa firmware fajlovima. Ovo je bio popularan izbor za rad sa BIOS čipovima računara (koji su samo EEPROM-ovi). Ovaj uređaj se povezuje preko USB-a i potrebni su minimalni alati za početak rada. Takođe, obično brzo obavlja posao, pa može biti koristan i prilikom fizičkog pristupa uređaju.

<img src="../../.gitbook/assets/board_image_ch341a.jpg" alt="crtež" width="400" align="center"/>

Povežite EEPROM memoriju sa CH341a Programerom i priključite uređaj u računar. U slučaju da uređaj nije detektovan, pokušajte instalirati drajvere na računar. Takođe, proverite da li je EEPROM povezan u pravilnoj orijentaciji (obično, postavite VCC Pin u obrnutu orijentaciju u odnosu na USB konektor) ili inače, softver neće moći da detektuje čip. Pogledajte dijagram ako je potrebno:

<img src="../../.gitbook/assets/connect_wires_ch341a.jpg" alt="crtež" width="350"/>

<img src="../../.gitbook/assets/eeprom_plugged_ch341a.jpg" alt="crtež" width="350"/>

Na kraju, koristite softvere poput flashrom, G-Flash (GUI), itd. za dumpovanje firmware-a. G-Flash je minimalni GUI alat koji je brz i automatski detektuje EEPROM. Ovo može biti korisno ako je firmware potrebno ekstrahovati brzo, bez mnogo eksperimentisanja sa dokumentacijom.

<img src="../../.gitbook/assets/connected_status_ch341a.jpg" alt="crtež" width="350"/>

Nakon dumpovanja firmware-a, analiza se može obaviti na binarnim fajlovima. Alati poput strings, hexdump, xxd, binwalk, itd. mogu se koristiti za ekstrahovanje mnogo informacija o firmware-u kao i celom fajl sistemu takođe.

Za ekstrahovanje sadržaja iz firmware-a, može se koristiti binwalk. Binwalk analizira heksadecimalne potpise i identifikuje fajlove u binarnom fajlu i sposoban je da ih ekstrahuje.
```
binwalk -e <filename>
```
<filename> može biti .bin ili .rom prema alatima i konfiguracijama korišćenim.

{% hint style="danger" %} Imajte na umu da je ekstrakcija firmware-a delikatan proces i zahteva puno strpljenja. Svaka nepravilna manipulacija može potencijalno oštetiti firmware ili čak ga potpuno izbrisati i učiniti uređaj neupotrebljivim. Preporučuje se proučavanje specifičnog uređaja pre nego što pokušate izvući firmware. {% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Imajte na umu da čak i ako PINOUT Pirate Bus-a pokazuje pinove za **MOSI** i **MISO** za povezivanje na SPI, neki SPI-ovi mogu pokazivati pinove kao DI i DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

Na Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) da biste dumpovali sadržaj flash memorije pokretanjem nečega poput:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
