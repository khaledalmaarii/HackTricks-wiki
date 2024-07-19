# SPI

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

## Basic Information

SPI (Serijski periferni interfejs) je sinhroni serijski komunikacioni protokol koji se koristi u ugrađenim sistemima za kratkodistancu komunikaciju između IC-ova (integrisanih kola). SPI komunikacioni protokol koristi arhitekturu master-slave koja se orkestrira putem signala sata i odabira čipa. Arhitektura master-slave se sastoji od mastera (obično mikroprocesora) koji upravlja spoljnim perifernim uređajima kao što su EEPROM, senzori, kontrolni uređaji itd. koji se smatraju robovima.

Više robova može biti povezano sa masterom, ali robovi ne mogu međusobno komunicirati. Robovi se upravljaju putem dva pina, sata i odabira čipa. Pošto je SPI sinhroni komunikacioni protokol, ulazni i izlazni pinovi prate signale sata. Odabir čipa koristi master da izabere robota i interaguje s njim. Kada je odabir čipa visok, uređaj rob nije izabran, dok kada je nizak, čip je izabran i master bi interagovao sa robom.

MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) su odgovorni za slanje i primanje podataka. Podaci se šalju robu putem MOSI pina dok je odabir čipa nizak. Ulazni podaci sadrže instrukcije, adrese memorije ili podatke prema tehničkoj dokumentaciji dobavljača uređaja rob. Nakon validnog ulaza, MISO pin je odgovoran za prenos podataka masteru. Izlazni podaci se šalju tačno u sledećem ciklusu sata nakon što ulaz završi. MISO pin prenosi podatke dok se podaci potpuno ne prenesu ili dok master ne postavi pin odabira čipa na visok (u tom slučaju, rob bi prestao sa prenosom i master ne bi slušao nakon tog ciklusa sata).

## Dumping Firmware from EEPROMs

Dumping firmware može biti koristan za analizu firmware-a i pronalaženje ranjivosti u njima. Često, firmware nije dostupan na internetu ili je nebitan zbog varijacija faktora kao što su broj modela, verzija itd. Stoga, ekstrakcija firmware-a direktno sa fizičkog uređaja može biti korisna da bi se bili specifični prilikom lova na pretnje.

Dobijanje serijske konzole može biti korisno, ali često se dešava da su datoteke samo za čitanje. To ograničava analizu iz raznih razloga. Na primer, alati koji su potrebni za slanje i primanje paketa ne bi bili prisutni u firmware-u. Dakle, ekstrakcija binarnih datoteka za obrnuto inženjerstvo nije izvodljiva. Stoga, imati ceo firmware dumpovan na sistemu i ekstraktovati binarne datoteke za analizu može biti veoma korisno.

Takođe, tokom red teaming-a i dobijanja fizičkog pristupa uređajima, dumping firmware-a može pomoći u modifikaciji datoteka ili injektovanju zlonamernih datoteka, a zatim ponovnom flešovanju u memoriju što može biti korisno za implantaciju backdoora u uređaj. Stoga, postoji mnogo mogućnosti koje se mogu otključati dumpingom firmware-a.

### CH341A EEPROM Programmer and Reader

Ovaj uređaj je jeftin alat za dumping firmware-a iz EEPROM-a i takođe ponovo flešovanje sa firmware datotekama. Ovo je popularan izbor za rad sa BIOS čipovima računara (koji su samo EEPROM-i). Ovaj uređaj se povezuje putem USB-a i zahteva minimalne alate za početak. Takođe, obično brzo obavlja zadatak, tako da može biti koristan i za fizički pristup uređaju.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Povežite EEPROM memoriju sa CH341a programatorom i priključite uređaj na računar. U slučaju da uređaj nije prepoznat, pokušajte da instalirate drajvere na računar. Takođe, uverite se da je EEPROM povezan u pravom položaju (obično, postavite VCC pin u obrnutom položaju u odnosu na USB konektor) inače, softver neće moći da prepozna čip. Pogledajte dijagram ako je potrebno:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Na kraju, koristite softvere kao što su flashrom, G-Flash (GUI), itd. za dumping firmware-a. G-Flash je minimalni GUI alat koji je brz i automatski prepoznaje EEPROM. Ovo može biti korisno kada je potrebno brzo ekstraktovati firmware, bez mnogo petljanja sa dokumentacijom.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Nakon dumpinga firmware-a, analiza se može obaviti na binarnim datotekama. Alati kao što su strings, hexdump, xxd, binwalk, itd. mogu se koristiti za ekstrakciju mnogo informacija o firmware-u kao i o celom fajl sistemu.

Za ekstrakciju sadržaja iz firmware-a, može se koristiti binwalk. Binwalk analizira heksadecimalne potpise i identifikuje datoteke u binarnoj datoteci i sposoban je da ih ekstrakuje.
```
binwalk -e <filename>
```
Mogu biti .bin ili .rom u zavisnosti od alata i konfiguracija koje se koriste.

{% hint style="danger" %}
Imajte na umu da je ekstrakcija firmvera delikatan proces i zahteva puno strpljenja. Svako nepravilno rukovanje može potencijalno oštetiti firmver ili čak potpuno obrisati i učiniti uređaj neupotrebljivim. Preporučuje se da proučite specifični uređaj pre nego što pokušate da ekstraktujete firmver.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Imajte na umu da čak i ako PINOUT Pirate Busa označava pinove za **MOSI** i **MISO** za povezivanje sa SPI, neki SPIs mogu označavati pinove kao DI i DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

U Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) da dump-ujete sadržaj flash memorije pokrećući nešto poput:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
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
