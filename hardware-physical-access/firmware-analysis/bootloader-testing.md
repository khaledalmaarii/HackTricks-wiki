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
{% endhint %}

Sledeći koraci se preporučuju za modifikaciju konfiguracija pokretanja uređaja i bootloader-a kao što je U-boot:

1. **Pristup Bootloader-ovom Interpreter Shell-u**:
- Tokom pokretanja, pritisnite "0", razmak ili druge identifikovane "magijske kodove" da biste pristupili bootloader-ovom interpreter shell-u.

2. **Modifikujte Boot Argumente**:
- Izvršite sledeće komande da dodate '`init=/bin/sh`' boot argumentima, omogućavajući izvršavanje shell komande:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Postavite TFTP Server**:
- Konfigurišite TFTP server za učitavanje slika preko lokalne mreže:
%%%
#setenv ipaddr 192.168.2.2 #lokalna IP adresa uređaja
#setenv serverip 192.168.2.1 #IP adresa TFTP servera
#saveenv
#reset
#ping 192.168.2.1 #proverite pristup mreži
#tftp ${loadaddr} uImage-3.6.35 #loadaddr uzima adresu za učitavanje fajla i ime fajla slike na TFTP serveru
%%%

4. **Iskoristite `ubootwrite.py`**:
- Koristite `ubootwrite.py` da napišete U-boot sliku i gurnete modifikovani firmware da biste dobili root pristup.

5. **Proverite Debug Funkcije**:
- Proverite da li su debug funkcije kao što su detaljno logovanje, učitavanje proizvoljnih kernela ili pokretanje sa nepouzdanih izvora omogućene.

6. **Opasna Hardverska Interferencija**:
- Budite oprezni prilikom povezivanja jednog pina na masu i interakcije sa SPI ili NAND flash čipovima tokom sekvence pokretanja uređaja, posebno pre nego što se kernel dekompresuje. Konsultujte se sa tehničkim listom NAND flash čipa pre nego što kratko spojite pinove.

7. **Konfigurišite Rogue DHCP Server**:
- Postavite rogue DHCP server sa zlonamernim parametrima koje uređaj može da prihvati tokom PXE pokretanja. Iskoristite alate kao što je Metasploit-ov (MSF) DHCP pomoćni server. Modifikujte 'FILENAME' parametar sa komandom za injekciju kao što je `'a";/bin/sh;#'` da biste testirali validaciju unosa za procedure pokretanja uređaja.

**Napomena**: Koraci koji uključuju fizičku interakciju sa pinovima uređaja (*označeni zvezdicama) treba da se pristupaju sa ekstremnim oprezom kako bi se izbeglo oštećenje uređaja.


## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% hint style="success" %}
</details>
{% endhint %}
