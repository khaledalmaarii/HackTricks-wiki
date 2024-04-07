# JTAG

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)is 'n instrument wat met 'n Raspberry PI of 'n Arduino gebruik kan word om JTAG-penne van 'n onbekende skyf te vind.\
In die **Arduino**, verbind die **pennetjies van 2 tot 11 met 10 penne wat moontlik aan 'n JTAG behoort**. Laai die program in die Arduino en dit sal probeer om al die penne te kragtig te vind om te sien of enige penne aan JTAG behoort en watter een elkeen is.\
In die **Raspberry PI** kan jy slegs **pennetjies van 1 tot 6** gebruik (6 penne, dus sal jy stadiger gaan om elke potensiële JTAG-pen te toets).

### Arduino

In Arduino, nadat die kabels aangesluit is (pen 2 tot 11 aan JTAG-penne en Arduino GND aan die basisbord GND), **laai die JTAGenum-program in Arduino** en stuur 'n **`h`** na die Seriële Monitor (bevel vir hulp) en jy behoort die hulp te sien:

![](<../../.gitbook/assets/image (936).png>)

![](<../../.gitbook/assets/image (575).png>)

Stel **"Geen lynafsluiting" en 115200 baud** in.\
Stuur die bevel s om die skandering te begin:

![](<../../.gitbook/assets/image (771).png>)

As jy 'n JTAG kontak, sal jy een of verskeie **lyne vind wat begin met FOUND!** wat die penne van JTAG aandui.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
