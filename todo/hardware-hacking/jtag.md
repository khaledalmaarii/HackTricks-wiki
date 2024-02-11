<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


# JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)is 'n instrument wat gebruik kan word met 'n Raspberry PI of 'n Arduino om JTAG-penne van 'n onbekende skyfie te vind.\
In die **Arduino**, verbind die **pennetjies van 2 tot 11 met 10 potensiële JTAG-penne**. Laai die program in die Arduino en dit sal probeer om alle penne te kragteloos maak om te vind of enige penne behoort aan JTAG en watter een elkeen is.\
In die **Raspberry PI** kan jy slegs **pennetjies van 1 tot 6** gebruik (6 penne, so jy sal stadiger gaan deur elke potensiële JTAG-pen te toets).

## Arduino

In Arduino, nadat jy die kabels verbind het (pen 2 tot 11 aan JTAG-penne en Arduino GND aan die basisbord GND), **laai die JTAGenum-program in Arduino** en stuur 'n **`h`** (opdrag vir hulp) na die Serial Monitor en jy behoort die hulp te sien:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Stel **"No line ending" en 115200baud** in.\
Stuur die opdrag s om die skandering te begin:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

As jy 'n JTAG kontak, sal jy een of verskeie **lyne sien wat begin met FOUND!** wat die penne van die JTAG aandui.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
