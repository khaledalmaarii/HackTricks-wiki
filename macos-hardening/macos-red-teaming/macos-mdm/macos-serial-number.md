# macOS Seriële Nommer

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


## Basiese Inligting

Apple-toestelle na 2010 het serienommers wat bestaan uit **12 alfanumeriese karakters**, waarvan elke segment spesifieke inligting oordra:

- **Eerste 3 Karakters**: Dui die **vervaardigingsplek** aan.
- **Karakters 4 & 5**: Dui die **jaar en week van vervaardiging** aan.
- **Karakters 6 tot 8**: Diens as 'n **unieke identifiseerder** vir elke toestel.
- **Laaste 4 Karakters**: Spesifiseer die **modelnommer**.

Byvoorbeeld, die serienommer **C02L13ECF8J2** volg hierdie struktuur.

### **Vervaardigingsplekke (Eerste 3 Karakters)**
Sekere kodes verteenwoordig spesifieke fabrieke:
- **FC, F, XA/XB/QP/G8**: Verskeie plekke in die VSA.
- **RN**: Meksiko.
- **CK**: Cork, Ierland.
- **VM**: Foxconn, Tsjeggiese Republiek.
- **SG/E**: Singapoer.
- **MB**: Maleisië.
- **PT/CY**: Korea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Verskillende plekke in China.
- **C0, C3, C7**: Spesifieke stede in China.
- **RM**: Opgelapte toestelle.

### **Vervaardigingsjaar (4de Karakter)**
Hierdie karakter wissel van 'C' (wat die eerste helfte van 2010 verteenwoordig) tot 'Z' (tweede helfte van 2019), met verskillende letters wat verskillende halfjaarperiodes aandui.

### **Vervaardigingsweek (5de Karakter)**
Syfers 1-9 stem ooreen met weke 1-9. Die letters C-Y (uitgesluit klinkers en 'S') verteenwoordig weke 10-27. Vir die tweede helfte van die jaar word 26 by hierdie nommer gevoeg.

### **Unieke Identifiseerder (Karakters 6 tot 8)**
Hierdie drie syfers verseker dat elke toestel, selfs van dieselfde model en lot, 'n unieke serienommer het.

### **Modelnommer (Laaste 4 Karakters)**
Hierdie syfers identifiseer die spesifieke model van die toestel.

### Verwysing

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
