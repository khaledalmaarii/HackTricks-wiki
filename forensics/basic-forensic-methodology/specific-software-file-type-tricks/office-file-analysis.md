# Kantoorlêerontleding

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Vir verdere inligting, besoek [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n opsomming:

Microsoft het baie kantoorlêerformate geskep, met twee hooftipes wat **OLE-formate** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML) formate** (soos DOCX, XLSX, PPTX) insluit. Hierdie formate kan makros insluit, wat hulle teikens maak vir hengel en kwaadwillige sagteware. OOXML-lêers is gestruktureer as zip-houers, wat inspeksie deur middel van ontzip toelaat, wat die lêer- en vouerhiërargie en XML-lêerinhoud onthul.

Om OOXML-lêerstrukture te verken, word die opdrag om 'n dokument te ontzip en die uitvoerstruktuur gegee. Tegnieke vir die versteek van data in hierdie lêers is gedokumenteer, wat dui op voortdurende innovasie in data-versteek binne CTF-uitdagings.

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskapstelle vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie gereedskap help om ingeslote makros te identifiseer en te ontleed, wat dikwels as vektore vir kwaadwillige sagteware-aflewering dien, wat tipies aanvullende skadelike vragte aflaai en uitvoer. Ontleding van VBA-makros kan uitgevoer word sonder Microsoft Office deur gebruik te maak van Libre Office, wat foutopsporing met breekpunte en kykveranderlikes moontlik maak.

Die installasie en gebruik van **oletools** is maklik, met opdragte wat voorsien word vir installering via pip en die onttrekking van makros uit dokumente. Outomatiese uitvoering van makros word geaktiveer deur funksies soos `AutoOpen`, `AutoExec`, of `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiseer werkstrome** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
