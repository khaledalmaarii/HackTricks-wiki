# Kantoorlêer-ontleding

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en outomatiseer met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n opsomming:

Microsoft het baie kantoorlêer-formate geskep, met twee hooftipes, naamlik **OLE-formate** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML) formate** (soos DOCX, XLSX, PPTX). Hierdie formate kan makros insluit, wat hulle teikens maak vir hengel en kwaadwillige sagteware. OOXML-lêers is gestruktureer as zip-houers, wat inspeksie deur middel van uitpakkery moontlik maak, waar die lêer- en vouerhiërargie en XML-lêerinhoude onthul word.

Om OOXML-lêerstrukture te verken, word die opdrag om 'n dokument uit te pak en die uitsetstruktuur gegee. Tegnieke vir die versteek van data in hierdie lêers is gedokumenteer, wat voortdurende innovasie in data-versteek binne CTF-uitdagings aandui.

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskapstelle vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie gereedskap help om ingebedde makros te identifiseer en te analiseer, wat dikwels as vektore vir kwaadwillige sagteware-aflewering dien, wat tipies aanvullende skadelike lading aflaai en uitvoer. Analise van VBA-makros kan uitgevoer word sonder Microsoft Office deur gebruik te maak van Libre Office, wat voorsiening maak vir foutopsporing met breekpunte en kykveranderlikes.

Die installasie en gebruik van **oletools** is eenvoudig, met opdragte wat voorsien word vir installasie via pip en die onttrekking van makros uit dokumente. Outomatiese uitvoering van makros word geaktiveer deur funksies soos `AutoOpen`, `AutoExec`, of `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werksvloeie te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repositoriums.

</details>
