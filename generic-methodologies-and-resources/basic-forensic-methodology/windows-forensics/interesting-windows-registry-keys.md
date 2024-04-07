# Interessante Windows-Registrasiereëls

### Interessante Windows-Registrasiereëls

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


### **Windows-weergawe en Eienaarinligting**
- Onder **`Software\Microsoft\Windows NT\CurrentVersion`** vind jy die Windows-weergawe, Dienspakket, installasietyd, en die geregistreerde eienaar se naam op 'n maklike manier.

### **Rekenaarnaam**
- Die rekenaarnaam word gevind onder **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Tydsone-instelling**
- Die stelsel se tydsone word gestoor in **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Toegangstydopsporing**
- Standaard is die laaste toegangstydopsporing afgeskakel (**`NtfsDisableLastAccessUpdate=1`**). Om dit te aktiveer, gebruik:
`fsutil behavior set disablelastaccess 0`

### Windows-weergawes en Dienspakketten
- Die **Windows-weergawe** dui die uitgawe aan (bv., Home, Pro) en sy vrystelling (bv., Windows 10, Windows 11), terwyl **Dienspakette** opdaterings is wat oplossings insluit en soms nuwe funksies.

### Aktivering van Laaste Toegangstyd
- Die aktivering van laaste toegangstydopsporing stel jou in staat om te sien wanneer lêers laas oopgemaak is, wat krities kan wees vir forensiese analise of stelselmonitoring.

### Netwerkinligtingsbesonderhede
- Die registrasie bevat omvattende data oor netwerkkonfigurasies, insluitend **tipes netwerke (draadloos, kabel, 3G)** en **netwerkkategorieë (Publiek, Privaat/Tuis, Domein/Werk)**, wat noodsaaklik is vir die begrip van netwerksekuriteitsinstellings en -toestemmings.

### Kliëntkantse Caching (CSC)
- **CSC** verbeter die aanlyn lêertoegang deur kopieë van gedeelde lêers te kacheer. Verskillende **CSCFlags**-instellings beheer hoe en watter lêers gekasheer word, wat die prestasie en gebruikerervaring beïnvloed, veral in omgewings met onderbrekende konnektiwiteit.

### Outomatiese Beginprogramme
- Programme wat in verskeie `Run` en `RunOnce` registrasiereëls gelys word, word outomaties by aanvang van die stelsel begin, wat die stelselopstarttyd beïnvloed en moontlik punte van belang kan wees vir die identifisering van malware of ongewenste sagteware.

### Shellbags
- **Shellbags** stoor nie net voorkeure vir vouerweergawes nie, maar verskaf ook forensiese bewyse van vouertoegang selfs as die vouer nie meer bestaan nie. Dit is van onschatbare waarde vir ondersoeke, wat gebruikersaktiwiteit onthul wat nie duidelik is deur ander metodes nie.

### USB-inligting en Forensika
- Die besonderhede wat in die registrasie oor USB-toestelle gestoor word, kan help om na te gaan watter toestelle aan 'n rekenaar gekoppel was, wat moontlik 'n toestel aan sensitiewe lêeroordragte of ongemagtigde toegangsinvalle kan koppel.

### Volumereeksnommer
- Die **Volumereeksnommer** kan van kritieke belang wees vir die opsporing van die spesifieke instansie van 'n lêersisteem, nuttig in forensiese scenario's waar lêeroorsprong oor verskillende toestelle vasgestel moet word.

### **Afskakelingsbesonderhede**
- Afskakelingstyd en telling (laasgenoemde slegs vir XP) word in **`System\ControlSet001\Control\Windows`** en **`System\ControlSet001\Control\Watchdog\Display`** bewaar.

### **Netwerkkonfigurasie**
- Vir gedetailleerde netwerkinterfase-inligting, verwys na **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Eerste en laaste netwerkverbindingsdae, insluitend VPN-verbindings, word gelog onder verskeie paaie in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Gedeelde Vouers**
- Gedeelde vouers en instellings is onder **`System\ControlSet001\Services\lanmanserver\Shares`**. Die Kliëntkantse Caching (CSC) instellings bepaal die aanlyn lêerbeskikbaarheid.

### **Programme wat Outomaties Begin**
- Paaie soos **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** en soortgelyke inskrywings onder `Software\Microsoft\Windows\CurrentVersion` beskryf programme wat by aanvang begin moet word.

### **Soekopdragte en Getikte Paaie**
- Ontdekkingsreissoekopdragte en getikte paaie word in die registrasie onder **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** vir WordwheelQuery en TypedPaths, onderskeidelik, gevolg.

### **Onlangse Dokumente en Kantoorlêers**
- Onlangse dokumente en kantoorlêers wat geopen is, word aangeteken in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` en spesifieke kantoorweergawe-paaie.

### **Mees Onlangs Gebruikte (MRU) Items**
- MRU-lyste, wat onlangse lêerpaaie en opdragte aandui, word gestoor in verskeie `ComDlg32` en `Explorer` subleidings onder `NTUSER.DAT`.

### **Gebruikersaktiwiteitsopsporing**
- Die Gebruikersassistente-funksie log gedetailleerde aansoekgebruikstatistieke, insluitend loopgetal en laaste looptyd, by **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags-analise**
- Shellbags, wat vouertoegangsdetails onthul, word gestoor in `USRCLASS.DAT` en `NTUSER.DAT` onder `Software\Microsoft\Windows\Shell`. Gebruik **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** vir analise.

### **USB-toestelgeskiedenis**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** en **`HKLM\SYSTEM\ControlSet001\Enum\USB`** bevat ryk besonderhede oor gekoppelde USB-toestelle, insluitend vervaardiger, produknaam, en koppeltydstempels.
- Die gebruiker wat met 'n spesifieke USB-toestel geassosieer word, kan bepaal word deur in `NTUSER.DAT`-korwe vir die toestel se **{GUID}** te soek.
- Die laaste gemonteerde toestel en sy volumereeksnommer kan nagespeur word deur `System\MountedDevices` en `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, onderskeidelik.

Hierdie gids kondenseer die noodsaaklike paaie en metodes vir die verkryging van gedetailleerde stelsel-, netwerk-, en gebruikersaktiwiteitsinligting op Windows-stelsels, met die doel om duidelikheid en bruikbaarheid te bied.



<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
