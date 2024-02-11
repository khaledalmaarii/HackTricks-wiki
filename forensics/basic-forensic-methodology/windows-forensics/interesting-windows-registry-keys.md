# Interessante Windows-registernøkke

### Interessante Windows-registernøkke

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


### **Windows-weergawe en eienaarinligting**
- Onder **`Software\Microsoft\Windows NT\CurrentVersion`** sal jy die Windows-weergawe, dienspakket, installasie-tyd en die geregistreerde eienaar se naam op 'n maklike manier vind.

### **Rekenaarnaam**
- Die rekenaarnaam word gevind onder **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Tydsone-instelling**
- Die stelsel se tydsone word gestoor in **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Toegangstydopsporing**
- Standaard is die laaste toegangstydopsporing afgeskakel (**`NtfsDisableLastAccessUpdate=1`**). Om dit in te skakel, gebruik:
`fsutil behavior set disablelastaccess 0`

### Windows-weergawes en dienspakette
- Die **Windows-weergawe** dui die uitgawe aan (bv. Home, Pro) en sy vrystelling (bv. Windows 10, Windows 11), terwyl **dienspakette** opdaterings is wat herstelwerk en soms nuwe funksies insluit.

### Aktivering van laaste toegangstyd
- Die aktivering van laaste toegangstydopsporing stel jou in staat om te sien wanneer lêers laas geopen is, wat krities kan wees vir forensiese analise of stelselmonitering.

### Netwerkinligtingbesonderhede
- Die register bevat uitgebreide data oor netwerk-konfigurasies, insluitend **netwerksoorte (draadloos, kabel, 3G)** en **netwerkkategorieë (Openbaar, Privaat/Tuis, Domein/Werk)**, wat belangrik is vir die verstaan van netwerksekuriteitsinstellings en toestemmings.

### Kliëntkant-caching (CSC)
- **CSC** verbeter die toegang tot lêers buite lyn deur kopieë van gedeelde lêers te kas. Verskillende **CSCFlags**-instellings beheer hoe en watter lêers gekas word, wat die prestasie en gebruikerservaring beïnvloed, veral in omgewings met onderbroke konnektiwiteit.

### Outomatiese beginprogramme
- Programme wat in verskillende `Run`- en `RunOnce`-registernøkke gelys word, word outomaties by opstart geloods, wat die stelselopstarttyd beïnvloed en moontlik punte van belang kan wees om kwaadwillige sagteware of ongewenste sagteware te identifiseer.

### Shellbags
- **Shellbags** stoor nie net voorkeure vir vouer-aansigte nie, maar verskaf ook forensiese bewyse van vouertoegang selfs as die vouer nie meer bestaan nie. Dit is van onskatbare waarde vir ondersoeke en onthul gebruikersaktiwiteit wat nie duidelik is deur ander middels nie.

### USB-inligting en forensika
- Die besonderhede wat in die register oor USB-toestelle gestoor word, kan help om vas te stel watter toestelle aan 'n rekenaar gekoppel was, moontlik 'n toestel aan gevoelige lêeroordragte of ongemagtigde toegangsgevalle te koppel.

### Volume-seriëlenommer
- Die **Volume-seriëlenommer** kan van kritieke belang wees vir die opsporing van die spesifieke instansie van 'n lêersisteem, wat nuttig is in forensiese scenario's waar lêeroorsprong oor verskillende toestelle vasgestel moet word.

### **Afsluitingsbesonderhede**
- Afsluitingstyd en telling (laasgenoemde slegs vir XP) word in **`System\ControlSet001\Control\Windows`** en **`System\ControlSet001\Control\Watchdog\Display`** gehou.

### **Netwerk-konfigurasie**
- Vir gedetailleerde netwerkinterface-inligting, verwys na **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Eerste en laaste netwerkverbindings-tye, insluitend VPN-verbindings, word gelog onder verskillende paaie in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Gedeelde vouers**
- Gedeelde vouers en instellings is onder **`System\ControlSet001\Services\lanmanserver\Shares`**. Die Kliëntkant-caching (CSC) instellings bepaal die beskikbaarheid van lêers buite lyn.

### **Programme wat outomaties begin**
- Paaie soos **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** en soortgelyke inskrywings onder `Software\Microsoft\Windows\CurrentVersion` beskryf programme wat by opstart ingestel is om uit te voer.

### **Soektogte en getikte paaie**
- Ontdekkingsreisiger-soektogte en getikte paaie word in die register onder **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** vir WordwheelQuery en TypedPaths, onderskeidelik, gevolg.

### **Onlangse dokumente en Office-lêers**
- Onlangse dokumente en Office-lêers wat geopen is, word aangeteken in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` en spesifieke Office-weergawepaaie.

### **Mees onlangs gebruikte (MRU) items**
- MRU-lyste, wat onlangse lêerpaaie en opdragte aandui, word gestoor in verskillende `ComDlg32`- en `Explorer`-subnøkke onder `NTUSER.DAT`.

### **Gebruikersaktiwiteitopsporing**
- Die Gebruikerhulp-funksie hou gedetailleerde toepassingsgebruikstatistieke by, insluitend uitvoertelling en laaste uitvoertyd, by **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags-analise**
- Shellbags, wat vouertoegangsdetails onthul, word gestoor in `USRCLASS.DAT` en `NTUSER.DAT` onder `Software\Microsoft\Windows\Shell`. Gebruik **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** vir analise.

### **USB-toestelgeskiedenis**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** en **`HKLM\SYSTEM\ControlSet001\Enum\USB`** bevat ryk besonderhede oor gekoppelde USB-toestelle, insluitend vervaardiger, produknaam en koppeltydstempels.
- Die gebruiker wat met 'n spesifieke USB-toestel
