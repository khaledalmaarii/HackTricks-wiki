# Interesantni Windows registarski ključevi

### Interesantni Windows registarski ključevi

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


### **Informacije o Windows verziji i vlasniku**
- Nađite Windows verziju, Service Pack, vreme instalacije i ime registrovanog vlasnika na jednostavan način u **`Software\Microsoft\Windows NT\CurrentVersion`**.

### **Ime računara**
- Hostname se nalazi pod **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Podešavanje vremenske zone**
- Vremenska zona sistema se čuva u **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Pracenje vremena pristupa**
- Podrazumevano, praćenje vremena poslednjeg pristupa je isključeno (**`NtfsDisableLastAccessUpdate=1`**). Da biste ga omogućili, koristite:
`fsutil behavior set disablelastaccess 0`

### Windows verzije i Service Pack-ovi
- **Windows verzija** označava izdanje (npr. Home, Pro) i njeno izdanje (npr. Windows 10, Windows 11), dok **Service Pack-ovi** predstavljaju ažuriranja koja uključuju popravke i ponekad nove funkcije.

### Omogućavanje vremena poslednjeg pristupa
- Omogućavanje praćenja vremena poslednjeg pristupa omogućava vam da vidite kada su datoteke poslednji put otvorene, što može biti ključno za forenzičku analizu ili praćenje sistema.

### Detalji o mrežnim informacijama
- Registar čuva obimne podatke o mrežnim konfiguracijama, uključujući **tipove mreža (bežične, kablove, 3G)** i **kategorije mreže (Javna, Privatna/Domaća, Domen/Radna)**, što je važno za razumevanje postavki mrežne sigurnosti i dozvola.

### Klijentsko skladištenje (CSC)
- **CSC** poboljšava pristup datotekama van mreže skladištenjem kopija deljenih datoteka. Različita podešavanja **CSCFlags** kontrolišu kako i koje datoteke se skladište, utičući na performanse i korisničko iskustvo, posebno u okruženjima sa povremenom konekcijom.

### Programi koji se automatski pokreću
- Programi navedeni u različitim `Run` i `RunOnce` registarskim ključevima automatski se pokreću prilikom pokretanja sistema, utičući na vreme pokretanja sistema i potencijalno predstavljajući tačke interesa za identifikaciju malvera ili neželjenog softvera.

### Shellbags
- **Shellbags** ne samo da čuvaju preferencije za prikaze fascikli, već pružaju i forenzičke dokaze o pristupu fasciklama čak i ako fascikla više ne postoji. Oni su neprocenjivi za istrage, otkrivajući korisničku aktivnost koja nije očigledna na druge načine.

### Informacije i forenzika o USB uređajima
- Detalji o USB uređajima čuvaju se u registru i mogu pomoći u praćenju koji su uređaji bili povezani sa računarom, potencijalno povezujući uređaj sa prenosom osetljivih datoteka ili incidentima neovlašćenog pristupa.

### Serijski broj zapremine
- **Serijski broj zapremine** može biti ključan za praćenje specifične instance sistema datoteka, koristan u forenzičkim scenarijima gde je potrebno utvrditi poreklo datoteke na različitim uređajima.

### **Detalji o isključivanju**
- Vreme isključivanja i broj (samo za XP) čuvaju se u **`System\ControlSet001\Control\Windows`** i **`System\ControlSet001\Control\Watchdog\Display`**.

### **Konfiguracija mreže**
- Za detaljne informacije o mrežnim interfejsima, pogledajte **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Prvo i poslednje vreme povezivanja na mrežu, uključujući VPN veze, beleže se pod različitim putanjama u **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Deljeni folderi**
- Deljeni folderi i podešavanja nalaze se pod **`System\ControlSet001\Services\lanmanserver\Shares`**. Podešavanja klijentskog skladištenja (CSC) određuju dostupnost datoteka van mreže.

### **Programi koji se automatski pokreću**
- Putanje poput **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** i slični unosi pod `Software\Microsoft\Windows\CurrentVersion` detaljno opisuju programe postavljene da se pokreću prilikom pokretanja sistema.

### **Pretrage i otkucane putanje**
- Pretrage i otkucane putanje u Explorer-u prate se u registru pod **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** za WordwheelQuery i TypedPaths, redom.

### **Nedavni dokumenti i Office datoteke**
- Nedavni dokumenti i Office datoteke na koje je pristupano beleže se u `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` i specifičnim putanjama za verzije Office-a.

### **Nedavno korišćeni (MRU) elementi**
- Liste MRU, koje pokazuju nedavne putanje do datoteka i komande, čuvaju se u različitim podključevima `ComDlg32` i `Explorer` pod `NTUSER.DAT`.

### **Pracenje korisničke aktivnosti**
- Funkcija User Assist beleži detaljnu statistiku korišćenja aplikacija, uključujući broj pokretanja i poslednje vreme pokretanja, na putanji **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analiza Shellbags-a**
- Shellbags, koji otkrivaju detalje o pristupu fasciklama, čuvaju se u `USRCLASS.DAT` i `NTUSER.DAT` pod `Software\Microsoft\Windows\Shell`. Koristite **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** za analizu.

### **Istorija USB uređaja**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** i **`HKLM\SYSTEM\ControlSet001\Enum\USB`** sadrže bogate detalje o povezanim USB uređajima, uključujući proizvođača, naziv proizvoda i vremenske oznake povezivanja.
- Korisnik povezan sa određenim USB uređajem može se locirati pretragom `NTUSER.DAT` košnica za **{GUID}** uređaja.
- Poslednji montirani uređaj i njegov serijski broj zapremine mogu se pratiti kroz `System\MountedDevices` i `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, redom.

Ovaj vodič sažima ključne putanje i metode za pristup detaljnim informacijama o sistemu, mreži i korisničkoj aktivnosti na Windows sistemima, teži ka jasnoći i upotrebljivosti.



<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
