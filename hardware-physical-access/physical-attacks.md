# Fizički napadi

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Obnova BIOS šifre i bezbednost sistema

**Resetovanje BIOS-a** može se postići na nekoliko načina. Većina matičnih ploča uključuje **bateriju** koja, kada se ukloni oko **30 minuta**, resetuje BIOS podešavanja, uključujući i šifru. Alternativno, **jumper na matičnoj ploči** može se podesiti da resetuje ova podešavanja povezivanjem određenih pinova.

Za situacije kada hardverske prilagodbe nisu moguće ili praktične, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB** distribucijama poput **Kali Linux-a** omogućava pristup alatima poput **_killCmos_** i **_CmosPWD_**, koji mogu pomoći u obnovi BIOS šifre.

U slučajevima kada je BIOS šifra nepoznata, unošenje je pogrešno **tri puta** obično rezultira greškom. Ovaj kod se može koristiti na veb sajtovima poput [https://bios-pw.org](https://bios-pw.org) kako bi se potencijalno pronašla upotrebljiva šifra.

### UEFI bezbednost

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i modifikaciju UEFI podešavanja, uključujući onemogućavanje **Secure Boot**-a. To se može postići sledećom komandom:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analiza RAM-a i napadi sa hladnim startom

RAM zadržava podatke nakratko nakon isključivanja napajanja, obično **1 do 2 minuta**. Ova postojanost se može produžiti na **10 minuta** primenom hladnih supstanci, poput tečnog azota. Tokom ovog produženog perioda, može se napraviti **damp memorije** koristeći alate poput **dd.exe** i **volatility** za analizu.

### Napadi sa direktnim pristupom memoriji (DMA)

**INCEPTION** je alat dizajniran za **fizičku manipulaciju memorije** putem DMA, kompatibilan sa interfejsima poput **FireWire**-a i **Thunderbolt**-a. Omogućava zaobilaženje postupaka prijave tako što se memorija patchuje da prihvati bilo koju šifru. Međutim, neefikasan je protiv sistema **Windows 10**.

### Live CD/USB za pristup sistemu

Menjanje sistemskih binarnih fajlova poput **_sethc.exe_** ili **_Utilman.exe_** sa kopijom **_cmd.exe_** može obezbediti komandnu liniju sa sistemskim privilegijama. Alati poput **chntpw** mogu se koristiti za uređivanje **SAM** fajla Windows instalacije, omogućavajući promene šifre.

**Kon-Boot** je alat koji olakšava prijavljivanje na Windows sisteme bez poznavanja šifre privremeno modifikujući Windows kernel ili UEFI. Više informacija možete pronaći na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Postupanje sa Windows bezbednosnim funkcijama

#### Prečice za podizanje i oporavak sistema

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u režim oporavka.
- Pritiskanje **Shift** nakon Windows banera može zaobići automatsko prijavljivanje.

#### Uređaji sa lošim USB-om

Uređaji poput **Rubber Ducky**-a i **Teensyduino**-a služe kao platforme za kreiranje uređaja sa **lošim USB-om**, sposobnih za izvršavanje unapred definisanih payload-a kada su povezani sa ciljanim računarom.

#### Kopiranje senki zapisa

Administrator privilegije omogućavaju kreiranje kopija osetljivih fajlova, uključujući **SAM** fajl, putem PowerShell-a.

### Zaobilaženje BitLocker enkripcije

BitLocker enkripcija potencijalno može biti zaobiđena ako se **ključ za oporavak** pronađe u fajlu sa dump-om memorije (**MEMORY.DMP**). Alati poput **Elcomsoft Forensic Disk Decryptor**-a ili **Passware Kit Forensic**-a mogu se koristiti u tu svrhu.

### Društveno inženjerstvo za dodavanje ključa za oporavak

Novi BitLocker ključ za oporavak može se dodati putem taktika društvenog inženjeringa, ubedivši korisnika da izvrši komandu koja dodaje novi ključ za oporavak sastavljen od nula, čime se pojednostavljuje proces dešifrovanja. 

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks suvenir**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
