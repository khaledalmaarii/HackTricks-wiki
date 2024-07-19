# Fizički Napadi

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je **dark-web** pretraživač koji nudi **besplatne** funkcionalnosti za proveru da li je neka kompanija ili njeni klijenti **kompromitovani** od strane **stealer malwares**.

Njihov primarni cilj WhiteIntel-a je da se bori protiv preuzimanja naloga i ransomware napada koji proizlaze iz malvera koji krade informacije.

Možete proveriti njihovu veb stranicu i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## Oporavak BIOS lozinke i bezbednost sistema

**Resetovanje BIOS-a** može se postići na nekoliko načina. Većina matičnih ploča uključuje **bateriju** koja, kada se ukloni na oko **30 minuta**, resetuje BIOS podešavanja, uključujući lozinku. Alternativno, **jumper na matičnoj ploči** može se prilagoditi za resetovanje ovih podešavanja povezivanjem specifičnih pinova.

Za situacije u kojima prilagođavanje hardvera nije moguće ili praktično, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB** sa distribucijama kao što je **Kali Linux** omogućava pristup alatima kao što su **_killCmos_** i **_CmosPWD_**, koji mogu pomoći u oporavku BIOS lozinke.

U slučajevima kada je BIOS lozinka nepoznata, pogrešno unošenje **tri puta** obično rezultira kodom greške. Ovaj kod može se koristiti na veb sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) da bi se potencijalno povratila upotrebljiva lozinka.

### UEFI Bezbednost

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i modifikaciju UEFI podešavanja, uključujući onemogućavanje **Secure Boot**. To se može postići sledećom komandom:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analiza RAM-a i Cold Boot napadi

RAM zadržava podatke kratko nakon isključenja napajanja, obično od **1 do 2 minuta**. Ova postojanost može se produžiti na **10 minuta** primenom hladnih supstanci, kao što je tečni azot. Tokom ovog produženog perioda, može se napraviti **memory dump** koristeći alate kao što su **dd.exe** i **volatility** za analizu.

### Direct Memory Access (DMA) napadi

**INCEPTION** je alat dizajniran za **fizičku manipulaciju memorijom** putem DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje procedura prijavljivanja patchovanjem memorije da prihvati bilo koju lozinku. Međutim, nije efikasan protiv **Windows 10** sistema.

### Live CD/USB za pristup sistemu

Promena sistemskih binarnih datoteka kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom **_cmd.exe_** može omogućiti komandnu liniju sa sistemskim privilegijama. Alati kao što su **chntpw** mogu se koristiti za uređivanje **SAM** datoteke Windows instalacije, omogućavajući promene lozinke.

**Kon-Boot** je alat koji olakšava prijavljivanje na Windows sisteme bez poznavanja lozinke tako što privremeno modifikuje Windows kernel ili UEFI. Više informacija možete pronaći na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Rukovanje Windows bezbednosnim funkcijama

#### Prečice za pokretanje i oporavak

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u režim oporavka.
- Pritiskom na **Shift** nakon Windows banera može se zaobići automatsko prijavljivanje.

#### BAD USB uređaji

Uređaji kao što su **Rubber Ducky** i **Teensyduino** služe kao platforme za kreiranje **bad USB** uređaja, sposobnih za izvršavanje unapred definisanih payload-a kada su povezani na ciljni računar.

#### Volume Shadow Copy

Administratorske privilegije omogućavaju kreiranje kopija osetljivih datoteka, uključujući **SAM** datoteku, putem PowerShell-a.

### Zaobilaženje BitLocker enkripcije

BitLocker enkripcija može se potencijalno zaobići ako se **recovery password** pronađe unutar datoteke memory dump (**MEMORY.DMP**). Alati kao što su **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic** mogu se koristiti u tu svrhu.

### Socijalno inženjerstvo za dodavanje recovery ključa

Novi BitLocker recovery ključ može se dodati putem taktika socijalnog inženjerstva, ubeđujući korisnika da izvrši komandu koja dodaje novi recovery ključ sastavljen od nula, čime se pojednostavljuje proces dekripcije.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je **dark-web** pretraživač koji nudi **besplatne** funkcionalnosti za proveru da li je neka kompanija ili njeni klijenti **kompromitovani** od strane **stealer malwares**.

Njihov primarni cilj WhiteIntel-a je da se bori protiv preuzimanja naloga i ransomware napada koji proizlaze iz malvera koji krade informacije.

Možete proveriti njihovu veb stranicu i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
