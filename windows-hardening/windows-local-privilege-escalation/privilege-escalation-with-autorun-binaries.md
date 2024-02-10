# Eskalacija privilegija pomoću Autorun programa

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ako vas zanima **hakerska karijera** i hakovanje nehakabilnog - **mi zapošljavamo!** (_potrebno je tečno poznavanje poljskog jezika, kako pisanog tako i govornog_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** se može koristiti za pokretanje programa pri **pokretanju sistema**. Pogledajte koje binarne datoteke su programirane da se pokrenu pri pokretanju sistema pomoću:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zakazani zadaci

**Zadaci** mogu biti zakazani da se pokreću sa **određenom učestalošću**. Pogledajte koje binarne datoteke su zakazane za pokretanje pomoću:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folderi

Svi binarni fajlovi smešteni u **Startup folderima će biti izvršeni prilikom pokretanja sistema**. Uobičajeni startup folderi su navedeni u nastavku, ali se putanja do startup foldera nalazi u registru. [Pročitajte ovde da biste saznali gde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registar

{% hint style="info" %}
[Napomena odavde](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Unos registra **Wow6432Node** ukazuje da koristite 64-bitnu verziju Windowsa. Operativni sistem koristi ovaj ključ da prikaže odvojeni prikaz HKEY\_LOCAL\_MACHINE\SOFTWARE za 32-bitne aplikacije koje se pokreću na 64-bitnim verzijama Windowsa.
{% endhint %}

### Pokretanja

**Opšte poznati** AutoRun registri:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registarski ključevi poznati kao **Run** i **RunOnce** su dizajnirani da automatski izvršavaju programe svaki put kada se korisnik prijavi na sistem. Komandna linija dodeljena kao vrednost podataka ključa ograničena je na 260 karaktera ili manje.

**Pokretanja servisa** (mogu kontrolisati automatsko pokretanje servisa prilikom podizanja sistema):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Na Windows Vista i novijim verzijama, registarski ključevi **Run** i **RunOnce** se ne generišu automatski. Unosi u ovim ključevima mogu direktno pokretati programe ili ih specificirati kao zavisnosti. Na primer, da bi se učitao DLL fajl pri prijavi, mogao bi se koristiti registarski ključ **RunOnceEx** zajedno sa ključem "Depend". Ovo je prikazano dodavanjem unosa u registar za izvršavanje "C:\\temp\\evil.dll" tokom pokretanja sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Eksploit 1**: Ako možete pisati unutar bilo kojeg od navedenih registara unutar **HKLM**, možete povećati privilegije kada se drugi korisnik prijavi.
{% endhint %}

{% hint style="info" %}
**Eksploit 2**: Ako možete prebrisati bilo koji od binarnih fajlova navedenih u bilo kojem od registara unutar **HKLM**, možete izmeniti taj binarni fajl sa zadnjim vratima kada se drugi korisnik prijavi i povećati privilegije.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Putanja za pokretanje

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Prečice smeštene u fascikli **Startup** automatski će pokrenuti servise ili aplikacije prilikom prijavljivanja korisnika ili ponovnog pokretanja sistema. Lokacija fascikle **Startup** je definisana u registru za oba opsega, **Local Machine** i **Current User**. To znači da će svaka prečica dodata na ove određene lokacije **Startup**-a osigurati da povezani servis ili program pokrene nakon procesa prijavljivanja ili ponovnog pokretanja, čime se postiže jednostavan način za zakazivanje automatskog pokretanja programa.

{% hint style="info" %}
Ako možete prebrisati bilo koji \[User] Shell Folder pod **HKLM**, moći ćete ga usmeriti na fasciklu kojom upravljate i postaviti tajni prolaz koji će se izvršiti svaki put kada se korisnik prijavi na sistem, uz podizanje privilegija.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon ključevi

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipično, ključ **Userinit** je podešen na **userinit.exe**. Međutim, ako je ovaj ključ izmenjen, navedeni izvršni fajl će takođe biti pokrenut od strane **Winlogon**-a prilikom prijavljivanja korisnika. Slično tome, ključ **Shell** je namenjen da pokazuje na **explorer.exe**, koji je podrazumevani shell za Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Ako možete prebrisati vrednost registra ili binarni fajl, moći ćete da povećate privilegije.
{% endhint %}

### Postavke politike

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Proverite ključ **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Promena komande za siguran režim

U Windows registru pod `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, podrazumevano je postavljena vrednost **`AlternateShell`** na `cmd.exe`. To znači da kada odaberete "Siguran režim sa komandnom linijom" prilikom pokretanja (pritiskom na F8), koristi se `cmd.exe`. Međutim, moguće je podesiti računar da se automatski pokrene u ovom režimu bez potrebe da pritisnete F8 i ručno ga odaberete.

Koraci za kreiranje opcije za automatsko pokretanje u "Siguran režim sa komandnom linijom":

1. Promenite atribute fajla `boot.ini` kako biste uklonili atribute samo za čitanje, sistemski i skriveni: `attrib c:\boot.ini -r -s -h`
2. Otvorite `boot.ini` za uređivanje.
3. Ubacite liniju poput: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Sačuvajte promene u `boot.ini`.
5. Ponovo primenite originalne atribute fajla: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Promena registarskog ključa **AlternateShell** omogućava podešavanje prilagođene komandne linije, potencijalno za neovlašćeni pristup.
- **Exploit 2 (Dozvole za pisanje u PATH):** Imajući dozvole za pisanje na bilo koji deo sistemskog **PATH** promenljive, posebno pre `C:\Windows\system32`, omogućava izvršavanje prilagođenog `cmd.exe`, koji može biti tajni prolaz ako se sistem pokrene u Sigurnom režimu.
- **Exploit 3 (Dozvole za pisanje u PATH i boot.ini):** Pisanje u `boot.ini` omogućava automatsko pokretanje u Sigurnom režimu, olakšavajući neovlašćeni pristup pri sledećem ponovnom pokretanju.

Da biste proverili trenutno podešavanje **AlternateShell**, koristite ove komande:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Instalirani komponent

Active Setup je funkcija u Windows operativnom sistemu koja se pokreće pre potpunog učitavanja desktop okruženja. Ona daje prioritet izvršavanju određenih komandi koje moraju biti završene pre nego što se nastavi sa prijavljivanjem korisnika. Ovaj proces se dešava čak i pre pokretanja drugih unosa pri pokretanju, kao što su oni u Run ili RunOnce registarskim sekcijama.

Active Setup se upravlja putem sledećih registarskih ključeva:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Unutar ovih ključeva postoje različiti podključevi, koji odgovaraju određenoj komponenti. Vrednosti ključa koje su posebno zanimljive uključuju:

- **IsInstalled:**
- `0` označava da se komanda komponente neće izvršiti.
- `1` znači da će se komanda izvršiti jednom za svakog korisnika, što je podrazumevano ponašanje ako vrednost `IsInstalled` nedostaje.
- **StubPath:** Definiše komandu koju će izvršiti Active Setup. Može biti bilo koja ispravna komandna linija, kao što je pokretanje `notepad`.

**Bezbednosni uvidi:**

- Izmena ili pisanje u ključu gde je **`IsInstalled`** postavljen na `"1"` sa određenim **`StubPath`**-om može dovesti do neovlašćenog izvršavanja komandi, potencijalno za eskalaciju privilegija.
- Izmena binarnog fajla na koji se referiše u bilo kojoj vrednosti **`StubPath`**-a takođe može postići eskalaciju privilegija, uz odgovarajuće dozvole.

Za pregled konfiguracija **`StubPath`**-a preko Active Setup komponenti, mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Pregled Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) su DLL moduli koji dodaju dodatne funkcionalnosti Microsoft-ovom Internet Explorer-u. Oni se učitavaju u Internet Explorer i Windows Explorer pri svakom pokretanju. Međutim, njihovo izvršavanje može biti blokirano postavljanjem ključa **NoExplorer** na 1, čime se sprečava njihovo učitavanje sa instancama Windows Explorera.

BHOs su kompatibilni sa Windows 10 putem Internet Explorer 11, ali nisu podržani u Microsoft Edge-u, podrazumevanom pregledaču u novijim verzijama Windows-a.

Da biste istražili BHOs registrovane na sistemu, možete pregledati sledeće registarske ključeve:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Svaki BHO je predstavljen svojim **CLSID**-om u registru, koji služi kao jedinstveni identifikator. Detaljne informacije o svakom CLSID-u mogu se pronaći pod `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Za pretragu BHOs u registru, mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer ekstenzije

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Imajte na umu da će registar sadržavati 1 novi registar za svaku dll i biće predstavljen sa **CLSID**. Informacije o CLSID-u možete pronaći u `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font drajveri

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Otvori komandu

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcije izvršavanja slika

Image File Execution Options (IFEO) je mehanizam u operativnom sistemu Windows koji omogućava konfigurisanje dodatnih opcija za izvršavanje određenih izvršnih datoteka. Ova funkcionalnost se često koristi za debagovanje i profilisanje aplikacija, ali može biti iskorišćena i za eskalaciju privilegija.

Kada se IFEO koristi za eskalaciju privilegija, obično se kreira nova vrednost registra pod nazivom Debugger u ključu registra HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{ime_izvršne_datoteke}. Debugger vrednost se postavlja na putanju do izvršne datoteke koja će se pokrenuti umesto originalne izvršne datoteke.

Kada se ciljna izvršna datoteka pokrene, umesto nje će se pokrenuti izvršna datoteka navedena u Debugger vrednosti. Ovo omogućava napadaču da pokrene izvršnu datoteku sa privilegijama višim od onih koje ima trenutni korisnik.

Da bi se iskoristila ova tehnika, napadač mora imati administratorske privilegije na sistemu kako bi mogao da pristupi i izmeni registar. Takođe, napadač mora znati tačnu putanju do izvršne datoteke koju želi da zameni.

Da bi se sprečila zloupotreba IFEO mehanizma, preporučuje se da se registarski ključ HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options zaštiti od neovlašćenih izmena. Takođe, redovno ažuriranje sistema i primena sigurnosnih zakrpa može pomoći u sprečavanju ovakvih napada.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Imajte na umu da su svi sajtovi na kojima možete pronaći autorun fajlove **već pretraženi od strane** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Međutim, za **detaljniju listu automatski izvršenih** fajlova možete koristiti [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) iz SysInternals-a.
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Više

**Pronađite više Autorun registara na [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## Reference

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ako vas zanima **hakerska karijera** i hakiranje nehakabilnog - **zapošljavamo!** (_potrebno je tečno poznavanje poljskog jezika, pisano i govorno_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Naučite hakiranje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite videti **oglašavanje vaše kompanije u HackTricks-u** ili **preuzeti HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakirajuće trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
