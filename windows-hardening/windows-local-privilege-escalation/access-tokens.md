# Pristupni tokeni

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS ili preuzimanje HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova** [**hacktricks repozitorijumu**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijumu**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač na **dark vebu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu podataka**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb stranicu i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Pristupni tokeni

Svaki **korisnik prijavljen** na sistem **poseduje pristupni token sa informacijama o bezbednosti** za tu sesiju prijavljivanja. Sistem kreira pristupni token kada se korisnik prijavi. **Svaki proces izvršen** u ime korisnika **ima kopiju pristupnog tokena**. Token identifikuje korisnika, grupe korisnika i privilegije korisnika. Token takođe sadrži SID prijave (Security Identifier) koji identifikuje trenutnu sesiju prijavljivanja.

Ove informacije možete videti izvršavanjem `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
### Lokalni privilegiovani pristup

Kada se lokalni administrator prijavi, **kreiraju se dva pristupna tokena**: Jedan sa administratorskim pravima i drugi sa normalnim pravima. **Podrazumevano**, kada ovaj korisnik pokrene proces, koristi se onaj sa **običnim** (neadministrator) **pravima**. Kada ovaj korisnik pokuša da **izvrši** nešto **kao administrator** ("Pokreni kao administrator" na primer), **UAC** će zatražiti dozvolu.\
Ako želite da [**saznate više o UAC pročitajte ovu stranicu**](../authentication-credentials-uac-and-efs/#uac)**.**

### Impersonacija korisničkih akreditacija

Ako imate **validne akreditacije bilo kog drugog korisnika**, možete **kreirati** novu **sesiju prijavljivanja** sa tim akreditacijama:
```
runas /user:domain\username cmd.exe
```
**Pristupni token** takođe ima **referencu** sesija prijavljivanja unutar **LSASS**-a, što je korisno ako proces treba da pristupi nekim objektima na mreži.\
Možete pokrenuti proces koji **koristi različite akreditive za pristup mrežnim uslugama** koristeći:
```
runas /user:domain\username /netonly cmd.exe
```
Ovo je korisno ako imate korisne akreditive za pristup objektima u mreži, ali ti akreditivi nisu važeći unutar trenutnog računara jer će se koristiti samo u mreži (na trenutnom računaru će se koristiti vaši trenutni korisnički privilegiji).

### Vrste tokena

Postoje dva tipa dostupnih tokena:

* **Primarni token**: Služi kao reprezentacija sigurnosnih akreditiva procesa. Kreiranje i povezivanje primarnih tokena sa procesima su radnje koje zahtevaju povišene privilegije, naglašavajući princip razdvajanja privilegija. Tipično, servis za autentifikaciju je odgovoran za kreiranje tokena, dok servis za prijavljivanje upravlja njegovim povezivanjem sa korisnikovim operativnim sistemom. Važno je napomenuti da procesi nasleđuju primarni token svog roditeljskog procesa prilikom kreiranja.
* **Token za oponašanje**: Omogućava serverskoj aplikaciji da privremeno preuzme identitet klijenta radi pristupa sigurnim objektima. Ovaj mehanizam je stratifikovan u četiri nivoa operacija:
  * **Anoniman**: Dodeljuje pristup serveru sličan pristupu nepoznatog korisnika.
  * **Identifikacija**: Omogućava serveru da proveri identitet klijenta bez korišćenja za pristup objektima.
  * **Oponašanje**: Omogućava serveru da funkcioniše pod identitetom klijenta.
  * **Delegacija**: Slično oponašanju, ali uključuje mogućnost proširenja ove pretpostavke identiteta na udaljene sisteme sa kojima server interaguje, obezbeđujući očuvanje akreditiva.

#### Oponašanje tokena

Korišćenjem _**incognito**_ modula metasploita, ako imate dovoljno privilegija, možete lako **izlistati** i **oponašati** druge **tokene**. Ovo može biti korisno za izvođenje **akcija kao da ste drugi korisnik**. Takođe možete **povišiti privilegije** ovom tehnikom.

### Privilegije tokena

Saznajte koje **privilegije tokena mogu biti zloupotrebljene za povišenje privilegija:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Pogledajte [**sve moguće privilegije tokena i neke definicije na ovoj spoljnoj stranici**](https://github.com/gtworek/Priv2Admin).

## Reference

Saznajte više o tokenima u ovim tutorijalima: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) i [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač na **dark vebu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **pogođeni** od strane **malvera koji kradu informacije**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji kradu informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite da imate pristup **najnovijoj verziji PEASS ili preuzmete HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
