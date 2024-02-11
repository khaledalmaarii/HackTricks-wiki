# BloodHound na Zana Zingine za AD Enum

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) ni sehemu ya Suite ya Sysinternal:

> Ni mtazamaji na mhariri wa Active Directory (AD) wa juu. Unaweza kutumia AD Explorer kuvinjari kwa urahisi kwenye database ya AD, kufafanua maeneo ya kupendelea, kuona mali na sifa za vitu bila kufungua sanduku la mazungumzo, kuhariri ruhusa, kuona mpangilio wa vitu, na kutekeleza utafutaji wa kisasa ambao unaweza kuokoa na kutekeleza tena.

### Picha za Skrini

AD Explorer inaweza kuunda picha za skrini za AD ili uweze kuiangalia nje ya mtandao.\
Inaweza kutumika kugundua udhaifu nje ya mtandao, au kulinganisha hali tofauti za DB ya AD kwa wakati.

Utahitaji jina la mtumiaji, nenosiri, na mwelekeo wa kuunganisha (mtumiaji yeyote wa AD inahitajika).

Ili kuchukua picha ya skrini ya AD, nenda kwa `File` --> `Create Snapshot` na ingiza jina kwa picha ya skrini.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) ni zana ambayo inachambua na kuunganisha vielelezo mbalimbali kutoka kwenye mazingira ya AD. Taarifa inaweza kuwasilishwa katika **ripoti** ya Microsoft Excel **iliyopangwa maalum** ambayo inajumuisha muhtasari na takwimu za kurahisisha uchambuzi na kutoa picha kamili ya hali ya sasa ya mazingira ya AD ya lengo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Kutoka [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound ni programu-jalizi ya wavuti ya Javascript ya ukurasa mmoja, iliyojengwa juu ya [Linkurious](http://linkurio.us/), iliyopewa muundo na [Electron](http://electron.atom.io/), na hifadhidata ya [Neo4j](https://neo4j.com/) iliyojazwa na mkusanyaji wa data ya C#.

BloodHound hutumia nadharia ya grafu kuonyesha uhusiano uliofichika na mara nyingi usiotarajiwa ndani ya Mazingira ya Active Directory au Azure. Wadukuzi wanaweza kutumia BloodHound kwa urahisi kutambua njia za mashambulizi zenye utata ambazo kwa kawaida ingekuwa vigumu kutambua haraka. Watetezi wanaweza kutumia BloodHound kutambua na kuondoa njia hizo za mashambulizi. Timu za bluu na nyekundu zote wanaweza kutumia BloodHound kwa urahisi kupata ufahamu zaidi wa uhusiano wa mamlaka katika Mazingira ya Active Directory au Azure.

Kwa hivyo, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) ni chombo cha kushangaza ambacho kinaweza kuchunguza kikoa kiotomatiki, kuhifadhi habari zote, kupata njia za kuongeza mamlaka na kuonyesha habari zote kwa kutumia grafu.

Bloodhound ina sehemu kuu 2: **ingestors** na **programu ya kuonyesha**.

**Ingestors** hutumiwa kwa **kuchunguza kikoa na kutoa habari zote** katika muundo ambao programu ya kuonyesha itaelewa.

**Programu ya kuonyesha inatumia neo4j** kuonyesha jinsi habari zote zinavyohusiana na kuonyesha njia tofauti za kuongeza mamlaka katika kikoa.

### Usanidi
Baada ya uundaji wa BloodHound CE, mradi mzima ulisasishwa ili kuwa rahisi kutumia Docker. Njia rahisi ya kuanza ni kutumia usanidi wa Docker Compose uliopangwa tayari.

1. Sakinisha Docker Compose. Hii inapaswa kuwa pamoja na usanidi wa [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Chalisha:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Tafuta nenosiri lililoundwa kwa nasibu katika matokeo ya terminal ya Docker Compose.
4. Kwenye kivinjari, nenda kwenye http://localhost:8080/ui/login. Ingia kwa kutumia jina la mtumiaji la admin na nenosiri lililoundwa kwa nasibu kutoka kwenye magogo.

Baada ya hapo utahitaji kubadilisha nenosiri lililoundwa kwa nasibu na utakuwa na kiolesura kipya tayari, ambapo unaweza kupakua moja kwa moja wachambuzi wa data.

### SharpHound

Wana chaguo kadhaa lakini ikiwa unataka kukimbia SharpHound kutoka kwenye PC uliyounganishwa kwenye kikoa, ukitumia mtumiaji wako wa sasa na kuchambua habari zote unaweza kufanya yafuatayo:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Unaweza kusoma zaidi kuhusu **CollectionMethod** na kikao cha mzunguko [hapa](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Ikiwa unataka kutekeleza SharpHound ukitumia sifa tofauti za uwakilishi, unaweza kuunda kikao cha CMD cha netonly na kukimbia SharpHound kutoka hapo:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Jifunze zaidi kuhusu Bloodhound katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) ni chombo cha kutafuta **mapungufu** katika Active Directory yanayohusiana na **Group Policy**. \
Unahitaji **kuendesha group3r** kutoka kwenye mwenyeji ndani ya kikoa kwa kutumia **mtumiaji yeyote wa kikoa**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **inahakiki hali ya usalama wa mazingira ya AD** na hutoa **ripoti** nzuri na chati.

Ili kuendesha, unaweza kutekeleza faili ya binary `PingCastle.exe` na itaanza **kikao cha kuingiliana** kinachoonyesha menyu ya chaguo. Chaguo la msingi la kutumia ni **`healthcheck`** ambayo itaweka **muhtasari** wa **kikoa**, na kupata **makosa ya usanidi** na **mapungufu ya usalama**.&#x20;

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
