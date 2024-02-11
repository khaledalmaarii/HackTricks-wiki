<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


**Mchapisho asili ni** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Muhtasari

Vipengele viwili vya usajili viligunduliwa kuwa vinaweza kuandikwa na mtumiaji wa sasa:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Ilipendekezwa kuangalia ruhusa za huduma ya **RpcEptMapper** kwa kutumia **regedit GUI**, haswa kichupo cha **Ruhusa Zinazofaa** cha dirisha la **Mipangilio ya Usalama ya Juu**. Njia hii inaruhusu tathmini ya ruhusa zilizotolewa kwa watumiaji au vikundi maalum bila haja ya kuchunguza kila Kuingia Kudhibiti Upatikanaji (ACE) kwa kujitegemea.

Picha ilionyesha ruhusa zilizopewa mtumiaji mwenye haki ndogo, ambapo ruhusa ya **Kujenga Subkey** ilikuwa ya kushangaza. Ruhusa hii, inayojulikana pia kama **AppendData/AddSubdirectory**, inalingana na matokeo ya hati.

Uwezo wa kubadilisha thamani fulani moja kwa moja, lakini uwezo wa kuunda vijidirisha vipya, ulibainishwa. Mfano ulioonyeshwa ulikuwa jaribio la kubadilisha thamani ya **ImagePath**, ambayo ilisababisha ujumbe wa kukataliwa kwa ufikiaji.

Licha ya vizuizi hivi, uwezekano wa kuongeza mamlaka uligunduliwa kupitia uwezekano wa kutumia vijidirisha vya **Performance** ndani ya muundo wa usajili wa huduma ya **RpcEptMapper**, vijidirisha ambavyo havipo kwa chaguo-msingi. Hii inaweza kuwezesha usajili wa DLL na ufuatiliaji wa utendaji.

Ushauri juu ya vijidirisha vya **Performance** na matumizi yake kwa ufuatiliaji wa utendaji ulitumiwa, ikisababisha maendeleo ya DLL ya mfano. DLL hii, ikionyesha utekelezaji wa kazi za **OpenPerfData**, **CollectPerfData**, na **ClosePerfData**, ilijaribiwa kupitia **rundll32**, ikithibitisha mafanikio yake ya uendeshaji.

Lengo lilikuwa kulazimisha **huduma ya Msimamizi wa Mwisho wa RPC** kusoma DLL ya Ufundi wa Utendaji iliyoundwa. Uchunguzi ulifunua kuwa kutekeleza maswali ya darasa la WMI yanayohusiana na Data ya Utendaji kupitia PowerShell kulifanya faili ya kumbukumbu kuundwa, kuruhusu utekelezaji wa nambari ya aina yoyote chini ya muktadha wa **LOCAL SYSTEM**, hivyo kutoa mamlaka zilizoongezeka.

Uthabiti na athari za udhaifu huu zilisisitizwa, ikionyesha umuhimu wake kwa mikakati ya baada ya kudukua, harakati za pande zote, na kuepuka antivirus/EDR.

Ingawa udhaifu huu ulifunuliwa awali kwa bahati mbaya kupitia hati, ilisisitizwa kuwa unyanyasaji wake unakandamizwa kwa toleo za zamani za Windows (k.m., **Windows 7 / Server 2008 R2**) na unahitaji ufikiaji wa ndani. 

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
