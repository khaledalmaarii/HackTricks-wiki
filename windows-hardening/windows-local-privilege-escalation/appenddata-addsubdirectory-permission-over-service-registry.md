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


**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

Mfunguo mbili za rejista zilipatikana kuwa zinaweza kuandikwa na mtumiaji wa sasa:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Ilipendekezwa kuangalia ruhusa za huduma ya **RpcEptMapper** kwa kutumia **regedit GUI**, hasa kwenye kichupo cha **Ruhusa za Usalama za Juu**. Njia hii inaruhusu tathmini ya ruhusa zilizotolewa kwa watumiaji au vikundi maalum bila kuangalia kila Kuingilia Kazi ya Upatikanaji (ACE) moja kwa moja.

Picha ilionyesha ruhusa zilizotolewa kwa mtumiaji mwenye mamlaka ya chini, ambapo ruhusa ya **Kuunda Subkey** ilikuwa ya kutambulika. Ruhusa hii, pia inajulikana kama **AppendData/AddSubdirectory**, inalingana na matokeo ya skripti.

Uwezo wa kubadilisha baadhi ya thamani moja kwa moja, lakini uwezo wa kuunda subkeys mpya, ulionekana. Mfano ulionyesha ni jaribio la kubadilisha thamani ya **ImagePath**, ambayo ilipelekea ujumbe wa kukataliwa kwa ufikiaji.

Licha ya vikwazo hivi, uwezekano wa kupandisha mamlaka ulitambuliwa kupitia uwezekano wa kutumia subkey ya **Performance** ndani ya muundo wa rejista wa huduma ya **RpcEptMapper**, subkey ambayo haipo kwa kawaida. Hii inaweza kuruhusu usajili wa DLL na ufuatiliaji wa utendaji.

Hati kuhusu subkey ya **Performance** na matumizi yake kwa ufuatiliaji wa utendaji ilikaguliwa, ikisababisha maendeleo ya DLL ya uthibitisho wa dhana. DLL hii, ikionyesha utekelezaji wa kazi za **OpenPerfData**, **CollectPerfData**, na **ClosePerfData**, ilijaribiwa kupitia **rundll32**, ikithibitisha mafanikio yake ya uendeshaji.

Lengo lilikuwa kulazimisha huduma ya **RPC Endpoint Mapper** kupakia DLL ya Utendaji iliyoundwa. Uangalizi ulionyesha kuwa kutekeleza maswali ya darasa la WMI yanayohusiana na Data ya Utendaji kupitia PowerShell kulisababisha kuundwa kwa faili ya kumbukumbu, ikiruhusu utekelezaji wa msimbo wa kiholela chini ya muktadha wa **LOCAL SYSTEM**, hivyo kutoa mamlaka ya juu.

Uthibitisho na athari zinazoweza kutokea za udhaifu huu zilisisitizwa, zikionyesha umuhimu wake kwa mikakati ya baada ya unyakuzi, harakati za pembeni, na kuepuka mifumo ya antivirus/EDR.

Ingawa udhaifu huu ulifunuliwa kwa bahati mbaya kupitia skripti, ilisisitizwa kuwa unyakuzi wake unategemea toleo la zamani la Windows (mfano, **Windows 7 / Server 2008 R2**) na unahitaji ufikiaji wa ndani.

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
