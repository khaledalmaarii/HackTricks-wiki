# PsExec/Winexec/ScExec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Wanavyofanya Kazi

Mchakato umeelezwa katika hatua zifuatazo, ukionyesha jinsi binaries za huduma zinavyodhibitiwa ili kufikia utekelezaji wa mbali kwenye mashine ya lengo kupitia SMB:

1. **Kunakiliwa kwa binary ya huduma kwenda kwenye mgawanyo wa ADMIN$ kupitia SMB** inatekelezwa.
2. **Uumbaji wa huduma kwenye mashine ya mbali** unafanywa kwa kuelekeza kwenye binary.
3. Huduma inaanza **kutoka kwa mbali**.
4. Baada ya kumaliza, huduma ina **kuzimwa, na binary inafutwa**.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Kukadiria kuna mzigo wa utekelezaji (uliotengenezwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka ugunduzi wa antivirus), uitwao 'met8888.exe', ukionyesha mzigo wa nyuma wa meterpreter reverse\_http, hatua zifuatazo huchukuliwa:

* **Kunakiliwa kwa binary**: Mzigo wa utekelezaji unanakiliwa kwenye mgawanyo wa ADMIN$ kutoka kwa dirisha la amri, ingawa unaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki siri.
* **Kuunda huduma**: Kwa kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kwa mbali, huduma inayoitwa "meterpreter" inaundwa ili kuelekeza kwenye binary iliyopakiwa.
* **Kuanza huduma**: Hatua ya mwisho inahusisha kuanza huduma, ambayo labda itasababisha kosa la "muda wa nje" kwa sababu binary sio binary halisi ya huduma na kushindwa kurudisha nambari ya majibu inayotarajiwa. Kosa hili halina maana kwa kuwa lengo kuu ni utekelezaji wa binary.

Uangalizi wa msikilizaji wa Metasploit utaonyesha kuwa kikao kimeanzishwa kwa mafanikio.

[Jifunze zaidi kuhusu amri ya `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pata hatua zaidi za kina katika: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Unaweza pia kutumia binary ya Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
