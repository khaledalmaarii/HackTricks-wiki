# PsExec/Winexec/ScExec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi wanavyofanya kazi

Mchakato umeelezwa kwa hatua zifuatazo, ukionyesha jinsi faili za huduma zinavyodhibitiwa ili kufanikisha utekelezaji wa kijijini kwenye kompyuta ya lengo kupitia SMB:

1. **Nakala ya faili ya huduma kwenye sehemu ya ADMIN$ kupitia SMB** inatekelezwa.
2. **Uundaji wa huduma kwenye kompyuta ya mbali** unafanywa kwa kuelekeza kwenye faili ya binary.
3. Huduma inaanza **kijijini**.
4. Baada ya kumaliza, huduma ina **kamishwa, na faili ya binary inafutwa**.

### **Mchakato wa Kutekeleza PsExec kwa Mikono**

Kukubaliwa kuwa kuna mzigo wa utekelezaji (uliotengenezwa na msfvenom na kufichwa kwa kutumia Veil ili kuepuka kugunduliwa na programu ya antivirus), uitwao 'met8888.exe', unaowakilisha mzigo wa kurudi_http wa meterpreter, hatua zifuatazo zinachukuliwa:

- **Nakala ya binary**: Faili ya utekelezaji inanakiliwa kwenye sehemu ya ADMIN$ kutoka kwenye dirisha la amri, ingawa inaweza kuwekwa mahali popote kwenye mfumo wa faili ili kubaki siri.

- **Kuunda huduma**: Kwa kutumia amri ya Windows `sc`, ambayo inaruhusu kuuliza, kuunda, na kufuta huduma za Windows kijijini, huduma iliyoitwa "meterpreter" inaundwa ili kuelekeza kwenye binary iliyopakiwa.

- **Kuanza huduma**: Hatua ya mwisho inahusisha kuanza huduma, ambayo inaweza kusababisha kosa la "muda wa kumalizika" kutokana na binary kutokuwa binary halisi ya huduma na kushindwa kurudisha nambari ya majibu inayotarajiwa. Kosa hili halina maana kwa kuwa lengo kuu ni utekelezaji wa binary.

Uangalizi wa msikilizaji wa Metasploit utaonyesha kuwa kikao kimeanzishwa kwa mafanikio.

[Jifunze zaidi kuhusu amri ya `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).


Pata hatua zaidi za kina hapa: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Unaweza pia kutumia binary ya Windows Sysinternals, PsExec.exe:**

![](<../../.gitbook/assets/image (165).png>)

Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
