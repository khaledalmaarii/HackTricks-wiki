# SmbExec/ScExec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Inavyofanya Kazi

**Smbexec** ni zana inayotumiwa kwa utekelezaji wa amri kwa mbali kwenye mifumo ya Windows, kama **Psexec**, lakini inajiepusha kuweka faili yoyote yenye nia mbaya kwenye mfumo wa lengo.

### Mambo Muhimu kuhusu **SMBExec**

- Inafanya kazi kwa kuunda huduma ya muda (kwa mfano, "BTOBTO") kwenye kompyuta ya lengo ili kutekeleza amri kupitia cmd.exe (%COMSPEC%), bila kuacha faili yoyote ya binary.
- Ingawa inatumia njia ya siri, inazalisha magogo ya tukio kwa kila amri inayotekelezwa, ikitoa aina fulani ya "shell" isiyo ya mwingiliano.
- Amri ya kuunganisha kwa kutumia **Smbexec** inaonekana kama hii:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Kutekeleza Amri Bila Programu

- **Smbexec** inawezesha utekelezaji wa moja kwa moja wa amri kupitia njia ya binPaths ya huduma, ikiondoa haja ya kuwa na programu halisi kwenye lengo.
- Njia hii ni muhimu kwa utekelezaji wa amri za mara moja kwenye lengo la Windows. Kwa mfano, kuunganisha na moduli ya `web_delivery` ya Metasploit inaruhusu utekelezaji wa malipo ya PowerShell yaliyolengwa kwa kutumia Meterpreter ya nyuma.
- Kwa kuunda huduma ya mbali kwenye kompyuta ya mshambuliaji na kuweka binPath ili kukimbia amri iliyotolewa kupitia cmd.exe, inawezekana kutekeleza malipo kwa mafanikio, kufikia kurejea na utekelezaji wa malipo na msikilizaji wa Metasploit, hata kama makosa ya majibu ya huduma yanatokea.

### Mifano ya Amri

Kuunda na kuanza huduma kunaweza kufanikiwa kwa kutumia amri zifuatazo:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Kwa maelezo zaidi angalia [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Marejeo
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
