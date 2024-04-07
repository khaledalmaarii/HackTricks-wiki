# SmbExec/ScExec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Inavyofanya Kazi

**Smbexec** ni zana inayotumika kwa utekelezaji wa amri kwa mbali kwenye mifumo ya Windows, sawa na **Psexec**, lakini inakwepa kuweka faili yoyote yenye nia mbaya kwenye mfumo wa lengo.

### Mambo Muhimu kuhusu **SMBExec**

- Inafanya kazi kwa kuunda huduma ya muda (kwa mfano, "BTOBTO") kwenye mashine ya lengo kutekeleza amri kupitia cmd.exe (%COMSPEC%), bila kuacha faili yoyote ya binary.
- Licha ya njia yake ya siri, inazalisha kumbukumbu za tukio kwa kila amri iliyotekelezwa, ikitoa aina fulani ya "shell" isiyo ya mwingiliano.
- Amri ya kuunganisha kutumia **Smbexec** inaonekana hivi:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Kutekeleza Amri Bila Binaries

- **Smbexec** inawezesha utekelezaji wa moja kwa moja wa amri kupitia njia ya binPaths ya huduma, ikiondoa haja ya binaries za kimwili kwenye lengo.
- Njia hii ni muhimu kwa kutekeleza amri za mara moja kwenye lengo la Windows. Kwa mfano, kuiunganisha na moduli ya `web_delivery` ya Metasploit inaruhusu utekelezaji wa mzigo wa nyuma wa Meterpreter uliolengwa na PowerShell.
- Kwa kuunda huduma ya mbali kwenye mashine ya mshambuliaji na kuweka binPath kutekeleza amri iliyotolewa kupitia cmd.exe, inawezekana kutekeleza mzigo kwa mafanikio, kufikia kurejeshwa na utekelezaji wa mzigo na msikilizaji wa Metasploit, hata kama makosa ya majibu ya huduma yanatokea.

### Mfano wa Amri

Kuunda na kuanza huduma inaweza kufanikiwa kwa kutumia amri zifuatazo:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Kwa maelezo zaidi angalia [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Marejeo
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
