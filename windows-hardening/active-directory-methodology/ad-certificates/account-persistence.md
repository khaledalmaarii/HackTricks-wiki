# AD CS Uthabiti wa Akaunti

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Hii ni muhtasari mdogo wa sura za uthabiti wa mashine kutoka kwenye utafiti mzuri kutoka [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Kuelewa Wizi wa Kitambulisho cha Mtumiaji Mwenye Shughuli na Vyeti - PERSIST1**

Katika hali ambapo cheti kinachoruhusu uthibitisho wa kikoa kinaweza kuombwa na mtumiaji, mshambuliaji ana fursa ya **kuomba** na **kuiba** cheti hiki ili **kuendelea kuwepo** kwenye mtandao. Kwa chaguo-msingi, kigezo cha `User` katika Active Directory kinaruhusu maombi kama hayo, ingawa mara nyingine inaweza kuwa imezimwa.

Kwa kutumia zana inayoitwa [**Certify**](https://github.com/GhostPack/Certify), mtu anaweza kutafuta vyeti halali vinavyowezesha ufikiaji endelevu:
```bash
Certify.exe find /clientauth
```
Imesisitiza kuwa nguvu ya cheti iko katika uwezo wake wa **uthibitisho kama mtumiaji** ambaye cheti hicho kinahusiana naye, bila kujali mabadiliko ya nenosiri, ikiwa tu cheti kinaendelea kuwa **halali**.

Cheti linaweza kuombwa kupitia kiolesura cha picha kinachotumia `certmgr.msc` au kupitia mstari wa amri na `certreq.exe`. Kwa kutumia **Certify**, mchakato wa kuomba cheti unafanywa kuwa rahisi kama ifuatavyo:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Baada ya ombi la mafanikio, cheti pamoja na ufunguo wake wa kibinafsi hutengenezwa katika muundo wa `.pem`. Ili kubadilisha hii kuwa faili ya `.pfx`, ambayo inaweza kutumiwa kwenye mifumo ya Windows, amri ifuatayo hutumiwa:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Faili la `.pfx` linaweza kupakiwa kwenye mfumo wa lengo na kutumika na zana inayoitwa [**Rubeus**](https://github.com/GhostPack/Rubeus) kuomba Tiketi ya Kibali cha Tiketi (TGT) kwa mtumiaji, kuongeza ufikiaji wa mshambuliaji kwa muda mrefu kama cheti kinavyokuwa **halali** (kawaida mwaka mmoja):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Tahadhari muhimu inashirikiwa juu ya jinsi mbinu hii, iliyochanganywa na njia nyingine iliyoelezwa katika sehemu ya **THEFT5**, inaruhusu mshambuliaji kupata kwa kudumu **NTLM hash** ya akaunti bila kuingiliana na Huduma ya Subsystem ya Usalama wa Mitaa (LSASS), na kutoka kwa muktadha usio na uwezo, kutoa njia ya siri zaidi ya wizi wa vitambulisho kwa muda mrefu.

## **Kupata Uthabiti wa Mashine na Vyeti - PERSIST2**

Njia nyingine inahusisha kujiandikisha kwa akaunti ya mashine ya mfumo uliopotoshwa kwa cheti, kwa kutumia kigezo cha cheti cha `Machine` kinachoruhusu hatua kama hizo. Ikiwa mshambuliaji anapata mamlaka ya juu kwenye mfumo, wanaweza kutumia akaunti ya **SYSTEM** kuomba vyeti, kutoa aina fulani ya **uthabiti**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Hii ufikiaji unawezesha mshambuliaji kujithibitisha kwa **Kerberos** kama akaunti ya mashine na kutumia **S4U2Self** kupata tiketi za huduma za Kerberos kwa huduma yoyote kwenye mwenyeji, kwa ufanisi kumpa mshambuliaji ufikiaji endelevu kwenye mashine.

## **Kuongeza Uthabiti Kupitia Ukarabati wa Cheti - PERSIST3**

Njia ya mwisho inayojadiliwa inahusisha kutumia **kipindi cha halali** na **vipindi vya ukarabati** vya templeti za cheti. Kwa **kukarabati** cheti kabla ya muda wake wa kumalizika, mshambuliaji anaweza kuendelea kujithibitisha kwa Active Directory bila hitaji la usajili wa tiketi za ziada, ambazo zinaweza kuacha alama kwenye seva ya Mamlaka ya Cheti (CA).

Njia hii inaruhusu njia ya **uthabiti uliopanuliwa**, kupunguza hatari ya kugundulika kupitia mwingiliano mdogo na seva ya CA na kuepuka kuzalisha vitu ambavyo vinaweza kuwajulisha waendeshaji kuhusu uvamizi.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionyeshwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
