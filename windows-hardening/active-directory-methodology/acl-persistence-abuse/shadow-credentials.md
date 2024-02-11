# Vitambulisho vya Kivuli

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee.
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Utangulizi <a href="#3f17" id="3f17"></a>

**Angalia chapisho halisi kwa [habari zote kuhusu mbinu hii](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Kwa muhtasari: ikiwa unaweza kuandika kwenye mali ya mali ya **msDS-KeyCredentialLink** ya mtumiaji/kompyuta, unaweza kupata **NT hash ya kitu hicho**.

Katika chapisho hilo, njia imeelezewa ya kuweka vibali vya uwakilishi vya **funguo za umma-binafsi** ili kupata **Tiketi ya Huduma** ya kipekee ambayo inajumuisha NTLM hash ya lengo. Mchakato huu unahusisha NTLM_SUPPLEMENTAL_CREDENTIAL iliyosimbwa ndani ya Cheti cha Sifa cha Haki (PAC), ambayo inaweza kusimbuliwa.

### Mahitaji

Ili kutumia mbinu hii, hali fulani lazima zitimizwe:
- Inahitajika angalau Kudhibitiwa kwa Kikoa cha Windows Server 2016.
- Kudhibitiwa kwa Kikoa lazima iwe na cheti cha uthibitishaji wa seva kilichosanikishwa.
- Active Directory lazima iwe katika Kiwango cha Kazi cha Windows Server 2016.
- Inahitajika akaunti yenye haki za kuwezesha sifa ya msDS-KeyCredentialLink ya kitu cha lengo.

## Matumizi Mabaya

Matumizi mabaya ya Key Trust kwa vitu vya kompyuta yanajumuisha hatua zaidi ya kupata Tiketi ya Kutoa Tiketi (TGT) na NTLM hash. Chaguo zinajumuisha:
1. Kuunda **tiketi ya fedha ya RC4** ili kutenda kama watumiaji wenye mamlaka kwenye mwenyeji husika.
2. Kutumia TGT na **S4U2Self** kwa udanganyifu wa watumiaji wenye mamlaka, ambayo inahitaji marekebisho kwenye Tiketi ya Huduma ya kuongeza darasa la huduma kwenye jina la huduma.

Faida kubwa ya matumizi mabaya ya Key Trust ni kikomo chake kwa ufunguo wa faragha uliotengenezwa na mshambuliaji, kuepuka kupelekwa kwa akaunti zenye hatari na kutokuhitaji kuunda akaunti ya kompyuta, ambayo inaweza kuwa ngumu kuondoa.

## Zana

### [**Whisker**](https://github.com/eladshamir/Whisker)

Inategemea DSInternals na hutoa kiolesura cha C# kwa shambulio hili. Whisker na mpinzani wake wa Python, **pyWhisker**, huruhusu udhibiti wa sifa ya `msDS-KeyCredentialLink` ili kupata udhibiti wa akaunti za Active Directory. Zana hizi zinasaidia operesheni mbalimbali kama kuongeza, kuorodhesha, kuondoa, na kufuta vibali vya ufunguo kutoka kwa kitu cha lengo.

Vipengele vya **Whisker** ni pamoja na:
- **Ongeza**: Inazalisha jozi ya ufunguo na kuongeza kibali cha ufunguo.
- **Orodhesha**: Inaonyesha viingilio vyote vya vibali vya ufunguo.
- **Ondoa**: Inafuta kibali cha ufunguo kilichotajwa.
- **Futa**: Inafuta vibali vyote vya ufunguo, ikiharibu matumizi halali ya WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Inapanua uwezo wa Whisker kwa mifumo ya **UNIX-based**, ikichanganya Impacket na PyDSInternals kwa uwezo kamili wa kudukua, ikiwa ni pamoja na orodha, kuongeza, na kuondoa KeyCredentials, pamoja na kuziingiza na kuzitoa kwa muundo wa JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray inalenga **kutumia ruhusa za GenericWrite/GenericAll ambazo vikundi vya watumiaji vinaweza kuwa navyo juu ya vitu vya kikoa** ili kutumia ShadowCredentials kwa kiasi kikubwa. Inahusisha kuingia kwenye kikoa, kuthibitisha kiwango cha kazi cha kikoa, kuhesabu vitu vya kikoa, na kujaribu kuongeza KeyCredentials kwa ajili ya kupata TGT na kufunua NT hash. Chaguo za kusafisha na mbinu za kuendeleza uchunguzi huongeza umuhimu wake.


## Marejeo

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye repo ya [hacktricks](https://github.com/carlospolop/hacktricks) na [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
