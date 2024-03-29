# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kiotomatiki** inayotumia zana za jamii za **juu kabisa** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Orodha ya Kudhibiti Ufikiaji (ACL)**

Orodha ya Kudhibiti Ufikiaji (ACL) inajumuisha seti iliyopangwa ya Vitambulisho vya Kudhibiti Ufikiaji (ACEs) ambavyo vinadhibiti ulinzi wa kitu na mali zake. Kimsingi, ACL inaamua ni vitendo vipi vinavyoruhusiwa au kupigwa marufuku kwa kitu kilichopo.

Kuna aina mbili za ACLs:

* **Orodha ya Kudhibiti Ufikiaji wa Hiari (DACL):** Inabainisha ni watumiaji na vikundi vipi vinavyo au havina ufikiaji wa kitu.
* **Orodha ya Kudhibiti Ufikiaji wa Mfumo (SACL):** Inasimamia ukaguzi wa jaribio la ufikiaji wa kitu.

Mchakato wa kupata faili unajumuisha mfumo kuchunguza maelezo ya usalama ya kitu dhidi ya ishara ya ufikiaji wa mtumiaji ili kubaini ikiwa ufikiaji unapaswa kuruhusiwa na kiwango cha ufikiaji huo, kulingana na ACEs.

### **Vipengele muhimu**

* **DACL:** Ina ACEs ambazo hutoa au kukataa ruhusa za ufikiaji kwa watumiaji na vikundi kwa kitu. Kimsingi ni ACL kuu inayodhibiti haki za ufikiaji.
* **SACL:** Hutumiwa kwa ukaguzi wa ufikiaji wa vitu, ambapo ACEs hufafanua aina za ufikiaji zinazopaswa kurekodiwa kwenye Kumbukumbu ya Tukio la Usalama. Hii inaweza kuwa muhimu kwa kugundua jaribio la ufikiaji usioruhusiwa au kutatua masuala ya ufikiaji.

### **Mwingiliano wa Mfumo na ACLs**

Kila kikao cha mtumiaji kinaambatishwa na ishara ya ufikiaji inayojumuisha habari ya usalama inayofaa kwa kikao hicho, ikiwa ni pamoja na mtumiaji, vitambulisho vya vikundi, na mamlaka. Ishara hii pia inajumuisha SID ya kuingia ambayo inatambulisha kwa kipekee kikao hicho.

Mamlaka ya Usalama ya Ndani (LSASS) huprocess maombi ya ufikiaji wa vitu kwa kuchunguza DACL kwa ACEs ambazo zinafaa kwa mamlaka ya usalama inayojaribu ufikiaji. Ufikiaji unaruhusiwa mara moja ikiwa hakuna ACEs zinazofaa zinazopatikana. Vinginevyo, LSASS inalinganisha ACEs dhidi ya SID ya mamlaka ya usalama katika ishara ya ufikiaji ili kubaini uhalali wa ufikiaji.

### **Mchakato Uliosumuliwa**

* **ACLs:** Hufafanua ruhusa za ufikiaji kupitia DACLs na sheria za ukaguzi kupitia SACLs.
* **Ishara ya Ufikiaji:** Ina habari ya mtumiaji, kikundi, na maelezo ya kikao.
* **Uamuzi wa Ufikiaji:** Hufanywa kwa kulinganisha DACL ACEs na ishara ya ufikiaji; SACLs hutumiwa kwa ukaguzi.

### ACEs

Kuna **aina tatu kuu za Vitambulisho vya Kudhibiti Ufikiaji (ACEs)**:

* **ACE ya Kukataa Ufikiaji**: ACE hii inakataza wazi ufikiaji wa kitu kwa watumiaji au vikundi vilivyoorodheshwa (katika DACL).
* **ACE ya Kuruhusu Ufikiaji**: ACE hii inaruhusu wazi ufikiaji wa kitu kwa watumiaji au vikundi vilivyoorodheshwa (katika DACL).
* **ACE ya Ukaguzi wa Mfumo**: Iliyowekwa ndani ya Orodha ya Kudhibiti Ufikiaji wa Mfumo (SACL), ACE hii inahusika na kuzalisha magogo ya ukaguzi wakati wa jaribio la ufikiaji wa kitu na watumiaji au vikundi. Inaandika ikiwa ufikiaji uliruhusiwa au kukataliwa na asili ya ufikiaji.

Kila ACE ina **vipengele vinne muhimu**:

1. **Kitambulisho cha Usalama (SID)** cha mtumiaji au kikundi (au jina lao la msingi katika uwakilishi wa kielelezo).
2. **Bendera** inayoidhinisha aina ya ACE (kukataza ufikiaji, kuruhusu, au ukaguzi wa mfumo).
3. **Bendera za urithi** zinazobainisha ikiwa vitu vya watoto vinaweza kurithi ACE kutoka kwa mzazi wao.
4. [**Barua ya ufikiaji**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), thamani ya biti 32 inayobainisha haki zilizopewa kitu.

Uamuzi wa ufikiaji unafanywa kwa kuchunguza kila ACE kwa mpangilio hadi:

* ACE ya **Kukataza Ufikiaji** inakataza wazi haki zilizoombwa kwa msimamizi aliyeorodheshwa katika ishara ya ufikiaji.
* ACE ya **Kuruhusu Ufikiaji** inaruhusu wazi haki zote zilizoombwa kwa msimamizi katika ishara ya ufikiaji.
* Baada ya kuchunguza ACE zote, ikiwa haki yoyote iliyotakiwa haijaruhusiwa wazi, ufikiaji unakataliwa kwa upande wa msingi.

### Mpangilio wa ACEs

Namna **ACEs** (sheria zinazosema ni nani anaweza au hawezi kupata kitu) zinavyowekwa kwenye orodha inayoitwa **DACL** ni muhimu sana. Hii ni kwa sababu mara mfumo unapotoa au kukataa ufikiaji kulingana na sheria hizi, hauendelei kutazama zaidi.

Kuna njia bora ya kuandaa ACEs hizi, na inaitwa **"mpangilio wa kanoni."** Mbinu hii husaidia kuhakikisha kila kitu kinatendeka kwa urahisi na haki. Hapa ndivyo inavyofanya kazi kwa mifumo kama **Windows 2000** na **Windows Server 2003**:

* Kwanza, weka sheria zote zilizofanywa **kwa kusudi maalum kwa kipengee hiki** kabla ya zile zinazotoka mahali pengine, kama folda ya mzazi.
* Katika sheria hizo maalum, weka zile zinazosema **"hapana" (kukataa)** kabla ya zile zinazosema **"ndiyo" (kuruhusu)**.
* Kwa sheria zinazotoka mahali pengine, anza na zile kutoka kwa **chanzo kilicho karibu**, kama mzazi, na kisha endelea kutoka hapo. Tena, weka **"hapana"** kabla ya **"ndiyo."**

Hii inasaidia kwa njia mbili kuu:

* Inahakikisha kwamba ikiwa kuna **"hapana"** maalum, inaheshimiwa, bila kujali sheria zingine za **"ndiyo"** zilizopo.
* Inamruhusu mmiliki wa kitu kuwa na **maamuzi ya mwisho** kuhusu nani anaweza kuingia, kabla ya sheria kutoka kwenye folda za wazazi au nyuma yake kuanza kuchukua jukumu.

Kwa kufanya mambo kwa njia hii, mmiliki wa faili au folda anaweza kuwa makini sana kuhusu ni nani anapata ufikiaji, kuhakikisha watu sahihi wanaweza kuingia na wale wasio sahihi hawawezi.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Kwa hivyo, hii **"mpangilio wa kanoni"** ni kuhusu kuhakikisha sheria za ufikiaji zinaeleweka na kufanya kazi vizuri, kuweka sheria maalum kwanza na kuandaa kila kitu kwa njia yenye akili.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kiotomatiki** inayotumia zana za jamii za **juu kabisa** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### Mfano wa GUI

[**Mfano kutoka hapa**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Hii ni kichupo cha usalama cha kawaida cha folda kikionyesha ACL, DACL na ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Tukibonyeza **kitufe cha Kitaalam** tutapata chaguo zaidi kama urithi:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Na ukiongeza au kuhariri Mkuu wa Usalama:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Na mwisho tunayo SACL katika kichupo cha Ukaguzi:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Kuelezea Kudhibiti Upatikanaji kwa njia iliyorahisishwa

Tunapodhibiti upatikanaji wa rasilimali, kama folda, tunatumia orodha na sheria inayoitwa Orodha za Kudhibiti Upatikanaji (ACLs) na Vitu vya Kudhibiti Upatikanaji (ACEs). Hizi hufafanua ni nani anaweza au hawezi kupata data fulani.

#### Kukataa Upatikanaji kwa Kikundi Maalum

Fikiria una folda inayoitwa Gharama, na unataka kila mtu kuipata isipokuwa timu ya masoko. Kwa kuweka sheria sawa, tunaweza kuhakikisha kuwa timu ya masoko inakatazwa upatikanaji wazi kabla ya kuruhusu wengine wote. Hii hufanywa kwa kuweka sheria ya kukataa upatikanaji kwa timu ya masoko kabla ya sheria inayoruhusu upatikanaji kwa kila mtu mwingine.

#### Kuruhusu Upatikanaji kwa Mwanachama Maalum wa Kikundi Kilichokataliwa

Sema Bob, mkurugenzi wa masoko, anahitaji upatikanaji wa folda ya Gharama, ingawa kwa ujumla timu ya masoko haipaswi kupata. Tunaweza kuongeza sheria maalum (ACE) kwa Bob ambayo inamruhusu kupata, na kuweka kabla ya sheria inayokataza upatikanaji kwa timu ya masoko. Kwa njia hii, Bob anapata upatikanaji licha ya kizuizi cha jumla kwa timu yake.

#### Kuelewa Vitu vya Kudhibiti Upatikanaji

ACEs ni sheria binafsi katika ACL. Hizi hufafanua watumiaji au vikundi, hufafanua ni upatikanaji upi unaruhusiwa au kukataliwa, na kubainisha jinsi sheria hizi zinavyotumika kwa vitu vya chini (urithi). Kuna aina mbili kuu za ACEs:

* **ACEs za Kawaida**: Hizi zinafaa kwa ujumla, zikiathiri vitu vyote au kutofautisha tu kati ya vyombo (kama folda) na visivyo vyombo (kama faili). Kwa mfano, sheria inayoruhusu watumiaji kuona yaliyomo kwenye folda lakini sio kufikia faili ndani yake.
* **ACEs za Kipekee kwa Kitu**: Hizi hutoa udhibiti sahihi zaidi, kuruhusu sheria kuwekwa kwa aina maalum za vitu au hata mali binafsi ndani ya kitu. Kwa mfano, katika saraka ya watumiaji, sheria inaweza kuruhusu mtumiaji kusasisha nambari yake ya simu lakini sio masaa ya kuingia.

Kila ACE ina habari muhimu kama ni nani sheria inatumika (kwa kutumia Kitambulisho cha Usalama au SID), ni upatikanaji upi unaruhusiwa au kukataliwa (kwa kutumia kifuniko cha upatikanaji), na jinsi inavyorithiwa na vitu vingine.

#### Tofauti Kuu Kati ya Aina za ACE

* **ACEs za Kawaida** zinafaa kwa hali rahisi za kudhibiti upatikanaji, ambapo sheria sawa inatumika kwa vipengele vyote vya kitu au kwa vitu vyote ndani ya chombo.
* **ACEs za Kipekee kwa Kitu** hutumiwa kwa hali ngumu zaidi, hasa katika mazingira kama Active Directory, ambapo unaweza kuhitaji kudhibiti upatikanaji kwa mali maalum za kitu tofauti.

Kwa muhtasari, ACLs na ACEs husaidia kufafanua udhibiti sahihi wa upatikanaji, kuhakikisha kuwa watu au vikundi sahihi tu wanapata habari au rasilimali nyeti, na uwezo wa kubadilisha haki za upatikanaji hadi kiwango cha mali binafsi au aina za vitu.

### Mpangilio wa Kuingiza Kipengele cha Kudhibiti Upatikanaji

| Uga wa ACE | Maelezo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Aina        | Bendera inayoonyesha aina ya ACE. Windows 2000 na Windows Server 2003 hutoa msaada kwa aina sita za ACE: Aina tatu za kawaida za ACE ambazo zimeambatanishwa na vitu vyote vinavyoweza kudhibitiwa. Aina tatu za ACE za kipekee kwa vitu vya Active Directory.                                                                                                                                                                                                                                                            |
| Bendera     | Seti ya bendera za biti zinazodhibiti urithi na ukaguzi.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Ukubwa      | Idadi ya baiti za kumbukumbu zilizotengwa kwa ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Kifuniko cha upatikanaji | Thamani ya biti ya 32-bit ambayo biti zake zinaendana na haki za upatikanaji kwa kitu. Biti zinaweza kuwekwa au kuzimwa, lakini maana ya kuweka inategemea aina ya ACE. Kwa mfano, ikiwa biti inayolingana na haki ya kusoma ruhusu imewashwa, na aina ya ACE ni Kukataa, ACE inakataa haki ya kusoma ruhusu ya kitu. Ikiwa biti hiyo hiyo imezimwa lakini aina ya ACE ni Ruhusu, ACE inaruhusu haki ya kusoma ruhusu ya kitu. Maelezo zaidi ya Kifuniko cha Upatikanaji yanaonekana kwenye jedwali lifuatalo. |
| SID         | Inatambulisha mtumiaji au kikundi ambao upatikanaji wao unadhibitiwa au kufuatiliwa na ACE hii.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Mpangilio wa Kifuniko cha Upatikanaji

| Biti (Mfululizo) | Maana                            | Maelezo/Mfano                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Haki za Upatikanaji Maalum kwa Kitu      | Soma data, Tekeleza, Ongeza data           |
| 16 - 22     | Haki za Upatikanaji za Kawaida             | Futa, Andika ACL, Andika Mmiliki            |
| 23          | Inaweza kupata ACL ya usalama            |                                           |
| 24 - 27     | Imehifadhiwa                           |                                           |
| 28          | Kijumla Kote (Soma, Andika, Tekeleza) | Kila kitu chini                          |
| 29          | Tekeleza Kijumla                    | Vitu vyote vinavyohitajika kutekeleza programu |
| 30          | Andika Kijumla                      | Vitu vyote vinavyohitajika kuandika kwenye faili   |
| 31          | Soma Kijumla                       | Vitu vyote vinavyohitajika kusoma faili       |

## Marejeo

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)
