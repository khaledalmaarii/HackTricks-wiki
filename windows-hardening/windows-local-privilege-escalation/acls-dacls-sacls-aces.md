# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na kutekeleza kwa urahisi mchakato wa kazi ulioendeshwa na zana za jamii za juu zaidi duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Orodha ya Udhibiti wa Upatikanaji (ACL)**

Orodha ya Udhibiti wa Upatikanaji (ACL) inajumuisha seti iliyopangwa ya Vitambulisho vya Udhibiti wa Upatikanaji (ACEs) ambavyo vinadhibiti ulinzi wa kitu na mali zake. Kimsingi, ACL inaamua ni vitendo vipi vya watumiaji au vikundi vya usalama vinavyoruhusiwa au kukataliwa kwenye kitu kilichopewa.

Kuna aina mbili za ACL:

- **Orodha ya Udhibiti wa Upatikanaji wa Hiari (DACL):** Inaonyesha ni watumiaji na vikundi vipi vinavyo au havina upatikanaji wa kitu.
- **Orodha ya Udhibiti wa Upatikanaji wa Mfumo (SACL):** Inasimamia ukaguzi wa jaribio la upatikanaji wa kitu.

Mchakato wa kupata faili unahusisha mfumo kuangalia maelezo ya usalama ya kitu dhidi ya kitambulisho cha upatikanaji cha mtumiaji ili kubaini ikiwa upatikanaji unapaswa kuruhusiwa na kiwango cha upatikanaji huo, kulingana na ACEs.

### **Vipengele muhimu**

- **DACL:** Ina ACEs ambazo zinaruhusu au kukataa ruhusa za upatikanaji kwa watumiaji na vikundi kwenye kitu. Kimsingi, hii ni ACL kuu ambayo inaamua haki za upatikanaji.

- **SACL:** Hutumiwa kwa ukaguzi wa upatikanaji wa vitu, ambapo ACEs hufafanua aina za upatikanaji ambazo zitarekodiwa kwenye Kumbukumbu ya Tukio la Usalama. Hii inaweza kuwa muhimu sana katika kugundua jaribio la upatikanaji usiohalali au kutatua matatizo ya upatikanaji.

### **Mwingiliano wa Mfumo na ACLs**

Kila kikao cha mtumiaji kinaambatana na kitambulisho cha upatikanaji ambacho kina habari za usalama zinazohusiana na kikao hicho, ikiwa ni pamoja na mtumiaji, vitambulisho vya vikundi, na mamlaka. Kitambulisho hiki pia kinajumuisha SID ya kuingia ambayo inatambua kipekee kikao hicho.

Mamlaka ya Usalama ya Ndani (LSASS) inaprocess maombi ya upatikanaji wa vitu kwa kuchunguza DACL kwa ACEs ambazo zinafanana na kipekee cha usalama kinachotaka upatikanaji. Upatikanaji unaruhusiwa mara moja ikiwa hakuna ACEs zinazofaa. Vinginevyo, LSASS inalinganisha ACEs na SID ya kipekee ya usalama katika kitambulisho cha upatikanaji ili kubaini kustahiki upatikanaji.

### **Mchakato Uliosumuliwa**

- **ACLs:** Hufafanua ruhusa za upatikanaji kupitia DACLs na sheria za ukaguzi kupitia SACLs.
- **Kitambulisho cha Upatikanaji:** Kina habari za mtumiaji, vikundi, na mamlaka kwa kikao.
- **Uamuzi wa Upatikanaji:** Hufanywa kwa kulinganisha ACEs za DACL na kitambulisho cha upatikanaji; SACLs hutumiwa kwa ukaguzi.

### ACEs

Kuna **aina tatu kuu za Vitambulisho vya Udhibiti wa Upatikanaji (ACEs)**:

- **ACE ya Kukataa Upatikanaji**: ACE hii inakataza wazi upatikanaji wa kitu kwa watumiaji au vikundi vilivyotajwa (katika DACL).
- **ACE ya Kuruhusu Upatikanaji**: ACE hii inaruhusu wazi upatikanaji wa kitu kwa watumiaji au vikundi vilivyotajwa (katika DACL).
- **ACE ya Ukaguzi wa Mfumo**: Iliyowekwa ndani ya Orodha ya Udhibiti wa Upatikanaji wa Mfumo (SACL), ACE hii inawajibika kuzalisha kumbukumbu za ukaguzi wakati wa jaribio la upatikanaji wa kitu na watumiaji au vikundi. Inaandika ikiwa upatikanaji uliruhusiwa au kukataliwa na asili ya upatikanaji.

Kila ACE ina **vipengele vinne muhimu**:

1. **Kitambulisho cha Usalama (SID)** cha mtumiaji au kikundi (au jina la mkuu wao katika uwakilishi wa picha).
2. **Bendera** inayotambulisha aina ya ACE (kukataa upatikanaji, kuruhusu upatikanaji, au ukaguzi wa mfumo).
3. **Bendera za Urithi** ambazo zinaamua ikiwa vitu vya watoto vinaweza kurithi ACE kutoka kwa mzazi wao.
4. **Kifuniko cha upatikanaji**, thamani ya biti 32 inayoelezea haki zilizopewa kitu.

Uamuzi wa upatikanaji unafanywa kwa kuchunguza kwa utaratibu kila ACE hadi:

- ACE ya **Kukataa Upatikanaji** inakataza wazi haki zilizoombwa kwa wakala aliyetambuliwa katika kitambulisho cha upatikanaji.
- ACE ya **Kuruhusu Upatikanaji** inaruhusu wazi haki zote zilizoombwa kwa wakala katika kitambulisho cha upatikanaji.
- Baada ya kuchunguza ACE zote, ikiwa haki yoyote iliyotakiwa haijaruhusiwa wazi, upatikanaji unakataliwa kwa njia ya kutoeleweka.

### Mpangilio wa ACEs

Njia ambayo **ACEs** (kanuni zinazosema ni nani anaweza au hawezi kupata kitu) zinawekwa kwenye orodha inayoitwa **DACL** ni muhimu sana. Hii ni kwa sababu
### Mfano wa GUI

**[Mfano kutoka hapa](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Hii ni kichupo cha usalama cha kawaida cha folda kinachoonyesha ACL, DACL, na ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Ikiwa tunabonyeza **kitufe cha Advanced**, tutapata chaguo zaidi kama urithi:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Na ikiwa unaweka au kuhariri Mkuu wa Usalama:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Na mwisho tunayo SACL katika kichupo cha Ukaguzi:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Kuelezea Udhibiti wa Upatikanaji kwa Njia Rahisi

Tunapodhibiti upatikanaji wa rasilimali, kama folda, tunatumia orodha na sheria zinazojulikana kama Orodha za Udhibiti wa Upatikanaji (ACLs) na Vitambulisho vya Udhibiti wa Upatikanaji (ACEs). Hizi zinafafanua ni nani anaweza au hawezi kupata data fulani.

#### Kukataa Upatikanaji kwa Kikundi Maalum

Fikiria una folda inayoitwa Gharama, na unataka kila mtu kuipata isipokuwa timu ya masoko. Kwa kuweka sheria kwa usahihi, tunaweza kuhakikisha kuwa timu ya masoko inakatazwa kupata kabla ya kuruhusu wengine wote. Hii inafanywa kwa kuweka sheria ya kukataa upatikanaji kwa timu ya masoko kabla ya sheria ya kuruhusu upatikanaji kwa kila mtu.

#### Kuruhusu Upatikanaji kwa Mwanachama Maalum wa Kikundi Kilichokataliwa

Sema Bob, mkurugenzi wa masoko, anahitaji kupata folda ya Gharama, ingawa kwa ujumla timu ya masoko haipaswi kupata. Tunaweza kuongeza sheria maalum (ACE) kwa Bob ambayo inampa upatikanaji, na kuweka kabla ya sheria ya kukataa upatikanaji kwa timu ya masoko. Kwa njia hii, Bob anapata upatikanaji licha ya kizuizi cha jumla kwa timu yake.

#### Kuelewa Vitambulisho vya Udhibiti wa Upatikanaji

ACEs ni sheria binafsi katika ACL. Zinafafanua watumiaji au vikundi, hufafanua upatikanaji unaoruhusiwa au kukataliwa, na kubainisha jinsi sheria hizi zinaomba kwa vitu vingine (urithi). Kuna aina mbili kuu za ACEs:

- **ACEs za Kawaida**: Hizi zinaomba kwa ujumla, zikiathiri vitu vyote au kufanya tofauti kati ya vyombo (kama folda) na sio-vyombo (kama faili). Kwa mfano, sheria inayoruhusu watumiaji kuona yaliyomo kwenye folda lakini sio kufikia faili zilizomo.

- **ACEs za Kipekee kwa Vitu**: Hizi zinatoa udhibiti sahihi zaidi, kuruhusu sheria kuwekwa kwa aina maalum za vitu au hata mali binafsi ndani ya kipengele. Kwa mfano, katika saraka ya watumiaji, sheria inaweza kuruhusu mtumiaji kusasisha nambari yao ya simu lakini sio masaa ya kuingia.

Kila ACE ina habari muhimu kama ni nani sheria inatumika (kwa kutumia Kitambulisho cha Usalama au SID), ni nini sheria inaruhusu au kukataa (kwa kutumia kinyonge cha upatikanaji), na jinsi inavyorithiwa na vitu vingine.

#### Tofauti Kuu Kati ya Aina za ACE

- **ACEs za Kawaida** zinafaa kwa hali rahisi za udhibiti wa upatikanaji, ambapo sheria ile ile inatumika kwa vipengele vyote vya kipengele au kwa vitu vyote ndani ya chombo.

- **ACEs za Kipekee kwa Vitu** hutumiwa kwa hali ngumu zaidi, haswa katika mazingira kama Active Directory, ambapo unaweza kuhitaji kudhibiti upatikanaji kwa mali maalum za kipengele tofauti.

Kwa muhtasari, ACLs na ACEs husaidia kufafanua udhibiti sahihi wa upatikanaji, kuhakikisha kuwa watu au vikundi sahihi tu wanapata habari au rasilimali nyeti, na uwezo wa kubinafsisha haki za upatikanaji hadi kiwango cha mali binafsi au aina za vitu.

### Muundo wa Kuingia Udhibiti wa Upatikanaji

| Uga wa ACE | Maelezo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Aina        | Bendera inayoonyesha aina ya ACE. Windows 2000 na Windows Server 2003 inasaidia aina sita za ACE: Aina tatu za kawaida za ACE ambazo zimeambatishwa kwa vitu vyote vinavyoweza kusimamiwa. Aina tatu za ACE maalum za vitu ambazo zinaweza kutokea kwa vitu vya Active Directory.                                                                                                                                                                                                                                                            |
| Bendera     | Seti ya bendera za biti ambazo zinaongoza urithi na ukaguzi.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Ukubwa      | Idadi ya bayti za kumbukumbu zilizotengwa kwa ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Kinyonge cha upatikanaji | Thamani ya biti 32 ambazo zinaambatana na haki za upatikanaji kwa kipengele. Biti zinaweza kuwekwa au kuzimwa, lakini maana ya mipangilio inategemea aina ya ACE. Kwa mfano, ikiwa biti inayolingana na haki ya kusoma ruhusu imezimwa, na aina ya ACE ni Kukataa, ACE inakataa haki ya kusoma ruhusu ya kipengele. Ikiwa biti hiyo hiyo imezimwa lakini aina ya ACE ni Kuruhusu, ACE inaruhusu haki ya kusoma ruhusu ya kipengele. Maelezo zaidi ya Kinyonge cha upatikanaji yanaonekana kwenye jedwali lifuatalo. |
| SID         | Inatambua mtumiaji au kikundi ambao upatikanaji wao unadhibitiwa au kufuatiliwa na ACE hii.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Muundo wa Kinyonge cha Upatikanaji

| Biti (Upeo) | Maana                              | Maelezo/Mfano                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Haki za Upatikanaji za Kipekee za Kipengele      | Soma data, Tekeleza, Ongeza data           |
| 16 - 22     | Haki za Upatikanaji za Kawaida             | Futa, Andika ACL, Andika Mmiliki            |
| 23          | Inaweza kufikia ACL ya usalama            |                                           |
| 24 - 27     | Imehifadhiwa                           |                                           |
| 28          | Kipekee YOTE (Soma, Andika, Tekeleza) | Kila kitu chini                          |
| 29          | Kipekee Tekeleza                    | Vitu vyote vinavyohitajika kutekeleza programu |
| 30          | Kipekee Andika                      | Vitu vyote vinavyohitajika kuandika kwenye faili   |
| 31          | Kipekee Soma                       | Vitu vyote vinavyohitajika kusoma faili       |

## Marejeo

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://
