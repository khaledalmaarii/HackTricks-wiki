# Funguo za Usajili za Windows Zinazovutia

### Funguo za Usajili za Windows Zinazovutia

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


### **Toleo la Windows na Habari ya Mmiliki**
- Iko katika **`Software\Microsoft\Windows NT\CurrentVersion`**, utapata toleo la Windows, Pakiti ya Huduma, wakati wa usakinishaji, na jina la mmiliki aliyesajiliwa kwa njia rahisi.

### **Jina la Kompyuta**
- Jina la mwenyeji linapatikana chini ya **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Mipangilio ya Muda wa Eneo**
- Muda wa eneo la mfumo unahifadhiwa katika **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Ufuatiliaji wa Wakati wa Kufikia**
- Kwa chaguo-msingi, ufuatiliaji wa wakati wa kufikia wa mwisho umezimwa (**`NtfsDisableLastAccessUpdate=1`**). Ili kuwezesha, tumia:
`fsutil behavior set disablelastaccess 0`

### Matoleo ya Windows na Pakiti za Huduma
- **Toleo la Windows** linaonyesha toleo (k.m., Home, Pro) na kutolewa kwake (k.m., Windows 10, Windows 11), wakati **Pakiti za Huduma** ni sasisho zinazojumuisha marekebisho na, mara nyingine, vipengele vipya.

### Kuwezesha Ufuatiliaji wa Wakati wa Kufikia
- Kuwezesha ufuatiliaji wa wakati wa kufikia wa mwisho kunakuwezesha kuona wakati faili zilifunguliwa mara ya mwisho, ambayo inaweza kuwa muhimu kwa uchambuzi wa kisayansi au ufuatiliaji wa mfumo.

### Maelezo ya Habari za Mtandao
- Usajili una data nyingi juu ya mipangilio ya mtandao, ikiwa ni pamoja na **aina za mitandao (isiyo na waya, kebo, 3G)** na **makundi ya mtandao (Umma, Binafsi/Nyumbani, Kikoa/Kazi)**, ambayo ni muhimu kwa kuelewa mipangilio ya usalama wa mtandao na ruhusa.

### Kache ya Upande wa Mteja (CSC)
- **CSC** inaboresha ufikiaji wa faili nje ya mtandao kwa kuhifadhi nakala za faili zilizoshirikiwa. Mipangilio tofauti ya **CSCFlags** inadhibiti jinsi na ni faili gani zinazohifadhiwa kwenye kache, ikiaathiri utendaji na uzoefu wa mtumiaji, hasa katika mazingira yenye uunganisho wa muda mfupi.

### Programu Zinazoanza Kiotomatiki
- Programu zilizoorodheshwa katika funguo mbalimbali za usajili za `Run` na `RunOnce` zinaanzishwa kiotomatiki wakati wa kuanza, zikiathiri wakati wa kuanza wa mfumo na kuwa hatua muhimu za kutambua programu hasidi au programu zisizohitajika.

### Shellbags
- **Shellbags** sio tu hifadhi mapendeleo ya maoni ya folda lakini pia hutoa ushahidi wa kisayansi wa ufikiaji wa folda hata ikiwa folda haipo tena. Ni muhimu kwa uchunguzi, kufunua shughuli za mtumiaji ambazo hazionekani kwa njia nyingine.

### Habari na Uchunguzi wa USB
- Maelezo yaliyohifadhiwa kwenye usajili kuhusu vifaa vya USB vinaweza kusaidia kufuatilia ni vifaa vipi vilivyokuwa vimeunganishwa kwenye kompyuta, na hivyo kuunganisha kifaa na uhamisho wa faili nyeti au matukio ya ufikiaji usioruhusiwa.

### Nambari ya Serial ya Kiasi
- **Nambari ya Serial ya Kiasi** inaweza kuwa muhimu kufuatilia kesi maalum ya mfumo wa faili, inayoweza kutumika katika mazingira ya kisayansi ambapo asili ya faili inahitaji kubainishwa kwenye vifaa tofauti.

### **Maelezo ya Kuzima**
- Wakati wa kuzima na idadi (kwa XP tu) zinahifadhiwa katika **`System\ControlSet001\Control\Windows`** na **`System\ControlSet001\Control\Watchdog\Display`**.

### **Usanidi wa Mtandao**
- Kwa habari ya kina ya interface ya mtandao, tazama **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Wakati wa kwanza na wa mwisho wa uunganisho wa mtandao, ikiwa ni pamoja na uunganisho wa VPN, zimeorodheshwa chini ya njia mbalimbali katika **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Folda Zilizoshirikiwa**
- Folda zilizoshirikiwa na mipangilio ziko chini ya **`System\ControlSet001\Services\lanmanserver\Shares`**. Mipangilio ya Kache ya Upande wa Mteja (CSC) inaamua upatikanaji wa faili nje ya mtandao.

### **Programu Zinazoanza Kiotomatiki**
- Njia kama **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** na vitu sawa chini ya `Software\Microsoft\Windows\CurrentVersion` hufafanua programu zilizowekwa kuanza wakati wa kuanza.

### **Utafutaji na Njia Zilizotumiwa**
- Utafutaji wa Explorer na njia zilizotumiwa zinafuatiliwa kwenye usajili chini ya **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** kwa WordwheelQuery na TypedPaths, mtawalia.

### **Hati za Hivi Karibuni na Faili za Ofisi**
- Hati za hivi karibuni na faili za Ofisi zilizofikiwa zimeorodheshwa katika `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` na njia maalum za toleo la Ofisi.

### **Vitu Vilivyotumiwa Hivi Karibuni (MRU)**
- Orodha za MRU, zikionyesha njia za hivi karibuni za faili na amri, zimehifadhiwa kat
