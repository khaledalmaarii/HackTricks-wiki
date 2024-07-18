# Vipengele vya Kuvutia vya Usajili wa Windows

### Vipengele vya Kuvutia vya Usajili wa Windows

{% hint style="success" %}
Jifunze & zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Aunga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

### **Toleo la Windows na Mmiliki wa Taarifa**
- Iko katika **`Software\Microsoft\Windows NT\CurrentVersion`**, utapata toleo la Windows, Pakiti ya Huduma, wakati wa usakinishaji, na jina la mmiliki aliyesajiliwa kwa njia rahisi.

### **Jina la Kompyuta**
- Jina la mwenyeji linapatikana chini ya **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Mipangilio ya Muda wa Eneo**
- Muda wa eneo la mfumo unahifadhiwa katika **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Ufuatiliaji wa Muda wa Kufikia**
- Kwa chaguo-msingi, ufuatiliaji wa muda wa mwisho wa ufikiaji umezimwa (**`NtfsDisableLastAccessUpdate=1`**). Ili kuwezesha, tumia:
`fsutil behavior set disablelastaccess 0`

### Toleo za Windows na Pakiti za Huduma
- **Toleo la Windows** linaonyesha toleo (k.m., Home, Pro) na kutolewa kwake (k.m., Windows 10, Windows 11), wakati **Pakiti za Huduma** ni sasisho zinazojumuisha marekebisho na, mara nyingine, vipengele vipya.

### Kuwezesha Muda wa Mwisho wa Kufikia
- Kuwezesha ufuatiliaji wa muda wa mwisho wa ufikiaji kunakuwezesha kuona lini faili zilifunguliwa mwisho, jambo ambalo linaweza kuwa muhimu kwa uchambuzi wa kiforensiki au ufuatiliaji wa mfumo.

### Maelezo ya Habari za Mtandao
- Usajili unashikilia data kubwa kuhusu mipangilio ya mtandao, ikiwa ni pamoja na **aina za mitandao (bila waya, kebo, 3G)** na **makundi ya mtandao (Umma, Binafsi/Nyumbani, Kikoa/Kazi)**, ambayo ni muhimu kwa kuelewa mipangilio ya usalama wa mtandao na ruhusa.

### Kache ya Upande wa Mteja (CSC)
- **CSC** inaboresha ufikiaji wa faili nje ya mtandao kwa kuhifadhi nakala za faili zilizoshirikiwa. Mipangilio tofauti ya **CSCFlags** inadhibiti jinsi na ni faili gani zilizohifadhiwa, ikiaathiri utendaji na uzoefu wa mtumiaji, hasa katika mazingira yenye mawasiliano ya muda mfupi.

### Programu za Kuanza Kiotomatiki
- Programu zilizoorodheshwa katika funguo mbalimbali za usajili za `Run` na `RunOnce` zinaanzishwa kiotomatiki wakati wa kuanza, zikiathiri wakati wa kuanza wa mfumo na kuwa vituo vya kuvutia kwa kutambua zisizo au programu zisizohitajika.

### Shellbags
- **Shellbags** si tu hifadhi mapendeleo ya maoni ya folda bali pia hutoa ushahidi wa kiforensiki wa ufikiaji wa folda hata kama folda haipo tena. Ni muhimu kwa uchunguzi, kufunua shughuli za mtumiaji ambazo si wazi kupitia njia nyingine.

### Habari na Uchunguzi wa USB
- Maelezo yaliyohifadhiwa katika usajili kuhusu vifaa vya USB vinaweza kusaidia kufuatilia ni vifaa vipi vilivyokuwa vimeunganishwa kwenye kompyuta, ikilinganisha kifaa na uhamisho wa faili nyeti au matukio ya ufikiaji usioruhusiwa.

### Nambari ya Serial ya Kiasi
- **Nambari ya Serial ya Kiasi** inaweza kuwa muhimu kufuatilia kipengele maalum cha mfumo wa faili, ikiwa ni muhimu katika mazingira ya kiforensiki ambapo asili ya faili inahitaji kubainishwa kati ya vifaa tofauti.

### **Maelezo ya Kuzimwa**
- Wakati wa kuzimwa na idadi (ya mwisho tu kwa XP) zinahifadhiwa katika **`System\ControlSet001\Control\Windows`** na **`System\ControlSet001\Control\Watchdog\Display`**.

### **Mipangilio ya Mtandao**
- Kwa maelezo ya kina ya interface ya mtandao, tazama **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Nyakati za kwanza na za mwisho za uunganisho wa mtandao, ikiwa ni pamoja na uunganisho wa VPN, zinahifadhiwa chini ya njia mbalimbali katika **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Folda Zilizoshirikiwa**
- Folda zilizoshirikiwa na mipangilio zinapatikana chini ya **`System\ControlSet001\Services\lanmanserver\Shares`**. Mipangilio ya Kache ya Upande wa Mteja (CSC) inadhibiti upatikanaji wa faili nje ya mtandao.

### **Programu Zinazoanza Kiotomatiki**
- Njia kama **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** na vipengele sawa chini ya `Software\Microsoft\Windows\CurrentVersion` hufafanua programu zilizowekwa kuanza kiotomatiki.

### **Utafutaji na Njia Zilizotumiwa**
- Utafutaji wa Explorer na njia zilizotumiwa zinachunguzwa katika usajili chini ya **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** kwa WordwheelQuery na TypedPaths, mtawalia.

### **Hati za Hivi Karibuni na Faili za Ofisi**
- Hati za hivi karibuni na faili za Ofisi zilizofikiwa zinaorodheshwa katika `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` na njia maalum za toleo la Ofisi.

### **Vitu Vilivyotumiwa Hivi Karibuni (MRU)**
- Orodha za MRU, zikionyesha njia za hivi karibuni za faili na amri, zinahifadhiwa katika funguo mbalimbali za chini ya `ComDlg32` na `Explorer` chini ya `NTUSER.DAT`.

### **Ufuatiliaji wa Shughuli za Mtumiaji**
- Kipengele cha User Assist kinahifadhi takwimu za matumizi ya programu kwa undani, ikiwa ni pamoja na idadi ya matumizi na wakati wa mwisho wa matumizi, katika **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Uchambuzi wa Shellbags**
- Shellbags, zinazoonyesha maelezo ya ufikiaji wa folda, zinahifadhiwa katika `USRCLASS.DAT` na `NTUSER.DAT` chini ya `Software\Microsoft\Windows\Shell`. Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** kwa uchambuzi.

### **Historia ya Vifaa vya USB**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** na **`HKLM\SYSTEM\ControlSet001\Enum\USB`** zina maelezo mengi kuhusu vifaa vya USB vilivyounganishwa, ikiwa ni pamoja na mtengenezaji, jina la bidhaa, na muda wa uunganisho.
- Mtumiaji aliyeunganishwa na kifaa maalum cha USB anaweza kubainishwa kwa kutafuta mizinga ya `NTUSER.DAT` kwa **{GUID}** ya kifaa.
- Kifaa kilichomount mwisho na nambari yake ya serial ya kiasi vinaweza kufuatiliwa kupitia `System\MountedDevices` na `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, mtawalia.

Mwongozo huu unakusanya njia muhimu na mbinu za kupata taarifa za kina za mfumo, mtandao, na shughuli za mtumiaji kwenye mifumo ya Windows, ukiwa na lengo la uwazi na matumizi rahisi.
