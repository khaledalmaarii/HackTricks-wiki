{% hint style="success" %}
Jifunze & zoezi AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}


## smss.exe

**Meneja wa Kikao**.\
Kikao 0 kinaanza **csrss.exe** na **wininit.exe** (**huduma za OS**) wakati Kikao 1 kinaanza **csrss.exe** na **winlogon.exe** (**Kikao cha Mtumiaji**). Walakini, unapaswa kuona **mchakato mmoja tu** wa **binary** hiyo bila watoto katika mti wa michakato.

Pia, vikao isipokuwa 0 na 1 vinaweza maanisha kuwa vikao vya RDP vinatokea.


## csrss.exe

**Mchakato wa Mteja/Mhudumu wa Mfumo wa Kukimbia**.\
Inasimamia **michakato** na **nyuzi**, inafanya **Windows** **API** ipatikane kwa michakato mingine na pia **inapanga barua za kuendesha gari**, inaunda **faili za muda**, na inashughulikia **mchakato wa kuzimwa**.

Kuna moja **inayoendesha katika Kikao 0 na nyingine katika Kikao 1** (kwa hivyo **michakato 2** katika mti wa michakato). Nyingine moja inaundwa **kwa kila Kikao kipya**.


## winlogon.exe

**Mchakato wa Kuingia kwenye Windows**.\
Inahusika na **kuingia**/**kutoka** kwa mtumiaji. Inazindua **logonui.exe** kuuliza jina la mtumiaji na nywila na kisha inaita **lsass.exe** kuvithibitisha.

Kisha inazindua **userinit.exe** ambayo imeainishwa katika **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** na funguo **Userinit**.

Zaidi ya hayo, usajili wa awali unapaswa kuwa na **explorer.exe** katika funguo ya **Shell** au inaweza kutumika kama **njia ya kudumu ya zisizo za programu hasidi**.


## wininit.exe

**Mchakato wa Kuanzisha Windows**. \
Inazindua **services.exe**, **lsass.exe**, na **lsm.exe** katika Kikao 0. Inapaswa kuwa mchakato mmoja tu.


## userinit.exe

**Programu ya Kuingia ya Mtumiaji**.\
Inapakia **ntduser.dat katika HKCU** na kuanzisha **mazingira ya mtumiaji** na kutekeleza **maandishi ya kuingia** na **GPO**.

Inazindua **explorer.exe**.


## lsm.exe

**Meneja wa Kikao cha Lokali**.\
Inafanya kazi na smss.exe kubadilisha vikao vya mtumiaji: Kuingia/kutoka, kuanza kwa kifaa cha kuingia, kufunga/kufuli desktop, n.k.

Baada ya W7 lsm.exe iligeuzwa kuwa huduma (lsm.dll).

Inapaswa kuwa mchakato mmoja tu katika W7 na kati yao huduma inayoendesha DLL.


## services.exe

**Meneja wa Udhibiti wa Huduma**.\
Ina **paki** **huduma** zilizoconfigure kama **kuanza moja kwa moja** na **madereva**.

Ni mchakato mzazi wa **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** na wengine wengi.

Huduma zimefafanuliwa katika `HKLM\SYSTEM\CurrentControlSet\Services` na mchakato huu unahifadhi DB kumbukumbu ya habari ya huduma ambayo inaweza kuulizwa na sc.exe.

Tambua jinsi **baadhi ya** **huduma** zitakuwa zinaendesha katika **mchakato wao wenyewe** na zingine zitakuwa **zinashiriki mchakato wa svchost.exe**.

Inapaswa kuwa mchakato mmoja tu.


## lsass.exe

**Mfumo wa Mamlaka wa Usalama wa Lokali**.\
Inahusika na **uthibitishaji** wa mtumiaji na kuunda **vitambulisho vya usalama**. Inatumia paketi za uthibitishaji zilizoko katika `HKLM\System\CurrentControlSet\Control\Lsa`.

Inaandika kwenye **tukio la usalama** na inapaswa kuwa mchakato mmoja tu.

Kumbuka kuwa mchakato huu unashambuliwa sana kwa kudondosha nywila.


## svchost.exe

**Mchakato wa Mwenyeji wa Huduma ya Kawaida**.\
Inahifadhi huduma nyingi za DLL katika mchakato mmoja ulioshirikiwa.

Kawaida, utaona kwamba **svchost.exe** inazinduliwa na bendera ya `-k`. Hii itazindua uchunguzi kwa usajili **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** ambapo kutakuwa na funguo na hoja iliyotajwa katika -k ambayo italeta huduma za kuzindua katika mchakato huo huo.

Kwa mfano: `-k UnistackSvcGroup` itazindua: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Ikiwa **bendera `-s`** pia inatumika na hoja, basi svchost inaulizwa **kuzindua huduma iliyotajwa tu** katika hoja hii.

Kutakuwa na michakato kadhaa ya `svchost.exe`. Ikiwa mojawapo yao **haifanyi matumizi ya bendera ya `-k`**, basi hiyo ni ya kutiliwa shaka sana. Ikiwa utagundua kwamba **services.exe sio mzazi**, hiyo pia ni ya kutiliwa shaka.


## taskhost.exe

Mchakato huu hufanya kama mwenyeji wa michakato inayoendeshwa kutoka kwa DLLs. Pia inapakia huduma zinazoendeshwa kutoka kwa DLLs.

Katika W8 hii inaitwa taskhostex.exe na katika W10 taskhostw.exe.


## explorer.exe

Huu ni mchakato unayehusika na **desktop ya mtumiaji** na kuzindua faili kupitia nyongeza za faili.

**Mchakato 1 tu** unapaswa kuundwa **kwa kila mtumiaji aliyeingia.**

Hii inaendeshwa kutoka kwa **userinit.exe** ambayo inapaswa kusitishwa, kwa hivyo **mzazi haitaonekana** kwa mchakato huu.


# Kukamata Michakato ya Kudhuru

* Je! Inaendeshwa kutoka kwenye njia inayotarajiwa? (Hakuna binaries za Windows zinaendeshwa kutoka eneo la muda)
* Je! Ina mawasiliano na anwani za IP za ajabu?
* Angalia saini za dijitali (artifacts za Microsoft zinapaswa kuwa zimesainiwa)
* Je! Imeandikwa kwa usahihi?
* Inaendeshwa chini ya SID inayotarajiwa?
* Je! Mchakato mzazi ni ule unaotarajiwa (ikiwa upo)?
* Je! Michakato ya watoto ni ile inayotarajiwa? (bila cmd.exe, wscript.exe, powershell.exe..?)


{% hint style="success" %}
Jifunze & zoezi AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
