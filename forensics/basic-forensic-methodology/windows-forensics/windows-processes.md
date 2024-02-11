<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


## smss.exe

**Meneja wa Kikao**.\
Kikao cha 0 kinaanza **csrss.exe** na **wininit.exe** (**huduma za OS**) wakati Kikao cha 1 kinaanza **csrss.exe** na **winlogon.exe** (**kikao cha mtumiaji**). Walakini, unapaswa kuona **mchakato mmoja tu** wa hiyo **binary** bila watoto katika mti wa michakato.

Pia, vikao visivyo vya 0 na 1 vinaweza kuashiria kuwa vikao vya RDP vinaendelea.


## csrss.exe

**Mchakato wa Subsystem ya Mteja/Mhudumu**.\
Inasimamia **michakato** na **nyuzi**, inafanya **Windows API** ipatikane kwa michakato mingine na pia **inamapisha barua za kuendesha gari**, inaunda **faili za muda**, na inashughulikia **mchakato wa kuzima**.

Kuna mmoja anayekimbia katika Kikao cha 0 na mwingine katika Kikao cha 1 (kwa hivyo **michakato 2** katika mti wa michakato). Mwingine mmoja huundwa **kwa kila Kikao kipya**.


## winlogon.exe

**Mchakato wa Ingia wa Windows**.\
Inahusika na **kuingia kwa mtumiaji**/**kutoka kwa mtumiaji**. Inazindua **logonui.exe** kuomba jina la mtumiaji na nenosiri na kisha inaita **lsass.exe** kuvithibitisha.

Kisha inazindua **userinit.exe** ambayo imeainishwa katika **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** na funguo **Userinit**.

Zaidi ya hayo, usajili uliotangulia unapaswa kuwa na **explorer.exe** katika funguo la **Shell** au inaweza kutumiwa kama **njia ya kudumu ya programu hasidi**.


## wininit.exe

**Mchakato wa Uzinduzi wa Windows**. \
Inazindua **services.exe**, **lsass.exe**, na **lsm.exe** katika Kikao cha 0. Inapaswa kuwa na mchakato mmoja tu.


## userinit.exe

**Programu ya Ingia ya Userinit**.\
Inapakia **ntduser.dat katika HKCU** na inaanzisha **mazingira ya mtumiaji** na inatekeleza **maandishi ya kuingia** na **GPO**.

Inazindua **explorer.exe**.


## lsm.exe

**Meneja wa Kikao cha Lokal**.\
Inafanya kazi na smss.exe kubadilisha vikao vya mtumiaji: Kuingia/kutoka, kuanza kwa kichupo, kufunga/kufungua kufungwa, nk.

Baada ya W7 lsm.exe iligeuzwa kuwa huduma (lsm.dll).

Inapaswa kuwa na mchakato mmoja tu katika W7 na kutoka kwao huduma inayotumia DLL.


## services.exe

**Meneja wa Udhibiti wa Huduma**.\
Ina **kuzaa** **huduma** zilizo **sanidiwa kama kuanza moja kwa moja** na **madereva**.

Ni mchakato mzazi wa **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** na wengine wengi.

Huduma zimefafanuliwa katika `HKLM\SYSTEM\CurrentControlSet\Services` na mchakato huu unahifadhi DB kumbukumbu ya habari ya huduma ambayo inaweza kuulizwa na sc.exe.

Tazama jinsi **baadhi ya huduma** **zitakuwa zikikimbia katika mchakato wao wenyewe** na zingine zitakuwa **zinafungua mchakato wa svchost.exe**.

Inapaswa kuwa na mchakato mmoja tu.


## lsass.exe

**Mamlaka ya Usalama wa Lokal**.\
Inahusika na **uthibitishaji** wa mtumiaji na kuunda **vitambulisho vya usalama**. Inatumia vifurushi vya uthibitishaji vilivyoko katika `HKLM\System\CurrentControlSet\Control\Lsa`.

Inaandika kwenye **tukio la usalama** **la usalama** na inapaswa kuwa na mchakato mmoja tu.

Kumbuka kuwa mchakato huu unashambuliwa sana ili kupata nywila.


## svchost.exe

**Mchakato Mwenyeji wa Huduma Mbadala**.\
Inahifadhi huduma nyingi za DLL katika mchakato mmoja ulioshirikiwa.

Kawaida, utagundua kuwa **svchost.exe** inazinduliwa na bendera ya `-k`. Hii itazindua uchunguzi kwenye usajili **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** ambapo kutakuwa na funguo na hoja iliyotajwa katika -k ambayo italeta huduma za kuzindua katika mchakato huo huo.

Kwa mfano: `-k UnistackSvcGroup` itazindua: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Ikiwa **bendera `-s`** pia inatumika na hoja, basi svchost inaulizwa **kuzindua huduma iliyoainishwa tu** katika hoja hii.

Kutakuwa na michakato kadhaa ya `svchost.exe`. Ikiwa yeyote wao **haifanyi matumizi ya bendera `-k`**, basi hiyo ni ya kutiliwa shaka sana. Ikiwa utagundua kuwa **services.exe sio mzazi**, hiyo pia ni ya kutiliwa shaka.


## taskhost.exe

Mchakato huu hufanya kama mwenyeji kwa michakato inayokimbia kutoka kwa DLL. Pia inapakia huduma zinazokimbia kutoka kwa DLL.

Katika W8 hii inaitwa taskhostex.exe na katika W10 taskhostw.exe.


## explorer.exe

Hii ndio mchakato unaohusika na **desktop ya mtumiaji** na kuzindua faili kupitia viendelezi vya faili.

**Mchakato 1 tu** unapaswa kuundwa **kwa kila mtumiaji aliyeingia**.

Hii inatekelezwa kutoka kwa **userinit.exe** ambayo inapaswa kufutwa, kwa hivyo **mzazi haitapaswi kuonekana** kwa mchakato huu.


# Kukamata Michak
