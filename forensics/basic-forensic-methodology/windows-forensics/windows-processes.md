<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslag.

</details>


## smss.exe

**Sessiebestuurder**.\
Sessie 0 begin **csrss.exe** en **wininit.exe** (**OS-dienste**) terwyl Sessie 1 **csrss.exe** en **winlogon.exe** (**Gebruiker-sessie**) begin. Jy behoort egter **slegs een proses** van daardie **binêre lêer** sonder kinders in die prosesseboom te sien.

Daarbenewens kan sessies anders as 0 en 1 beteken dat RDP-sessies plaasvind.


## csrss.exe

**Kliënt/Bediener Uitvoeringsondersteuningsproses**.\
Dit bestuur **prosesse** en **drade**, maak die **Windows API** beskikbaar vir ander prosesse en **koppel stuurprogramme aan**, skep **tydelike lêers**, en hanteer die **afsluitingsproses**.

Daar is een wat in Sessie 0 loop en nog een in Sessie 1 (dus **2 prosesse** in die prosesseboom). Nog een word geskep **per nuwe Sessie**.


## winlogon.exe

**Windows Aantekenproses**.\
Dit is verantwoordelik vir gebruiker **aanmelding**/**afmelding**. Dit begin **logonui.exe** om vir gebruikersnaam en wagwoord te vra en roep dan **lsass.exe** aan om dit te verifieer.

Daarna begin dit **userinit.exe** wat gespesifiseer word in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** met die sleutel **Userinit**.

Daarbenewens moet die vorige register **explorer.exe** in die **Shell-sleutel** hê, anders kan dit misbruik word as 'n **kwaadwillige volhardingsmetode**.


## wininit.exe

**Windows Inisialisasieproses**. \
Dit begin **services.exe**, **lsass.exe**, en **lsm.exe** in Sessie 0. Daar behoort slegs 1 proses te wees.


## userinit.exe

**Userinit Aanmeldingsprogram**.\
Laai die **ntuser.dat in HKCU** en inisialiseer die **gebruikersomgewing** en voer **aanmeldingskripte** en **GPO** uit.

Dit begin **explorer.exe**.


## lsm.exe

**Plaaslike Sessiebestuurder**.\
Dit werk saam met smss.exe om gebruikersessies te manipuleer: Aanmelding/afmelding, skerm begin, skerm sluit/ontsluit, ens.

Na W7 is lsm.exe omskep in 'n diens (lsm.dll).

Daar behoort slegs 1 proses in W7 te wees en daarvandaan 'n diens wat die DLL uitvoer.


## services.exe

**Diensbeheerder**.\
Dit **laai** **dienste** wat as **outomatiese aanvang** en **bestuurders** gekonfigureer is.

Dit is die ouerproses van **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** en nog baie meer.

Dienste word gedefinieer in `HKLM\SYSTEM\CurrentControlSet\Services` en hierdie proses onderhou 'n databasis in die geheue van diensinligting wat deur sc.exe ondervra kan word.

Let daarop hoe **sommige** **dienste** in 'n **eie proses** sal loop en ander sal 'n **svchost.exe-proses deel**.

Daar behoort slegs 1 proses te wees.


## lsass.exe

**Plaaslike Sekuriteitsowerheidsondersteuning**.\
Dit is verantwoordelik vir die gebruiker se **verifikasie** en skep die **sekuriteitstokens**. Dit gebruik verifikasiepakkette wat in `HKLM\System\CurrentControlSet\Control\Lsa` geleë is.

Dit skryf na die **Sekuriteit-gebeurtenislogboek** en daar behoort slegs 1 proses te wees.

Hou in gedagte dat hierdie proses hoogs aangeval word om wagwoorde te dump.


## svchost.exe

**Generiese Diensgasheerproses**.\
Dit bied onderdak aan verskeie DLL-dienste in een gedeelde proses.

Gewoonlik sal jy vind dat **svchost.exe** met die `-k` vlag geloods word. Dit sal 'n navraag na die register **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** loods waar daar 'n sleutel met die genoemde argument sal wees wat die dienste bevat wat in dieselfde proses geloods moet word.

Byvoorbeeld: `-k UnistackSvcGroup` sal loods: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

As die **vlag `-s`** ook saam met 'n argument gebruik word, word svchost gevra om **slegs die gespesifiseerde diens** in hierdie argument te loods.

Daar sal verskeie prosesse van `svchost.exe` wees. As een van hulle **nie die `-k` vlag gebruik nie**, is dit baie verdag. As jy vind dat **services.exe nie die ouerproses is nie**, is dit ook baie verdag.


## taskhost.exe

Hierdie proses tree op as 'n gasheer vir prosesse wat van DLL's loop. Dit laai ook die dienste wat van DLL's loop.

In W8 word dit taskhostex.exe genoem en in W10 taskhostw.exe.


## explorer.exe

Hierdie is die proses wat verantwoordelik is vir die **gebruiker se lessenaar** en die loods van lêers via lêeruitbreidings.

**Slegs 1** proses behoort **per aangemelde gebruiker** gegenereer te word.

Dit word uitgevoer vanaf **userinit.exe** wat beëindig moet word, sodat **geen ouerproses** vir hierdie proses moet verskyn nie.


# Vang kwaadwillige prosesse

* Loop dit vanaf die verwagte pad? (Geen Windows-binêre lêers loop vanaf 'n tydelike plek nie)
* Kommunikeer dit met vreemde IP-adresse?
* Kontroleer digitale handtekeninge (Microsoft-artefakte moet onderteken wees)
* Is dit korrek gespel?
* Loop dit onder die verwagte SID?
* Is die ouerproses die verwagte een (indien enige)?
* Is die kinderprosesse die verwagte (geen cmd.exe, wscript.exe, powershell.exe nie)?


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, ky
