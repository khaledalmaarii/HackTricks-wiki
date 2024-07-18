{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


## smss.exe

**Sessiebestuurder**.\
Sessie 0 begin **csrss.exe** en **wininit.exe** (**OS-diens**) terwyl Sessie 1 **csrss.exe** en **winlogon.exe** (**Gebruikersessie**) begin. Jy behoort egter **net een proses** van daardie **binêre** te sien sonder kinders in die prosesseboom.

Verder kan sessies anders as 0 en 1 beteken dat RDP-sessies plaasvind.


## csrss.exe

**Kliënt/Bediener Uitvoeringsondersteuningsproses**.\
Dit bestuur **prosesse** en **drade**, maak die **Windows-API** beskikbaar vir ander prosesse en ook **koppel stationsletters aan**, skep **tydelike lêers**, en hanteer die **afsluitingsproses**.

Daar is een wat in Sessie 0 hardloop en nog een in Sessie 1 (dus **2 prosesse** in die prosesseboom). Nog een word geskep **per nuwe Sessie**.


## winlogon.exe

**Windows Aanmeldingsproses**.\
Dit is verantwoordelik vir gebruiker **aanmeldings**/**afmeldings**. Dit begin **logonui.exe** om vir gebruikersnaam en wagwoord te vra en skakel dan **lsass.exe** in om dit te verifieer.

Daarna begin dit **userinit.exe** wat gespesifiseer is in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** met sleutel **Userinit**.

Daarbenewens behoort die vorige register **explorer.exe** in die **Shell-sleutel** te hê of dit kan misbruik word as 'n **malware volhardingsmetode**.


## wininit.exe

**Windows Inisialisasieproses**. \
Dit begin **services.exe**, **lsass.exe**, en **lsm.exe** in Sessie 0. Daar behoort net 1 proses te wees.


## userinit.exe

**Gebruikerinisialisasie Aanmeldingsprogram**.\
Laai die **ntduser.dat in HKCU** en inisialiseer die **gebruiker** **omgewing** en voer **aanmeldingskripte** en **GPO** uit.

Dit begin **explorer.exe**.


## lsm.exe

**Plaaslike Sessiebestuurder**.\
Dit werk saam met smss.exe om gebruikersessies te manipuleer: Aanmelding/afmelding, skerm begin, skerm sluit/ontsluit, ens.

Na W7 is lsm.exe omskep in 'n diens (lsm.dll).

Daar behoort net 1 proses in W7 te wees en van hulle 'n diens wat die DLL hardloop.


## services.exe

**Diensbeheerder**.\
Dit **laai** **dienste** wat as **outomatiese aanvang** en **bestuurders** gekonfigureer is.

Dit is die ouerproses van **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** en baie meer.

Dienste word gedefinieer in `HKLM\SYSTEM\CurrentControlSet\Services` en hierdie proses handhaaf 'n DB in die geheue van diensinligting wat deur sc.exe ondervra kan word.

Let op hoe **sommige** **dienste** in 'n **proses van hul eie** gaan hardloop en ander gaan **'n svchost.exe-proses deel**.

Daar behoort net 1 proses te wees.


## lsass.exe

**Plaaslike Sekuriteitsowerheidsondersteuning**.\
Dit is verantwoordelik vir die gebruiker **verifikasie** en skep die **sekuriteit** **tokens**. Dit gebruik verifikasiepakette wat in `HKLM\System\CurrentControlSet\Control\Lsa` geleë is.

Dit skryf na die **Sekuriteit** **gebeurtenis** **logboek** en daar behoort net 1 proses te wees.

Hou in gedagte dat hierdie proses hoogs aangeval word om wagwoorde te dump.


## svchost.exe

**Generiese Diensgasheerproses**.\
Dit bied gasheer aan meervoudige DLL-dienste in een gedeelde proses.

Gewoonlik sal jy vind dat **svchost.exe** met die `-k` vlag gelanseer word. Dit sal 'n navraag na die register **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** lanceer waar daar 'n sleutel met die genoemde argument in -k sal wees wat die dienste bevat om in dieselfde proses te lanceer.

Byvoorbeeld: `-k UnistackSvcGroup` sal lanceer: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

As die **vlag `-s`** ook met 'n argument gebruik word, word svchost gevra om **net die gespesifiseerde diens** in hierdie argument te lanceer.

Daar sal verskeie prosesse van `svchost.exe` wees. As enige van hulle **nie die `-k` vlag gebruik nie**, is dit baie verdag. As jy vind dat **services.exe nie die ouerproses is nie**, is dit ook baie verdag.


## taskhost.exe

Hierdie proses tree op as 'n gasheer vir prosesse wat van DLL's hardloop. Dit laai ook die dienste wat van DLL's hardloop.

In W8 word dit taskhostex.exe genoem en in W10 taskhostw.exe.


## explorer.exe

Dit is die proses wat verantwoordelik is vir die **gebruiker se lessenaar** en die aanvang van lêers via lêeruitbreidings.

**Net 1** proses behoort **per aangemelde gebruiker** gegenereer te word.

Dit word vanaf **userinit.exe** uitgevoer wat beëindig behoort te word, sodat **geen ouer** vir hierdie proses moet verskyn nie.


# Vangskadelike Prosesse

* Hardloop dit van die verwagte pad af? (Geen Windows-binêres hardloop vanaf 'n tydelike plek nie)
* Kommunikeer dit met vreemde IP-adresse?
* Kontroleer digitale handtekeninge (Microsoft-artefakte behoort onderteken te wees)
* Is dit korrek gespel?
* Hardloop dit onder die verwagte SID?
* Is die ouerproses die verwagte een (indien enige)?
* Is die kinderprosesse die verwagte (geen cmd.exe, wscript.exe, powershell.exe..?)?


{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
