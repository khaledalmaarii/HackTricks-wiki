{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


## smss.exe

**Session Manager**.\
Sesija 0 pokreće **csrss.exe** i **wininit.exe** (**OS** **servisi**), dok sesija 1 pokreće **csrss.exe** i **winlogon.exe** (**Korisnička** **sesija**). Međutim, trebalo bi da vidite **samo jedan proces** te **binarne datoteke bez podprocesa u stablu procesa**.

Takođe, sesije osim 0 i 1 mogu značiti da se dešavaju RDP sesije.


## csrss.exe

**Client/Server Run Subsystem Process**.\
Upravlja **procesima** i **nitima**, čini **Windows** **API** dostupnim drugim procesima i takođe **mapira slova drajva**, kreira **privremene datoteke** i rukuje **procesom gašenja**.

Jedan se **pokreće u Sesiji 0, a drugi u Sesiji 1** (tako da ima **2 procesa** u stablu procesa). Još jedan se kreira **po novoj sesiji**.


## winlogon.exe

**Windows Logon Process**.\
Odgovoran je za korisničke **prijave**/**odjave**. Pokreće **logonui.exe** da zatraži korisničko ime i lozinku, a zatim poziva **lsass.exe** da ih proveri.

Zatim pokreće **userinit.exe** koji je naveden u **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** sa ključem **Userinit**.

Pomerajte se, prethodni registar bi trebalo da ima **explorer.exe** u **Shell ključu** ili bi mogao biti zloupotrebljen kao **metoda za trajno prisustvo malvera**.


## wininit.exe

**Windows Initialization Process**. \
Pokreće **services.exe**, **lsass.exe** i **lsm.exe** u Sesiji 0. Trebalo bi da postoji samo 1 proces.


## userinit.exe

**Userinit Logon Application**.\
Učitava **ntduser.dat u HKCU** i inicijalizuje **korisničko** **okruženje** i pokreće **logon** **skripte** i **GPO**.

Pokreće **explorer.exe**.


## lsm.exe

**Local Session Manager**.\
Sarađuje sa smss.exe da manipuliše korisničkim sesijama: Prijavljivanje/odjavljivanje, pokretanje školjke, zaključavanje/otključavanje radne površine, itd.

Nakon W7, lsm.exe je transformisan u servis (lsm.dll).

Trebalo bi da postoji samo 1 proces u W7 i od njih servis koji pokreće DLL.


## services.exe

**Service Control Manager**.\
**Učitava** **servise** konfigurisane kao **automatsko pokretanje** i **drajvere**.

To je roditeljski proces za **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** i mnoge druge.

Servisi su definisani u `HKLM\SYSTEM\CurrentControlSet\Services` i ovaj proces održava bazu podataka u memoriji informacija o servisu koja se može upitati pomoću sc.exe.

Primetite kako će **neki** **servisi** biti pokrenuti u **svom procesu** dok će drugi biti **deljeni u svchost.exe procesu**.

Trebalo bi da postoji samo 1 proces.


## lsass.exe

**Local Security Authority Subsystem**.\
Odgovoran je za autentifikaciju korisnika i stvaranje **sigurnosnih** **tokena**. Koristi autentifikacione pakete smeštene u `HKLM\System\CurrentControlSet\Control\Lsa`.

Upisuje u **bezbednosni** **događajni** **log** i trebalo bi da postoji samo 1 proces.

Imajte na umu da je ovaj proces često meta napada za iskopavanje lozinki.


## svchost.exe

**Generic Service Host Process**.\
Hostuje više DLL servisa u jednom deljenom procesu.

Obično ćete primetiti da je **svchost.exe** pokrenut sa zastavicom `-k`. Ovo će pokrenuti upit u registar **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** gde će biti ključ sa navedenim argumentom u -k koji će sadržati servise za pokretanje u istom procesu.

Na primer: `-k UnistackSvcGroup` će pokrenuti: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Ako se koristi i **zastavica `-s`** sa argumentom, tada se od svchosta traži da **samo pokrene navedeni servis** u ovom argumentu.

Biće nekoliko procesa `svchost.exe`. Ako neki od njih **ne koristi zastavicu `-k`**, to je veoma sumnjivo. Ako otkrijete da **services.exe nije roditelj**, to je takođe veoma sumnjivo.


## taskhost.exe

Ovaj proces deluje kao domaćin za procese koji se pokreću iz DLL-ova. Takođe učitava servise koji se pokreću iz DLL-ova.

U W8 se naziva taskhostex.exe, a u W10 taskhostw.exe.


## explorer.exe

Ovo je proces odgovoran za **korisničku radnu površinu** i pokretanje datoteka putem ekstenzija datoteka.

**Samo 1** proces bi trebalo da bude pokrenut **po prijavljenom korisniku.**

Ovo se pokreće iz **userinit.exe** koji bi trebalo da bude završen, tako da **ne bi trebalo da se pojavi roditelj** za ovaj proces.


# Hvatanje zlonamernih procesa

* Da li se pokreće sa očekivane putanje? (Windows binarne datoteke ne pokreću se sa privremene lokacije)
* Da li komunicira sa čudnim IP adresama?
* Proverite digitalne potpise (Microsoft artefakti trebalo bi da budu potpisani)
* Da li je ispravno napisan?
* Da li se pokreće pod očekivanim SID-om?
* Da li je roditeljski proces očekivan (ako postoji)?
* Da li su dečiji procesi očekivani? (nema cmd.exe, wscript.exe, powershell.exe..?)


{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
