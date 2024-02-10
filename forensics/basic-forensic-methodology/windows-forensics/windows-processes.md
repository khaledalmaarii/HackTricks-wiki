<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite videti **oglašavanje vaše kompanije na HackTricks-u** ili **preuzeti HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


## smss.exe

**Session Manager**.\
Sesija 0 pokreće **csrss.exe** i **wininit.exe** (**OS** **servisi**), dok sesija 1 pokreće **csrss.exe** i **winlogon.exe** (**Korisnička** **sesija**). Međutim, trebali biste videti **samo jedan proces** te **izvršne datoteke** bez potomaka u stablu procesa.

Takođe, sesije osim 0 i 1 mogu značiti da se dešavaju RDP sesije.


## csrss.exe

**Client/Server Run Subsystem Process**.\
Upravlja **procesima** i **nitima**, čini **Windows** **API** dostupnim drugim procesima i takođe **mapira pogonska slova**, kreira **privremene datoteke** i upravlja **procesom za gašenje**.

Postoji jedan koji radi u sesiji 0 i još jedan u sesiji 1 (tako da ima **2 procesa** u stablu procesa). Još jedan se kreira **po novoj sesiji**.


## winlogon.exe

**Windows Logon Process**.\
Odgovoran je za prijavu/odjavu korisnika. Pokreće **logonui.exe** da zatraži korisničko ime i lozinku, a zatim poziva **lsass.exe** da ih proveri.

Zatim pokreće **userinit.exe** koji je naveden u **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** sa ključem **Userinit**.

Osim toga, prethodni registar treba da ima **explorer.exe** u **Shell ključu** ili se može zloupotrebiti kao **metoda za trajno prisustvo malvera**.


## wininit.exe

**Windows Initialization Process**. \
Pokreće **services.exe**, **lsass.exe** i **lsm.exe** u sesiji 0. Trebao bi postojati samo 1 proces.


## userinit.exe

**Userinit Logon Application**.\
Učitava **ntuser.dat u HKCU** i inicijalizuje **korisničko okruženje** i pokreće **logon skripte** i **GPO**.

Pokreće **explorer.exe**.


## lsm.exe

**Local Session Manager**.\
Sarađuje sa smss.exe da manipuliše korisničkim sesijama: prijava/odjava, pokretanje ljuske, zaključavanje/otključavanje radne površine, itd.

Nakon W7, lsm.exe je pretvoren u servis (lsm.dll).

Treba postojati samo 1 proces u W7 i od njih jedan servis koji pokreće DLL.


## services.exe

**Service Control Manager**.\
Učitava **servise** konfigurisane kao **auto-start** i **drajvere**.

To je nadređeni proces za **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** i mnoge druge.

Servisi su definisani u `HKLM\SYSTEM\CurrentControlSet\Services`, a ovaj proces održava bazu podataka u memoriji sa informacijama o servisu koju može pretraživati sc.exe.

Primetite kako će **neki servisi** raditi u **svom sopstvenom procesu** a drugi će **deliti svchost.exe proces**.

Treba postojati samo 1 proces.


## lsass.exe

**Local Security Authority Subsystem**.\
Odgovoran je za autentifikaciju korisnika i kreiranje **bezbednosnih tokena**. Koristi autentifikacione pakete smeštene u `HKLM\System\CurrentControlSet\Control\Lsa`.

Upisuje u **bezbednosni događajni zapis** i trebao bi postojati samo 1 proces.

Imajte na umu da je ovaj proces često napadan kako bi se izvukle lozinke.


## svchost.exe

**Generic Service Host Process**.\
Hostuje više DLL servisa u jednom deljenom procesu.

Obično ćete primetiti da se **svchost.exe** pokreće sa zastavicom `-k`. To će pokrenuti upit u registar **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** gde će biti ključ sa argumentom navedenim u -k koji će sadržati servise za pokretanje u istom procesu.

Na primer: `-k UnistackSvcGroup` će pokrenuti: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Ako se koristi i **zastavica `-s`** sa argumentom, tada se od svchost-a traži da **samo pokrene navedeni servis** u ovom argumentu.

Biće nekoliko procesa `svchost.exe`. Ako neki od njih **ne koristi zastavicu `-k`**, to je vrlo sumnjivo. Ako otkrijete da **services.exe nije roditelj**, to je takođe vrlo sumnjivo.


## taskhost.exe

Ovaj proces deluje kao domaćin za procese koji se pokreću iz DLL-ova. Takođe učitava servise koji se pokreću iz DLL-ova.

U W8 se naziva taskhostex.exe, a u W10 taskhostw.exe.


## explorer.exe

Ovo je proces odgovoran za **korisnički radnu površinu** i pokretanje datoteka putem ekstenzija.

Trebao bi biti pokrenut **samo 1** proces **po prijavljenom korisniku**.

Pokreće se iz **userinit.exe** koji bi trebao biti završen, tako da za ovaj proces **ne bi trebalo da postoji roditelj**.


# Otkrivanje zlonamernih procesa

* Pokreće li se iz očekivane putanje? (Nijedna Windows izvršna datoteka ne radi sa privremene lokacije)
* Da li komunicira sa čudnim IP adresama?
* Proverite digitalne potpise (Microsoft artefakti trebaju biti potpisani)
* Da li je pravilno napisano?
* Da li se izvršava pod očekivanim SID-om?
* Da li je roditeljski proces očekivani (ako postoji)?
* Da li su dečiji procesi očekivani? (nema cmd.exe, wscript.exe, powershell.exe..?)


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite videti **oglašavanje vaše kompanije na HackTricks-u** ili **preuzeti HackTricks u PDF formatu** proverite [**SUBSCRIPTION
