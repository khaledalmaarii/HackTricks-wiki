# Tersine Mühendislik Araçları ve Temel Yöntemler

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni alın (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in bulunduğu koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**]'e (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**]'a (https://github.com/carlospolop/hacktricks-cloud) destek olun.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## ImGui Tabanlı Tersine Mühendislik Araçları

Yazılım:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat derleyici

Çevrimiçi:

* Wasm (ikili) dosyasını wat (açık metin) formatına **çözümlemek** için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
* Wat dosyasını wasm formatına derlemek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
* Ayrıca [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kullanarak çözümleme yapabilirsiniz

Yazılım:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **kütüphaneler** (.dll), **Windows meta veri dosyaları** (.winmd) ve **uygulamalar** (.exe) dahil olmak üzere **çeşitli formatları çözümleyen** bir dekompilerdir. Çözümlendikten sonra bir derleme, bir Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş bir kaynak kodunun eski bir derlemeden geri yüklenmesi gerekiyorsa, bu işlemin zaman kazandırabileceğidir. Ayrıca, dotPeek, çözümlenen kod boyunca kullanışlı gezinme sağlayarak, **Xamarin algoritma analizi için mükemmel araçlardan biri** haline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir eklenti modeli ve aracı tam olarak ihtiyaçlarınıza uyacak şekilde genişleten bir API ile .NET Reflector, zaman kazandırır ve geliştirmeyi basitleştirir. Bu aracın sağladığı birçok tersine mühendislik hizmetine bir göz atalım:

* Verilerin bir kütüphane veya bileşen üzerinden nasıl aktığına dair bir bakış açısı sağlar
* .NET dilleri ve çerçevelerinin uygulanışı ve kullanımı hakkında bilgi sağlar
* Kullanılan API'ler ve teknolojilerden daha fazla veri almak için belgelenmemiş ve açığa çıkarılmamış işlevsellikleri bulur
* Bağımlılıkları ve farklı derlemeleri bulur
* Kodunuzdaki hataların, üçüncü taraf bileşenlerin ve kütüphanelerin tam konumunu belirler
* Çalıştığınız tüm .NET kodunun kaynağına hata ayıklar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy eklentisi](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz, git'i indirmenize gerek yok. **Uzantılar**'a tıklayın ve **ILSpy**'ı **arama** yapın).\
Eğer **çözümlemek**, **değiştirmek** ve **yeniden derlemek** gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan bir çatalı olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyon içinde bir şeyi değiştirmek için **Sağ Tıkla -> Yöntemi Değiştir**).

### DNSpy Günlüğü

**DNSpy'nin bazı bilgileri bir dosyaya kaydetmesi** için bu kod parçacığını kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Hata Ayıklama

DNSpy kullanarak kodu hata ayıklamak için şunları yapmanız gerekmektedir:

İlk olarak, **hata ayıklama** ile ilgili **Derleme özniteliklerini** değiştirin:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
## Temel Tersine Mühendislik Araçları ve Yöntemleri

Bu bölümde, temel tersine mühendislik araçları ve yöntemleri hakkında bilgi bulacaksınız. Tersine mühendislik, bir programın veya dosyanın iç yapısını anlamak için kullanılan önemli bir tekniktir. Bu araçlar ve yöntemler, yazılımın nasıl çalıştığını anlamak ve potansiyel güvenlik açıklarını tespit etmek için kullanılır. Bu bölümde öğreneceğiniz bilgiler, yazılım geliştirme ve siber güvenlik alanlarında size büyük fayda sağlayacaktır.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Ve ardından **derle**'ye tıklayın:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Daha sonra yeni dosyayı _**Dosya >> Modülü Kaydet...**_ yolunu izleyerek kaydedin:

![](<../../.gitbook/assets/image (279).png>)

Bunu yapmanız gereklidir çünkü bunu yapmazsanız, **çalışma zamanında** kodunuza birkaç **optimizasyon** uygulanabilir ve **hata ayıklarken bir kesme noktasına ulaşılamayabilir** veya bazı **değişkenler mevcut olmayabilir**.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, onu şu şekilde **yeniden başlatabilirsiniz**:
```
iisreset /noforce
```
Ardından, hata ayıklamaya başlamak için tüm açık dosyaları kapatmalı ve **Debug Sekmesi** içinde **Attach to Process...**'i seçmelisiniz:

![](<../../.gitbook/assets/image (280).png>)

Daha sonra **w3wp.exe**'yi seçerek **IIS sunucusuna** bağlanın ve **attach**'e tıklayın:

![](<../../.gitbook/assets/image (281).png>)

Şimdi işlemi hata ayıklıyoruz, durdurma ve tüm modülleri yükleme zamanı. İlk olarak _Debug >> Break All_ üzerine tıklayın ve ardından _**Debug >> Windows >> Modules**_ üzerine tıklayın:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

**Modüller** üzerinde herhangi bir modüle tıklayın ve **Open All Modules**'i seçin:

![](<../../.gitbook/assets/image (284).png>)

**Assembly Explorer** içinde herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'i tıklayın:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Hata Ayıklama

### IDA Kullanarak

* **rundll32 yükle** (64 bitlik sürüm C:\Windows\System32\rundll32.exe ve 32 bitlik sürüm C:\Windows\SysWOW64\rundll32.exe)
* **Windbg hata ayıklayıcıyı seçin**
* "**Kütüphane yükleme/boşaltma duraklat**" seçin

![](<../../.gitbook/assets/image (135).png>)

* **Yürütmenin parametrelerini yapılandırın**, **DLL'nin yolunu** ve çağırmak istediğiniz **işlevi** belirterek:

![](<../../.gitbook/assets/image (136).png>)

Ardından, hata ayıklamaya başladığınızda **her DLL yüklendiğinde yürütme durdurulur**, sonra rundll32 DLL'nizi yüklediğinde yürütme durdurulur.

Ancak, yüklenen DLL'nin koduna nasıl ulaşabilirsiniz? Bu yöntemi kullanarak, bunu bilmiyorum.

### x64dbg/x32dbg Kullanarak

* **rundll32 yükle** (64 bitlik sürüm C:\Windows\System32\rundll32.exe ve 32 bitlik sürüm C:\Windows\SysWOW64\rundll32.exe)
* **Komut Satırını Değiştirin** ( _Dosya --> Komut Satırını Değiştir_ ) ve dll'nin yolunu ve çağırmak istediğiniz işlevi belirleyin, örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* _Ayarlar --> Ayarlar_ değiştirin ve "**DLL Girişi**"ni seçin.
* Ardından **yürütmeyi başlatın**, hata ayıklayıcı her dll ana noktasında duracak, bir noktada **dll Girişi'nde duracaksınız**. Oradan, kırılma noktalarını koymak istediğiniz noktaları arayın.

Yürütme herhangi bir nedenle durduğunda win64dbg'de **hangi kodda olduğunuzu** görebilirsiniz, **win64dbg penceresinin üst kısmına bakarak**:

![](<../../.gitbook/assets/image (137).png>)

Sonra, yürütmenin durduğu dll'yi hata ayıklamak istediğiniz noktayı görebilirsiniz.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmanıza ve değiştirmenize yardımcı olan faydalı bir programdır. Daha fazla bilgi için:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcode'lar

### Blobrunner ile bir shellcode'u hata ayıklama

[**Blobrunner**](https://github.com/OALabs/BlobRunner), **shellcode'u** bir bellek alanına **ayırır**, size shellcode'un **ayrıldığı bellek adresini gösterir** ve **yürütmeyi durdurur**.\
Daha sonra, bir **hata ayıklayıcıyı** (Ida veya x64dbg) işleme **bağlamanız** ve **belirtilen bellek adresine bir kırılma noktası koymalısınız** ve yürütmeyi **devam ettirmelisiniz**. Bu şekilde shellcode'u hata ayıklıyorsunuz.

Yayınlar github sayfasında derlenmiş sürümleri içeren zip dosyalarını içerir: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın hafif değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için sadece **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve derleyin**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### jmp2it ile bir shellcode'u hata ayıklama

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), blobrunner'a çok benzerdir. **Shellcode'u** bir bellek alanına **ayırır** ve bir **sonsuz döngü başlatır**. Daha sonra, işleme **hata ayıklayıcıyı bağlamanız**, **başlatmanız**, 2-5 saniye beklemeniz ve durdurmanız gerekecek ve kendinizi **sonsuz döngü içinde** bulacaksınız. Sonsuz döngünün bir sonraki talimatına atlayın çünkü bu shellcode'a bir çağrı olacaktır ve sonunda shellcode'u yürütürken bulacaksınız.

![](<../../.gitbook/assets/image (397).png>)

[Çıkış sayfasından derlenmiş bir sürümünü indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak bir shellcode'u hata ayıklama

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'nin GUI'sudur. Cutter'ı kullanarak shellcode'u emüle edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Dosya Aç" ve "Shellcode Aç" seçeneklerine izin verdiğini unutmayın. Benim durumumda, shellcode'u bir dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda yapamadı:

![](<../../.gitbook/assets/image (400).png>)

Başlamak istediğiniz yerde emülasyonu başlatmak için oraya bir bp ayarlayın ve görünüşe göre cutter otomatik olarak oradan emülasyona başlayacaktır:

![](<../../.gitbook/assets/image (399).png>)

Örneğin, bir onaltılık döküm içinde yığını görebilirsiniz:

![](<../../.gitbook/assets/image (402).png>)

### Shellcode'u deobfuscate etme ve yürütülen işlevleri almak

[**scdbg'yi** denemelisiniz](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Shellcode'un hangi işlevleri kullandığını ve shellcode'un bellekte kendini **çözüp çözmediğini** size söyleyecektir.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca seçtiğiniz seçenekleri belirleyip shellcode'ları yürütebileceğiniz grafiksel bir başlatıcıya sahiptir

![](<../../.gitbook/assets/image (398).png>)

**Create Dump** seçeneği, bellekte shellcode dinamik olarak değiştirilirse son shellcode'u döker (çözülmüş shellcode'u indirmek için faydalıdır). **Başlangıç ofseti** belirli bir ofsette shellcode'u başlatmak için faydalı olabilir. **Debug Shell** seçeneği, shellcode'u scDbg terminalini kullanarak hata ayıklamak için faydalıdır (ancak bu konuda açıklanan seçeneklerden herhangi birini daha iyi buluyorum çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef Kullanarak Disassembling

Shellcode dosyanızı giriş olarak yükleyin ve aşağıdaki tarifi kullanarak decompile edin: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, tüm `mov` komutları için talimatları değiştirir (evet, gerçekten harika). Ayrıca yürütme akışlarını değiştirmek için kesmeler kullanır. Nasıl çalıştığı hakkında daha fazla bilgi için:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Şanslıysanız [demovfuscator](https://github.com/kirschju/demovfuscator) ikili dosyayı açığa çıkaracaktır. Çeşitli bağımlılıkları bulunmaktadır
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [keystone'ı yükle](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oyununda, bayrağı bulmak için bu çözüm** çok faydalı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için `::main` gibi fonksiyonlara arama yapın:

![](<../../.gitbook/assets/image (612).png>)

Bu durumda ikili dosya authenticator olarak adlandırıldığı için ilginç ana fonksiyonun bu olduğu oldukça açıktır.\
**Çağrılan fonksiyonların isimlerine** sahip olarak, bunları **İnternet** üzerinde arayarak **girdileri** ve **çıktıları** hakkında bilgi edinin.

## **Delphi**

Delphi derlenmiş ikili dosyalar için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz

Bir Delphi ikili dosyasını tersine çevirmeniz gerekiyorsa, IDA eklentisini kullanmanızı öneririm [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Sadece **ATL+f7** tuşlarına basın (IDA'da python eklentisini içe aktarın) ve python eklentisini seçin.

Bu eklenti, hata ayıklamanın başlangıcında işlev adlarını dinamik olarak çözecek ve işlev adlarını çözecektir. Hata ayıklamaya başladıktan sonra tekrar Başlat düğmesine basın (yeşil olan veya f9) ve bir kesme noktası gerçek kodun başında olacaktır.

Ayrıca, grafik uygulamasında bir düğmeye bastığınızda hata ayıklayıcı, o düğme tarafından yürütülen işlevde duracaktır.

## Golang

Bir Golang ikili dosyasını tersine çevirmeniz gerekiyorsa, IDA eklentisini kullanmanızı öneririm [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Sadece **ATL+f7** tuşlarına basın (IDA'da python eklentisini içe aktarın) ve python eklentisini seçin.

Bu, işlevlerin adlarını çözecektir.

## Derlenmiş Python

Bu sayfada, bir ELF/EXE python derlenmiş ikili dosyasından python kodunu nasıl alacağınızı bulabilirsiniz:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Bir GBA oyununun **ikili** dosyasını aldıysanız, onu **emüle etmek** ve **hata ayıklamak** için farklı araçlar kullanabilirsiniz:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Hata ayıklama sürümünü indirin_) - Arayüzle birlikte bir hata ayıklayıcı içerir
* [**mgba** ](https://mgba.io)- Bir CLI hata ayıklayıcı içerir
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra eklentisi
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra eklentisi

[**no$gba**](https://problemkaputt.de/gba.htm)'da _**Options --> Emulation Setup --> Controls**_\*\* \*\* altında Game Boy Advance **düğmelerini** nasıl basacağınızı görebilirsiniz

![](<../../.gitbook/assets/image (578).png>)

Basıldığında, her **tuşun bir değeri** vardır ve bunu tanımlamak için:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Bu tür programlarda, ilginç olan kısım, programın kullanıcı girdisini nasıl işlediğidir. Adreste **0x4000130** sıkça bulunan **KEYINPUT** fonksiyonunu bulacaksınız.

![](<../../.gitbook/assets/image (579).png>)

Önceki görüntüde, fonksiyonun **FUN\_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

O fonksiyonda, bazı başlatma işlemlerinden sonra (önemsiz):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Bu kod bulundu:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Son if, **`uVar4`**'ün **son tuşlar** içinde olup olmadığını kontrol ediyor ve mevcut tuş değilse, yani bir düğmeye bırakılıyor (mevcut tuş **`uVar1`** içinde saklanır).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Önceki kodda, **uVar1** (basılan düğmenin değerinin bulunduğu yer) bazı değerlerle karşılaştırıldığını görebilirsiniz:

* İlk olarak, **değer 4** (**SEÇ** düğmesi) ile karşılaştırılır: Bu düğme meydan okumada ekranı temizler
* Ardından, **değer 8** (**BAŞLAT** düğmesi) ile karşılaştırılır: Bu meydan okumada bayrağı almak için kodun geçerli olup olmadığını kontrol eder.
* Bu durumda, **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
* Diğer durumlarda, bazı kontroller (`DAT_030000d4`) yapılır. Bu bir kontrol olduğundan, kod girdikten hemen sonra 1 eklenir.\
Eğer 8'den küçükse, **`DAT_030000d8`** değişkenine değerler **eklemeyi** içeren bir şey yapılır (temelde, kont 8'den küçük olduğu sürece bu değişkene basılan tuşların değerlerini ekliyor).

Bu meydan okumada, düğmelerin değerlerini bilerek, sonucunda toplamın 0xf3 olacağı 8'den küçük bir uzunluktaki bir kombinasyonu **basmanız gerekiyordu**.

**Bu öğretici için referans:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kurslar

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak** veya HackTricks'i **PDF olarak indirmek** istiyorsanız [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) takip edin.
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
