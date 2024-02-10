# Tersine Mühendislik Araçları ve Temel Yöntemler

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## ImGui Tabanlı Tersine Mühendislik Araçları

Yazılım:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Çevrimiçi:

* Wasm (binary) dosyasını wat (açık metin) dosyasına **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
* Wat dosyasını wasm dosyasına **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
* decompile için [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kullanmayı deneyebilirsiniz

Yazılım:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **kütüphaneler** (.dll), **Windows meta veri dosyaları** (.winmd) ve **yürütülebilir dosyalar** (.exe) dahil olmak üzere **çeşitli formatları decompile eder ve incelemeler**. Bir derleme decompile edildikten sonra, bir Visual Studio projesi (.csproj) olarak kaydedilebilir.

Bu, kaybolan bir kaynak kodunun eski bir derlemeden geri yüklenmesi gerektiğinde zaman kazandırır. Ayrıca, dotPeek, decompile edilen kod boyunca kullanışlı gezinme sağlar, bu da onu **Xamarin algoritma analizi için mükemmel araçlardan biri yapar.**

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir eklenti modeline ve aracı tam olarak ihtiyaçlarınıza uyacak şekilde genişleten bir API'ye sahip olan .NET reflector, zaman kazandırır ve geliştirmeyi basitleştirir. Bu aracın sağladığı birçok tersine mühendislik hizmetine bir göz atalım:

* Bir kütüphane veya bileşen üzerinden verinin nasıl aktığına dair bir içgörü sağlar
* .NET dilleri ve çerçevelerinin uygulanması ve kullanımı hakkında bilgi sağlar
* Kullanılan API'ler ve teknolojilerden daha fazla verim almak için belgelenmemiş ve açığa çıkarılmamış işlevselliği bulur.
* Bağımlılıkları ve farklı derlemeleri bulur
* Kodunuzdaki hataların, üçüncü taraf bileşenlerin ve kütüphanelerin tam konumunu bulur.
* Çalıştığınız tüm .NET kodunun kaynağına hata ayıklama yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy eklentisi](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz, git'i indirmenize gerek yok. **Extensions** üzerine tıklayın ve **ILSpy** arayın).\
**Decompile**, **değiştir** ve **yeniden derle** ihtiyacınız varsa: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Sağ Tıkla -> Modify Method** ile bir fonksiyonun içinde bir şeyi değiştirebilirsiniz).\
Ayrıca [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/) adresini deneyebilirsiniz.

### DNSpy Logging

**DNSpy'ın bazı bilgileri bir dosyaya kaydetmesi** için bu .Net satırlarını kullanabilirsiniz:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Hata Ayıklama

DNSpy kullanarak kodu hata ayıklamak için şunları yapmanız gerekmektedir:

İlk olarak, **hata ayıklama** ile ilgili **Assembly özelliklerini** değiştirin:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
/hive/hacktricks/reversing/reversing-tools-basic-methods/README.md

# Reversing Tools - Basic Methods

## Introduction

In the field of reverse engineering, there are several tools that can be used to analyze and understand the inner workings of software. This guide provides an overview of some of the basic methods and tools commonly used in reverse engineering.

## Static Analysis

Static analysis involves examining the binary code of a program without actually executing it. This can be done using tools such as disassemblers and decompilers. Disassemblers convert the binary code into assembly language, making it easier to understand and analyze. Decompilers, on the other hand, convert the binary code into a higher-level programming language, such as C or C++, allowing for a more comprehensive analysis.

## Dynamic Analysis

Dynamic analysis involves executing the program and monitoring its behavior in real-time. This can be done using tools such as debuggers and dynamic analysis frameworks. Debuggers allow for step-by-step execution of the program, making it possible to analyze the program's state at different points in time. Dynamic analysis frameworks provide a more automated approach, allowing for the collection of runtime information and the detection of vulnerabilities or malicious behavior.

## Memory Analysis

Memory analysis involves examining the memory of a running program to understand its behavior and extract useful information. This can be done using tools such as memory dumpers and memory forensics frameworks. Memory dumpers allow for the extraction of the program's memory, which can then be analyzed offline. Memory forensics frameworks provide a more comprehensive approach, allowing for the analysis of memory artifacts and the detection of hidden processes or malware.

## Binary Patching

Binary patching involves modifying the binary code of a program to change its behavior or fix vulnerabilities. This can be done using tools such as hex editors or binary patching frameworks. Hex editors allow for direct modification of the binary code, while binary patching frameworks provide a more automated approach, allowing for the creation of patches that can be applied to multiple instances of the program.

## Conclusion

These are just some of the basic methods and tools used in reverse engineering. Each method and tool has its own strengths and weaknesses, and the choice of which to use depends on the specific task at hand. By understanding and utilizing these methods and tools, reverse engineers can gain valuable insights into the inner workings of software and uncover vulnerabilities or hidden functionality.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Ve **derlemeye** tıklayın:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Ardından yeni dosyayı _**Dosya >> Modülü Kaydet...**_ seçeneğiyle kaydedin:

![](<../../.gitbook/assets/image (279).png>)

Bunu yapmanız gerekmektedir çünkü **çalışma zamanında** kod üzerinde birkaç **optimizasyon** uygulanabilir ve **hata ayıklama** yaparken **bir kesme noktası hiç tetiklenmeyebilir** veya bazı **değişkenler mevcut olmayabilir**.

Ardından, .Net uygulamanız **IIS** tarafından **çalıştırılıyorsa** onu **yeniden başlatabilirsiniz**.
```
iisreset /noforce
```
Ardından, hata ayıklamaya başlamak için açık olan tüm dosyaları kapatmalı ve **Hata Ayıklama Sekmesi**'nde **Sürece Ekle...**'yi seçmelisiniz:

![](<../../.gitbook/assets/image (280).png>)

Ardından, **IIS sunucusuna** bağlanmak için **w3wp.exe**'yi seçin ve **bağlan**'a tıklayın:

![](<../../.gitbook/assets/image (281).png>)

Şimdi, süreci hata ayıklıyoruz ve tüm modülleri yüklüyoruz. İlk olarak _Hata Ayıklama >> Tümünü Durdur_ üzerine tıklayın ve ardından _**Hata Ayıklama >> Pencereler >> Modüller**_ üzerine tıklayın:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

**Modüller** üzerinde herhangi bir modüle tıklayın ve **Tüm Modülleri Aç**'ı seçin:

![](<../../.gitbook/assets/image (284).png>)

**Assembly Explorer** üzerinde herhangi bir modüle sağ tıklayın ve **Modülleri Sırala**'yı tıklayın:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Hata Ayıklama

### IDA kullanarak

* **rundll32**'yi yükleyin (64 bit için C:\Windows\System32\rundll32.exe ve 32 bit için C:\Windows\SysWOW64\rundll32.exe)
* **Windbg** hata ayıklayıcıyı seçin
* "**Kütüphane yükleme/boşaltma durdur**" seçeneğini seçin

![](<../../.gitbook/assets/image (135).png>)

* Yürütmenin **parametrelerini** ayarlayın, DLL'nin **yolunu** ve çağırmak istediğiniz işlevi girin:

![](<../../.gitbook/assets/image (136).png>)

Ardından, hata ayıklamaya başladığınızda, her DLL yüklendiğinde yürütme durdurulur, ardından rundll32 DLL'nizi yüklediğinde yürütme durdurulur.

Ancak, yüklenen DLL'nin koduna nasıl erişebilirsiniz? Bu yöntemi kullanarak, bunu bilmiyorum.

### x64dbg/x32dbg kullanarak

* **rundll32**'yi yükleyin (64 bit için C:\Windows\System32\rundll32.exe ve 32 bit için C:\Windows\SysWOW64\rundll32.exe)
* Komut Satırını Değiştirin (_Dosya --> Komut Satırını Değiştir_) ve dll'nin yolunu ve çağırmak istediğiniz işlevi ayarlayın, örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* _Ayarlar --> Ayarlar_ üzerinde değişiklik yapın ve "**DLL Girişi**"ni seçin.
* Ardından **yürütmeyi başlatın**, hata ayıklayıcı her dll ana işlevinde duracak, bir noktada kendi dll Girişinizde duracaksınız. Oradan, kırılma noktalarını koymak istediğiniz yerleri arayın.

Dikkat edin, yürütme herhangi bir nedenle durduğunda win64dbg'de **hangi kodda olduğunuzu** win64dbg penceresinin **üst kısmında** görebilirsiniz:

![](<../../.gitbook/assets/image (137).png>)

Bu şekilde, istediğiniz DLL'de yürütme durduğunda nerede olduğunu görebilirsiniz.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmanıza ve değiştirmenize yardımcı olan kullanışlı bir programdır. Daha fazla bilgi için:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM ve MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcode'lar

### Blobrunner ile bir shellcode'yu hata ayıklama

[**Blobrunner**](https://github.com/OALabs/BlobRunner), shellcode'yu bellekte bir alan içine **ayırır**, shellcode'nun ayrıldığı **bellek adresini** size bildirir ve yürütmeyi **durdurur**.\
Ardından, bir hata ayıklayıcıyı (Ida veya x64dbg) sürece bağlamalı ve belirtilen bellek adresine bir **kırılma noktası** yerleştirmeli ve yürütmeyi **devam ettirmelisiniz**. Böylece shellcode'u hata ayıklıyorsunuz.

Yayınlar github sayfası, derlenmiş sürümleri içeren zip dosyalarını içerir: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın hafif değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için sadece **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve derleyin**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### jmp2it ile bir shellcode'yu hata ayıklama

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), blobrunner'a çok benzer. Shellcode'yu bellekte bir alan içine **ayırır** ve bir **sonsuz döngü** başlatır. Ardından, hata ayıklayıcıyı sürece **bağlamanız**, **başlatmanız**, 2-5 saniye beklemeniz ve **durdurmanız** gerekmektedir ve kendinizi **sonsuz döngü** içinde bulacaksınız. Sonsuz döngünün bir sonraki talimatına atlayın çünkü bu shellcode'a bir çağrı olacak ve sonunda shellcode'u yürütüyormuş gibi bulacaksınız.

![](<../../.gitbook/assets/image (397).png>)

Derlenmiş bir sürümünü [yayınlar sayfasından jmp2it'i indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode'u hata ayıklama

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'nin GUI'sudur. Cutter kullanarak shellcode'u emüle edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Dosya Aç" ve "Shellcode Aç" seçeneklerine sahip olduğunu unutmayın. Benim durumumda, shellcode'u bir dosya olarak açtığımda doğru şekilde dekompilasyon yaptı, ancak shellcode'u bir shellcode olarak açtığımda yapmadı:

![](<../../.gitbook/assets/image (400).png>)

Emülasyonu istediğiniz yerde başlatmak için oraya bir kırılma noktası ayarlayın ve görünüşe göre cutter otomatik olarak oradan emülasyonu başlatacaktır:

![](<../../.gitbook/assets/image (399).png>)

Örneğin, bir onaltılık döküm içinde yığını görebilirsiniz:

![](<../../.gitbook/assets/image (402).png>)

### Shellcode'u deobfuscate etmek ve yürütülen işlevleri almak

[**scdbg**'yi denemelisiniz](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
scdbg, shellcode'un hangi işlevleri kullandığını ve shellcode'un bellekte kendini **şifrelediğini** söyler.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca, istediğiniz seçenekleri seçebileceğiniz ve shellcode'yu çalıştırabileceğiniz grafiksel bir başlatıcıya sahiptir.

![](<../../.gitbook/assets/image (398).png>)

**Dump Oluştur** seçeneği, bellekteki shellcode'a dinamik olarak herhangi bir değişiklik yapılırsa (şifrelenmiş shellcode'u indirmek için kullanışlıdır) son shellcode'u döker. **Başlangıç ofseti**, shellcode'u belirli bir ofsette başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'u hata ayıklamak için kullanışlıdır (ancak bu konuda önce açıklanan seçeneklerden herhangi birini kullanmanın daha iyi olduğunu düşünüyorum çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef Kullanarak Disassembling

Shellcode dosyanızı giriş olarak yükleyin ve aşağıdaki reçeteyi kullanarak onu decompile edin: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, **tüm `mov` talimatlarını değiştirir** (evet, gerçekten harika). Ayrıca, yürütme akışlarını değiştirmek için kesintileri kullanır. Nasıl çalıştığı hakkında daha fazla bilgi için:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Şanslıysanız, [demovfuscator](https://github.com/kirschju/demovfuscator) ikili dosyayı deobfuscate edecektir. Çeşitli bağımlılıkları vardır.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [keystone'ı yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oynuyorsanız, bayrağı bulmak için bu çözüm yöntemi** çok faydalı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

**Giriş noktasını** bulmak için `::main` ile fonksiyonları arayın, örneğin:

![](<../../.gitbook/assets/image (612).png>)

Bu durumda, ikili dosya authenticator olarak adlandırıldığından, bu ilginç ana fonksiyon olduğu oldukça açıktır.\
Çağrılan **fonksiyonların adını** bulduktan sonra, **Internet** üzerinde bunların **girdileri** ve **çıktıları** hakkında bilgi edinmek için arama yapın.

## **Delphi**

Delphi derlenmiş ikili dosyalar için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi ikili dosyasını tersine çevirmeniz gerekiyorsa, IDA eklentisini kullanmanızı öneririm [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Sadece **ATL+f7** tuşlarına basın (IDA'da python eklentisini içe aktarın) ve python eklentisini seçin.

Bu eklenti, hata ayıklamanın başında ikili dosyayı yürütür ve fonksiyon adlarını dinamik olarak çözer. Hata ayıklamaya başladıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın ve gerçek kodun başında bir kesme noktası oluşacaktır.

Ayrıca, grafik uygulamasında bir düğmeye bastığınızda hata ayıklayıcı, o düğme tarafından yürütülen fonksiyonda duracaktır.

## Golang

Bir Golang ikili dosyasını tersine çevirmeniz gerekiyorsa, IDA eklentisini kullanmanızı öneririm [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Sadece **ATL+f7** tuşlarına basın (IDA'da python eklentisini içe aktarın) ve python eklentisini seçin.

Bu, fonksiyonların adlarını çözecektir.

## Derlenmiş Python

Bu sayfada, bir ELF/EXE Python derlenmiş ikili dosyasından Python kodunu nasıl alacağınızı bulabilirsiniz:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Bir GBA oyununun **ikili** dosyasını elde ederseniz, farklı araçları kullanarak bunu **emüle** edebilir ve **hata ayıklama** yapabilirsiniz:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Hata ayıklama sürümünü indirin_) - Arayüzle birlikte bir hata ayıklayıcı içerir
* [**mgba** ](https://mgba.io)- Bir CLI hata ayıklayıcı içerir
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra eklentisi
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra eklentisi

[**no$gba**](https://problemkaputt.de/gba.htm) içinde _**Options --> Emulation Setup --> Controls**_\*\* \*\* bölümünde Game Boy Advance **düğmelerini** nasıl basacağınızı görebilirsiniz

![](<../../.gitbook/assets/image (578).png>)

Basıldığında, her **tuşun bir değeri** vardır ve bunu tanımlamak için kullanılır:
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
Bu tür programlarda, programın kullanıcı girişini nasıl işlediği ilginç bir kısım olacaktır. Adreste **0x4000130** sıkça karşılaşılan **KEYINPUT** fonksiyonunu bulacaksınız.

![](<../../.gitbook/assets/image (579).png>)

Önceki görüntüde, fonksiyonun **FUN\_080015a8** (adresler: _0x080015fa_ ve _0x080017ac_) tarafından çağrıldığını görebilirsiniz.

Bu fonksiyonda, bazı başlatma işlemlerinden sonra (önemli olmayanlar):
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
Son if ifadesi, **`uVar4`**'ün **son tuşlarda** bulunup bulunmadığını ve mevcut tuş olmadığını kontrol ediyor, ayrıca bir düğmeyi bırakma olarak adlandırılıyor (mevcut tuş **`uVar1`** içinde saklanır).
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

* İlk olarak, **4 değeri** (**SELECT** düğmesi) ile karşılaştırılır: Bu meydan okumada bu düğme ekranı temizler.
* Ardından, **8 değeri** (**START** düğmesi) ile karşılaştırılır: Bu meydan okumada kodun bayrağı almak için geçerli olup olmadığını kontrol eder.
* Bu durumda, **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynı ise bazı kodlar çalıştırılır.
* Diğer durumlarda, bazı **cont (`DAT_030000d4`)** kontrol edilir. Bu bir cont'tur çünkü kodun içine girdikten hemen sonra 1 eklenir. 
* 8'den küçükse, **`DAT_030000d8`** değişkenine değerlerin eklenmesiyle ilgili bir şey yapılır (temel olarak, cont 8'den küçük olduğu sürece bu değişkene basılan tuşların değerlerini ekler).

Bu meydan okumada, düğmelerin değerlerini bilerek, sonucunda eklemenin 0xf3 olduğu 8'den küçük bir kombinasyonu **basmanız gerekiyordu**.

**Bu öğretici için referans:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kurslar

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da** takip edin.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
