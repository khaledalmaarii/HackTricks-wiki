<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

# Wasm Decompilation and Wat Compilation Guide

**WebAssembly** alanında, **decompile** ve **compile** işlemleri için araçlar geliştiriciler için önemlidir. Bu kılavuz, **Wasm (WebAssembly ikili)** ve **Wat (WebAssembly metin)** dosyalarını işlemek için bazı çevrimiçi kaynaklar ve yazılımlar tanıtır.

## Çevrimiçi Araçlar

- Wasm'ı Wat'a **decompile** etmek için, [Wabt'in wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) aracı kullanışlıdır.
- Wat'ı Wasm'a **compile** etmek için, [Wabt'in wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanılabilir.
- Başka bir decompile seçeneği [web-wasmdec](https://wwwg.github.io/web-wasmdec/) adresinde bulunabilir.

## Yazılım Çözümleri

- Daha güçlü bir çözüm için, [PNF Software tarafından geliştirilen JEB](https://www.pnfsoftware.com/jeb/demo) kapsamlı özellikler sunar.
- Açık kaynaklı proje [wasmdec](https://github.com/wwwg/wasmdec) decompile görevleri için kullanılabilir.

# .Net Decompilation Kaynakları

.Net derlemelerini decompile etmek için şu araçlar kullanılabilir:

- [ILSpy](https://github.com/icsharpcode/ILSpy), aynı zamanda [Visual Studio Code için eklenti](https://github.com/icsharpcode/ilspy-vscode) sunan, çapraz platform kullanımına izin veren bir araçtır.
- **Decompile**, **modification** ve **recompilation** görevlerini içeren işlemler için, [dnSpy](https://github.com/0xd4d/dnSpy/releases) şiddetle önerilir. Bir yönteme sağ tıklayarak **Modify Method** seçeneğiyle kod değişiklikleri yapılabilir.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/), .Net derlemelerini decompile etmek için başka bir alternatiftir.

## Hata Ayıklama ve Günlüklemeyi DNSpy ile Geliştirme

### DNSpy Günlükleme
DNSpy kullanarak bilgileri bir dosyaya kaydetmek için, aşağıdaki .Net kod parçasını dahil edin:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy Hata Ayıklama
DNSpy ile etkili bir hata ayıklama için, hata ayıklamayı engelleyebilecek optimizasyonların devre dışı bırakıldığı **Assembly attributes** ayarlarını düzenlemek için bir dizi adım önerilir. Bu işlem, `DebuggableAttribute` ayarlarını değiştirmeyi, derlemeyi yeniden yapmayı ve değişiklikleri kaydetmeyi içerir.

Ayrıca, **IIS** tarafından çalıştırılan bir .Net uygulamasını hata ayıklamak için, IIS'i yeniden başlatmak için `iisreset /noforce` komutunu çalıştırmak gerekmektedir. DNSpy'ı hata ayıklama için IIS sürecine bağlamak için, kılavuz, DNSpy içinde **w3wp.exe** sürecini seçmeyi ve hata ayıklama oturumunu başlatmayı anlatır.

Hata ayıklama sırasında yüklenen modüllerin kapsamlı bir görünümü için, DNSpy'daki **Modules** penceresine erişmek ve tüm modülleri açmak ve gezinme ve hata ayıklama için derlemeleri sıralamak önerilir.

Bu kılavuz, WebAssembly ve .Net decompilation'ın özünü kapsar ve geliştiricilere bu görevleri kolaylıkla yönetmeleri için bir yol sunar.

## **Java Decompiler**
Java bytecode'ı decompile etmek için şu araçlar çok yardımcı olabilir:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLL'leri Hata Ayıklama**
### IDA Kullanımı
- 64-bit ve 32-bit sürümler için belirli yollardan **Rundll32** yüklenir.
- **Windbg**, hata ayıklama için seçilen ve kütüphane yükleme/boşaltma üzerinde askıya alma seçeneği etkinleştirilen hata ayıklayıcıdır.
- Yürütme parametreleri DLL yolunu ve işlev adını içerir. Bu yapılandırma, her DLL yüklenmesinde yürütmeyi duraklatır.

### x64dbg/x32dbg Kullanımı
- IDA'ya benzer şekilde, **rundll32** DLL ve işlevi belirtmek için komut satırı değişiklikleriyle yüklenir.
- Ayarlar, DLL girişinde duraklamaya izin veren şekilde ayarlanır ve istenen DLL giriş noktasında kesme noktası ayarlamaya izin verir.

### Görüntüler
- Yürütme duraklama noktaları ve yapılandırmaları ekran görüntüleriyle gösterilir.

## **ARM & MIPS**
- Emülasyon için [arm_now](https://github.com/nongiach/arm_now) kullanışlı bir kaynaktır.

## **Shellcode'lar**
### Hata Ayıklama Teknikleri
- **Blobrunner** ve **jmp2it**, bellekte shellcode tahsis etmek ve Ida veya x64dbg ile hata ayıklamak için araçlardır.
- Blobrunner [sürümleri](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [derlenmiş sürümü](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**, GUI tabanlı shellcode emülasyonu ve incelemesi sunar, dosya olarak shellcode ile doğrudan shellcode arasındaki farkları vurgular.

### Deobfuscation ve Analiz
- **scdbg**, shellcode işlevlerine ve deobfuscation yeteneklerine içgörü sağlar.
%%%bash
scdbg.exe -f shellcode # Temel bilgiler
scdbg.exe -f shellcode -r # Analiz raporu
scdbg.exe -f shellcode -i -r # Etkileşimli kancalar
scdbg.exe -f shellcode -d # Kod çözülmüş shellcode'u dök
scdbg.exe -f shellcode /findsc # Başlangıç ofsetini bul
scdbg.exe -f shellcode /foff 0x0000004D # Ofsetten çalıştır
%%%

- Shellcode'u disassemble etmek için **CyberChef**: [CyberChef tarifi](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Tüm talimatları `mov` ile değiştiren bir obfuscator.
- Faydalı kaynaklar arasında bir [YouTube açıklaması](https://www.youtube.com/watch?v=2VF_wPkiBJY) ve [PDF sl
## **Delphi**
- Delphi ikili dosyaları için [IDR](https://github.com/crypto2011/IDR) önerilir.


# Kurslar

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binary deobfuscation\)



<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
