# WmicExec

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Nasıl Çalıştığı Açıklaması

Kullanıcı adı ve ya şifre veya hash bilinen ana bilgisayarlarda WMI kullanarak işlemler açılabilir. Wmiexec tarafından WMI kullanılarak komutlar yürütülür ve yarı etkileşimli bir kabuk deneyimi sağlanır.

**dcomexec.py:** Farklı DCOM uç noktalarını kullanarak, bu komut dosyası wmiexec.py'ye benzer yarı etkileşimli bir kabuk sunar ve özellikle ShellBrowserWindow DCOM nesnesini kullanır. Şu anda MMC20. Uygulama, Shell Pencereleri ve Shell Tarayıcı Penceresi nesnelerini desteklemektedir. (kaynak: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Temelleri

### Ad Alanı

Dizin tarzında hiyerarşiye sahip olan WMI'nın en üst düzey konteyneri \root'dur ve altında ad alanları olarak adlandırılan ek dizinler düzenlenir.
Ad alanlarını listelemek için kullanılan komutlar:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Bir isim alanındaki sınıflar aşağıdaki şekilde listelenebilir:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Sınıflar**

Bir WMI sınıf adını, örneğin win32\_process'i ve bulunduğu ad alanını bilmek, herhangi bir WMI işlemi için önemlidir.
`win32` ile başlayan sınıfları listelemek için kullanılan komutlar:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Bir sınıfın çağrılması:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Yöntemler

Yöntemler, WMI sınıflarının bir veya daha fazla yürütülebilir işlevleridir ve çalıştırılabilirler.
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

### WMI Hizmet Durumu

WMI hizmetinin çalışıp çalışmadığını doğrulamak için kullanılan komutlar:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Sistem ve İşlem Bilgileri

WMI aracılığıyla sistem ve işlem bilgileri toplama:
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
### **El ile Uzaktan WMI Sorgulama**

Uzaktaki bir makinede yerel yöneticilerin veya oturum açmış kullanıcıların gizli bir şekilde belirlenmesi, özel WMI sorguları aracılığıyla mümkündür. `wmic`, ayrıca birden fazla düğümde komutları eşzamanlı olarak yürütmek için bir metin dosyasından okuma desteği sağlar.

Empire ajanı gibi bir işlemi uzaktan WMI üzerinde yürütmek için aşağıdaki komut yapısı kullanılır ve başarılı yürütme "0" dönüş değeri ile gösterilir:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Bu süreç, WMI'nın uzaktan yürütme ve sistem numaralandırma yeteneklerini göstererek, hem sistem yönetimi hem de penetrasyon testi için kullanışlı olduğunu vurgular.


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

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
