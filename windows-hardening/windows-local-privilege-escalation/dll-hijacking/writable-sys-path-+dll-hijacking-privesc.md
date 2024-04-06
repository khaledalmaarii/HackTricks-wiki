# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanlık seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Giriş

Eğer **bir Sistem Yolu klasörüne yazabileceğinizi** tespit ettiyseniz (unutmayın, bir Kullanıcı Yolu klasörüne yazabiliyorsanız bu çalışmayacaktır), bu durumda sisteminizde **privilege escalation (ayrıcalık yükseltme)** yapabilirsiniz.

Bunu yapmak için, **Daha fazla ayrıcalığa sahip bir hizmet veya işlem tarafından yüklenen bir kütüphaneyi ele geçireceksiniz** ve çünkü bu hizmet, muhtemelen sistemde hiç var olmayan bir Dll'yi yüklemeye çalışacak, bu Dll'yi yazabileceğiniz Sistem Yolu'ndan yüklemeye çalışacak.

**Dll Hijacking** hakkında daha fazla bilgi için:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Dll Hijacking ile Privilege Escalation

### Eksik bir Dll bulma

İlk yapmanız gereken, **sizden daha fazla ayrıcalığa sahip bir işlem** tarafından **Sistem Yolu'ndan bir Dll yüklemeye çalışan bir işlemi** tespit etmektir.

Bu durumdaki sorun, bu işlemlerin muhtemelen zaten çalışıyor olmasıdır. İhtiyaç duyduğunuz hizmetlerin eksik olan Dll'lerini bulmak için, işlemler yüklenmeden önce mümkün olan en kısa sürede procmon'u başlatmanız gerekmektedir. Bu nedenle, eksik .dll'leri bulmak için şunları yapın:

* `C:\privesc_hijacking` klasörünü **oluşturun** ve **Sistem Yolu** çevresel değişkenine `C:\privesc_hijacking` yolunu **ekleyin**. Bunları **manuel olarak** yapabilirsiniz veya **PS** ile yapabilirsiniz:

```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```

* **`procmon`**'u başlatın ve **`Options`** --> **`Enable boot logging`** seçeneğine gidin ve açılan pencerede **`OK`** düğmesine basın.
* Ardından, **sistemi yeniden başlatın**. Bilgisayar yeniden başlatıldığında **`procmon`** olayları kaydetmeye başlayacaktır.
* **Windows** başladığında **`procmon`**'ı tekrar çalıştırın, çalıştığını ve olayları bir dosyada saklamak isteyip istemediğinizi soracaktır. **Evet** deyin ve olayları bir dosyada **saklayın**.
* **Dosya** oluşturulduktan **sonra**, açık olan **`procmon`** penceresini kapatın ve olaylar dosyasını açın.
* Aşağıdaki **filtreleri ekleyin** ve yazılabilir Sistem Yolu klasöründen yüklenmeye çalışılan tüm DLL'leri bulacaksınız:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Eksik DLL'ler

Bu komutu ücretsiz bir **sanal (vmware) Windows 11 makinesinde** çalıştırdığımda şu sonuçları elde ettim:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe dosyaları işe yaramaz, onları görmezden gelin, eksik DLL'ler şunlardan kaynaklanmaktadır:

| Hizmet                         | DLL                | CMD satırı                                                           |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Görev Zamanlayıcısı (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Tanılama İlkesi Hizmeti (DPS)  | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Bunu bulduktan sonra, bu ilginç blog yazısını buldum, ayrıca [**WptsExtensions.dll'yi ayrıcalık yükseltmek için nasıl kötüye kullanabileceğinizi**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll) açıklıyor. Şimdi **bunu yapacağız**.

### Sömürü

Bu nedenle, ayrıcalıkları yükseltmek için **WptsExtensions.dll** kütüphanesini ele geçireceğiz. **Yolu** ve **adı** olan kötü amaçlı dll'yi sadece **oluşturmanız gerekiyor**.

[**Bu örneklerden herhangi birini denemeyi deneyebilirsiniz**](./#creating-and-compiling-dlls). Rev shell alabilir, bir kullanıcı ekleyebilir, bir işaretçi çalıştırabilirsiniz...

{% hint style="warning" %}
Dikkat edin, **tüm hizmetler** **`NT AUTHORITY\SYSTEM`** ile çalıştırılmaz, bazıları aynı zamanda **`NT AUTHORITY\LOCAL SERVICE`** ile çalıştırılır ve bu daha az ayrıcalığa sahiptir ve **yeni bir kullanıcı oluşturamazsınız**. Bununla birlikte, bu kullanıcının **`seImpersonate`** ayrıcalığı vardır, bu nedenle [**potato suite'yi ayrıcalıkları yükseltmek için kullanabilirsiniz**](../roguepotato-and-printspoofer.md). Bu durumda, bir rev shell oluşturmak, bir kullanıcı oluşturmaya çalışmaktan daha iyi bir seçenektir.
{% endhint %}

Bu yazıyı yazdığım sırada **Görev Zamanlayıcısı** hizmeti **Nt AUTHORITY\SYSTEM** ile çalıştırılıyor.

Kötü amaçlı DLL'yi **oluşturduktan sonra** (_benim durumumda x64 rev shell kullandım ve msfvenom'dan geldiği için defender tarafından öldürüldü_), onu yazılabilir Sistem Yolu'na **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı yeniden başlatın (veya hizmeti yeniden başlatın veya etkilenen hizmeti/programı yeniden çalıştırmak için gerekeni yapın).

Hizmet yeniden başlatıldığında, **dll yüklenecek ve çalıştırılacak**tır (kütüphanenin beklenildiği gibi yüklendiğini kontrol etmek için **procmon** hilesini yeniden kullanabilirsiniz).

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
