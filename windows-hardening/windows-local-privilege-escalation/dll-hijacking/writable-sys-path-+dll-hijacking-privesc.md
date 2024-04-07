# Yazılabilir Sys Yolu + Dll Korsanlığı İstek Yükseltme

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>

## Giriş

Eğer **Bir Sistem Yolu klasörüne yazabileceğinizi** fark ederseniz (unutmayın ki bu bir Kullanıcı Yolu klasörüne yazabiliyorsanız çalışmaz) bu durumda **sistemde ayrıcalıkları yükseltebilirsiniz**.

Bunu yapabilmek için, **Daha fazla ayrıcalığa sahip bir hizmet veya işlem tarafından yüklenen bir kütüphaneyi ele geçireceğiniz bir Dll Korsanlığını** istismar edebilirsiniz ve çünkü bu hizmet muhtemelen sistem genelinde mevcut olmayan bir Dll'yi yüklemeye çalışacak, bu Dll'yi yazabileceğiniz Sistem Yolundan yüklemeye çalışacak.

**Dll Korsanlığı nedir** hakkında daha fazla bilgi için:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Dll Korsanlığı ile İstek Yükseltme

### Eksik bir Dll bulma

İlk yapmanız gereken şey, **sizden daha fazla ayrıcalığa sahip bir işlemi tanımlamak** ve **yazabileceğiniz Sistem Yolundan bir Dll yüklemeye çalışan** bu işlemi belirlemektir.

Bu durumlarda sorun, bu işlemlerin zaten çalışıyor olmasıdır. İhtiyacınız olan .dll'leri bulmak için, gerekli hizmetlerin eksik olan .dll'lerini bulmak için mümkün olan en kısa sürede procmon'u başlatmanız gerekmektedir (işlemler yüklenmeden önce). Bu nedenle eksik .dll'leri bulmak için şunları yapın:

* `C:\privesc_hijacking` klasörünü **oluşturun** ve bu yolu **Sistem Yolu ortam değişkenine** ekleyin. Bunları **manuel olarak** veya **PS** ile yapabilirsiniz:
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
* **`procmon`**'u başlatın ve **`Options`** --> **`Enable boot logging`**'e gidin ve ekrandaki **`OK`** düğmesine basın.
* Ardından **sistemi yeniden başlatın**. Bilgisayar yeniden başlatıldığında **`procmon`** olayları hemen kaydetmeye başlayacaktır.
* **Windows** başladığında **`procmon`**'u tekrar **çalıştırın**, çalıştığını ve olayları bir dosyada saklamak isteyip istemediğinizi soracaktır. **Evet** deyin ve olayları bir dosyada **saklayın**.
* **Dosya** oluşturulduktan **sonra**, açık olan **`procmon`** penceresini kapatın ve **olaylar dosyasını açın**.
* Aşağıdaki **filtreleri ekleyin** ve yazılabilir System Path klasöründen yüklenmeye çalışılan tüm Dll'leri bulacaksınız:

<figure><img src="../../../.gitbook/assets/image (942).png" alt=""><figcaption></figcaption></figure>

### Eksik Dll'ler

Bu adımları **ücretsiz bir sanal (vmware) Windows 11 makinesinde** çalıştırdığımda şu sonuçları elde ettim:

<figure><img src="../../../.gitbook/assets/image (604).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe dosyaları işe yaramaz, onları görmezden gelin, eksik DLL'ler şuradan geldi:

| Servis                         | Dll                | Komut satırı                                                        |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Görev Zamanlayıcısı (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Tanımlayıcı Politika Servisi (DPS) | Bilinmeyen.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Bunu bulduktan sonra, aynı zamanda [**WptsExtensions.dll'yi kötüye kullanmak için nasıl kullanılacağını açıklayan**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll) ilginç bir blog yazısı buldum. Şimdi **yapacağımız şey** budur.

### Sömürü

Yani, **yetkileri yükseltmek** için **WptsExtensions.dll** kütüphanesini ele geçireceğiz. **Yolu** ve **adı** olan bir kez daha **kötü niyetli dll'yi oluşturmamız gerekiyor**.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](./#creating-and-compiling-dlls). Rev shell alabilir, bir kullanıcı ekleyebilir, bir işaretçi çalıştırabilirsiniz...

{% hint style="warning" %}
**Not:** **Tüm hizmetlerin** **`NT AUTHORITY\SYSTEM`** ile çalıştırılmadığını unutmayın, bazıları aynı zamanda **`NT AUTHORITY\LOCAL SERVICE`** ile çalıştırılır, bu da **daha az ayrıcalığa** sahiptir ve **bir kullanıcı oluşturamazsınız**. Bununla birlikte, bu kullanıcının **`seImpersonate`** ayrıcalığı vardır, bu nedenle [**aşırı ayrıcalıklar için patates takımını kullanabilirsiniz**](../roguepotato-and-printspoofer.md). Bu durumda bir rev shell oluşturmak, bir kullanıcı oluşturmaya çalışmaktan daha iyi bir seçenektir.
{% endhint %}

Bu yazıyı yazdığım sırada **Görev Zamanlayıcısı** hizmeti **Nt AUTHORITY\SYSTEM** ile çalıştırılıyor.

**Kötü niyetli Dll'yi oluşturduktan** (_benim durumumda x64 rev shell kullandım ve bir kabuk aldım ancak defender, msfvenom'dan geldiği için onu öldürdü_), yazılabilir System Path'e **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **yeniden başlatın** (veya hizmeti yeniden başlatın veya etkilenen hizmeti/programı yeniden çalıştırmak için gereken her şeyi yapın).

Hizmet yeniden başlatıldığında, **dll yüklenmeli ve çalıştırılmalıdır** (kütüphanenin beklenildiği gibi yüklendiğini kontrol etmek için **procmon** hilesini tekrar kullanabilirsiniz).
