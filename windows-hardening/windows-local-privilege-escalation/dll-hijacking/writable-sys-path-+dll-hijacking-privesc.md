# Writable Sys Path +Dll Hijacking Privesc

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Introduction

Eğer bir **Sistem Yolu klasöründe yazma yetkiniz olduğunu** bulduysanız (bu, bir Kullanıcı Yolu klasöründe yazma yetkiniz varsa çalışmayacaktır) sistemde **yetki yükseltme** yapmanız mümkün olabilir.

Bunu yapmak için, **sizin yetkilerinizden daha fazla yetkiye sahip** bir hizmet veya işlem tarafından **yüklenen bir kütüphaneyi ele geçireceğiniz** bir **Dll Hijacking** durumunu kötüye kullanabilirsiniz ve bu hizmet, muhtemelen sistemde hiç var olmayan bir Dll'yi yüklemeye çalıştığı için, yazabileceğiniz Sistem Yolu'ndan yüklemeye çalışacaktır.

**Dll Hijacking nedir** hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc with Dll Hijacking

### Finding a missing Dll

İhtiyacınız olan ilk şey, **yazma yetkinizden daha fazla yetkiye sahip** bir işlemi **Sistem Yolundan Dll yüklemeye çalışan** bir işlem olarak **belirlemektir**.

Bu durumlarda sorun, muhtemelen bu işlemlerin zaten çalışıyor olmasıdır. Hangi Dll'lerin hizmetlerden eksik olduğunu bulmak için, mümkün olan en kısa sürede (işlemler yüklenmeden önce) procmon'u başlatmalısınız. Eksik .dll'leri bulmak için:

* **C:\privesc_hijacking** klasörünü **oluşturun** ve `C:\privesc_hijacking` yolunu **Sistem Yolu ortam değişkenine** ekleyin. Bunu **manuel olarak** veya **PS** ile yapabilirsiniz:
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
* **`procmon`**'u başlatın ve **`Options`** --> **`Enable boot logging`**'e gidin ve istemde **`OK`**'ye basın.
* Sonra, **yeniden başlatın**. Bilgisayar yeniden başlatıldığında **`procmon`** olayları mümkün olan en kısa sürede **kaydetmeye** başlayacaktır.
* **Windows** başladıktan sonra **`procmon`**'u tekrar çalıştırın, çalıştığını söyleyecek ve olayları bir dosyada **saklamak** isteyip istemediğinizi soracaktır. **Evet** deyin ve **olayları bir dosyada saklayın**.
* **Dosya** oluşturulduktan sonra, açılan **`procmon`** penceresini **kapatın** ve **olay dosyasını açın**.
* Bu **filtreleri** ekleyin ve yazılabilir Sistem Yolu klasöründen yüklemeye çalışan tüm Dll'leri bulacaksınız:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Kaçırılan Dll'ler

Ücretsiz bir **sanallaştırma (vmware) Windows 11 makinesinde** bunu çalıştırdığımda bu sonuçları aldım:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe'ler işe yaramaz, bu yüzden onları göz ardı edin, kaçırılan DLL'ler şunlardı:

| Servis                          | Dll                | CMD satırı                                                            |
| ------------------------------- | ------------------ | --------------------------------------------------------------------- |
| Görev Zamanlayıcı (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Tanılama Politika Servisi (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Bunu bulduktan sonra, [**WptsExtensions.dll'yi privesc için nasıl kötüye kullanacağınızı**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll) açıklayan ilginç bir blog yazısı buldum. Şimdi **bunu yapacağız**.

### Sömürü

Yani, **yetkileri artırmak** için **WptsExtensions.dll** kütüphanesini ele geçireceğiz. **Yolu** ve **adı** bildiğimiz için sadece **kötü niyetli dll**'yi **oluşturmamız** gerekiyor.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](./#creating-and-compiling-dlls). Rev shell almak, bir kullanıcı eklemek, bir beacon çalıştırmak gibi yükleri çalıştırabilirsiniz...

{% hint style="warning" %}
Tüm hizmetlerin **`NT AUTHORITY\SYSTEM`** ile çalışmadığını unutmayın, bazıları **`NT AUTHORITY\LOCAL SERVICE`** ile de çalışır ki bu da **daha az yetkiye** sahiptir ve **yeni bir kullanıcı oluşturamazsınız** izinlerini kötüye kullanamazsınız.\
Ancak, o kullanıcının **`seImpersonate`** yetkisi vardır, bu yüzden [**yetkileri artırmak için potato suite'i kullanabilirsiniz**](../roguepotato-and-printspoofer.md). Bu durumda, bir rev shell, bir kullanıcı oluşturmaya çalışmaktan daha iyi bir seçenektir.
{% endhint %}

Yazma anında **Görev Zamanlayıcı** servisi **Nt AUTHORITY\SYSTEM** ile çalışıyor.

**Kötü niyetli Dll'yi oluşturduktan sonra** (_benim durumumda x64 rev shell kullandım ve bir shell geri aldım ama defender bunu msfvenom'dan olduğu için öldürdü_), yazılabilir Sistem Yolu'na **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **yeniden başlatın** (veya hizmeti yeniden başlatın ya da etkilenen hizmet/programı yeniden çalıştırmak için ne gerekiyorsa yapın).

Hizmet yeniden başlatıldığında, **dll yüklenmeli ve çalıştırılmalıdır** (kütüphanenin **beklendiği gibi yüklenip yüklenmediğini kontrol etmek için **procmon** numarasını **kullanabilirsiniz**).

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
