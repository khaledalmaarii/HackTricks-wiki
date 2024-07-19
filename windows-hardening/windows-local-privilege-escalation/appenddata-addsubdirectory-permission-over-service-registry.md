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


**Orijinal gönderi** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Özet

Mevcut kullanıcı tarafından yazılabilir iki kayıt anahtarı bulundu:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper** hizmetinin izinlerini **regedit GUI** kullanarak kontrol etmenin önerildiği belirtildi, özellikle **Gelişmiş Güvenlik Ayarları** penceresinin **Etkin İzinler** sekmesi. Bu yaklaşım, her Erişim Kontrol Girişi'ni (ACE) ayrı ayrı incelemeden belirli kullanıcılar veya gruplara verilen izinlerin değerlendirilmesini sağlar.

Düşük ayrıcalıklı bir kullanıcıya atanan izinleri gösteren bir ekran görüntüsü, **Alt Anahtar Oluştur** izninin dikkat çekici olduğunu gösterdi. Bu izin, **AppendData/AddSubdirectory** olarak da adlandırılmakta olup, scriptin bulgularıyla örtüşmektedir.

Belirli değerleri doğrudan değiştirme yeteneğinin olmaması, ancak yeni alt anahtarlar oluşturma yeteneğinin olduğu kaydedildi. Öne çıkan bir örnek, **ImagePath** değerini değiştirme girişimiydi ve bu, erişim reddedildi mesajıyla sonuçlandı.

Bu sınırlamalara rağmen, **RpcEptMapper** hizmetinin kayıt yapısındaki **Performance** alt anahtarını kullanma olasılığı ile ayrıcalık yükseltme potansiyeli belirlendi; bu alt anahtar varsayılan olarak mevcut değildir. Bu, DLL kaydı ve performans izleme imkanı sağlayabilir.

**Performance** alt anahtarı ve performans izleme için kullanımı hakkında belgeler incelendi ve bir kanıt konsepti DLL'si geliştirildi. Bu DLL, **OpenPerfData**, **CollectPerfData** ve **ClosePerfData** işlevlerinin uygulanmasını göstererek **rundll32** aracılığıyla test edildi ve başarılı bir şekilde çalıştığı doğrulandı.

Amaç, **RPC Endpoint Mapper hizmetini** oluşturulan Performans DLL'sini yüklemeye zorlamaktı. Gözlemler, PowerShell aracılığıyla Performans Verileri ile ilgili WMI sınıf sorgularının yürütülmesinin bir günlük dosyası oluşturduğunu ve böylece **LOCAL SYSTEM** bağlamında keyfi kod yürütülmesine olanak tanıdığını, bu durumun da yükseltilmiş ayrıcalıklar sağladığını ortaya koydu.

Bu güvenlik açığının kalıcılığı ve potansiyel etkileri vurgulandı, post-exploitation stratejileri, yan hareket ve antivirüs/EDR sistemlerinden kaçınma ile ilgili önemine dikkat çekildi.

Güvenlik açığının başlangıçta script aracılığıyla istemeden ifşa edildiği belirtilse de, istismarının eski Windows sürümleri (örneğin, **Windows 7 / Server 2008 R2**) ile sınırlı olduğu ve yerel erişim gerektirdiği vurgulandı.

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
