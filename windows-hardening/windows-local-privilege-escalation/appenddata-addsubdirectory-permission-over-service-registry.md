<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


**Orijinal yazı** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Özet

Mevcut kullanıcı tarafından yazılabilir olarak bulunan iki kayıt defteri anahtarı tespit edildi:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper** hizmetinin izinlerini kontrol etmek için **regedit GUI** kullanılması ve özellikle **Gelişmiş Güvenlik Ayarları** penceresinin **Etkili İzinler** sekmesinin incelenmesi önerildi. Bu yaklaşım, her Erişim Kontrol Girişi (ACE) ayrı ayrı incelenmeden belirli kullanıcılara veya gruplara verilen izinlerin değerlendirilmesini sağlar.

Düşük ayrıcalıklı bir kullanıcıya atanan izinlerin gösterildiği bir ekran görüntüsü, **Alt Anahtar Oluşturma** izni dikkat çekiciydi. Bu izin, aynı zamanda **AppendData/AddSubdirectory** olarak da adlandırılan izin, betiğin bulgularıyla uyumludur.

Belirli değerleri doğrudan değiştirememe, ancak yeni alt anahtarlar oluşturma yeteneğinin olduğu belirtildi. Bir örnek olarak, **ImagePath** değerini değiştirmeye yönelik bir girişim, erişim reddedildi mesajıyla sonuçlandı.

Bu sınırlamalara rağmen, **RpcEptMapper** hizmetinin kayıt defteri yapısındaki **Performance** alt anahtarının kullanılmasıyla ayrıcalık yükseltme potansiyeli belirlendi. Bu, DLL kaydı ve performans izleme imkanı sağlayabilir.

**Performance** alt anahtarı ve performans izleme için kullanımıyla ilgili belgelere başvurularak, bir kanıt-of-kavram DLL'si geliştirildi. **OpenPerfData**, **CollectPerfData** ve **ClosePerfData** işlevlerinin uygulanmasını gösteren bu DLL, **rundll32** aracılığıyla test edilerek işletimsel başarısını doğruladı.

Amaç, **RPC Endpoint Mapper hizmetini** oluşturulan Performans DLL'sini yüklemeye zorlamaktı. Gözlemler, PowerShell aracılığıyla Performans Verileri ile ilgili WMI sınıf sorgularının yürütülmesinin bir günlük dosyasının oluşturulmasına yol açtığını ortaya koydu. Bu, **LOCAL SYSTEM** bağlamında keyfi kodun yürütülmesine olanak sağlayarak yükseltilmiş ayrıcalıklar sağlar.

Bu zafiyetin kalıcılığı ve potansiyel etkileri vurgulandı ve post-exploitasyon stratejileri, yan hareketlilik ve antivirüs/EDR sistemlerinden kaçınma için önemli olduğu belirtildi.

Zafiyetin başlangıçta betik aracılığıyla istemeden açığa çıkarıldığı, ancak sömürünün eski Windows sürümleriyle (örneğin, **Windows 7 / Server 2008 R2**) sınırlı olduğu ve yerel erişim gerektirdiği vurgulandı.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
