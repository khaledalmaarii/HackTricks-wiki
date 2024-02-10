# PsExec/Winexec/ScExec

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

## Nasıl çalışırlar

Hizmet ikili dosyalarının SMB üzerinden hedef makinede uzaktan yürütme elde etmek için nasıl manipüle edildiğini gösteren aşağıdaki adımlarla işlem açıklanmıştır:

1. **SMB üzerinden bir hizmet ikili dosyasının ADMIN$ paylaşımına kopyalanması** gerçekleştirilir.
2. **Uzak makinede bir hizmet oluşturulması**, ikili dosyaya işaret ederek yapılır.
3. Hizmet **uzaktan başlatılır**.
4. Çıkış yapıldığında, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'ın El ile Yürütülme Süreci**

Antivirüs tespitinden kaçınmak için msfvenom ile oluşturulmuş ve Veil kullanılarak gizlenmiş bir yürütülebilir payload olduğunu varsayarsak, 'met8888.exe' adında bir meterpreter reverse_http payloadunu temsil eden aşağıdaki adımlar izlenir:

- **İkili dosyanın kopyalanması**: Yürütülebilir dosya, komut isteminden ADMIN$ paylaşımına kopyalanır, ancak gizlenmek için dosya sisteminin herhangi bir yerine yerleştirilebilir.

- **Bir hizmet oluşturma**: Uzaktan Windows hizmetlerini sorgulamaya, oluşturmaya ve silmeye olanak tanıyan Windows `sc` komutunu kullanarak, yüklenen ikili dosyaya işaret eden "meterpreter" adında bir hizmet oluşturulur.

- **Hizmetin başlatılması**: Son adım, hizmetin başlatılmasını içerir, bu da ikili dosyanın gerçek bir hizmet ikili dosyası olmaması ve beklenen yanıt kodunu döndürememesi nedeniyle muhtemelen bir "zaman aşımı" hatasıyla sonuçlanır. Bu hata önemsizdir çünkü asıl amaç ikili dosyanın yürütülmesidir.

Metasploit dinleyicisinin başarılı bir şekilde başlatıldığını gösteren bir oturum başlatıldığı gözlemlenecektir.

[`sc` komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha ayrıntılı adımları burada bulabilirsiniz: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Ayrıca Windows Sysinternals ikili dosyası PsExec.exe'yi kullanabilirsiniz:**

![](<../../.gitbook/assets/image (165).png>)

Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
