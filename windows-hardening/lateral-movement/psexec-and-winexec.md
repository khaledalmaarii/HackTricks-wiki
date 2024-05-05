# PsExec/Winexec/ScExec

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Nasıl Çalışırlar

Hizmet ikili dosyalarının SMB üzerinden uzaktan yürütme başarısına ulaşmak için aşağıdaki adımlarda özetlenen süreç:

1. **Hizmet ikili dosyasının SMB üzerindeki ADMIN$ paylaşımına kopyalanması** gerçekleştirilir.
2. Uzak makinede bir hizmet **oluşturulur** ve ikili dosyaya işaret edilir.
3. Hizmet **uzaktan başlatılır**.
4. Çıkışta, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'ın El ile Yürütme Süreci**

Msfvenom ile oluşturulan ve antivirus tespitini önlemek için Veil kullanılarak gizlenen 'met8888.exe' adlı yürütülebilir bir payload varsayılarak, aşağıdaki adımlar izlenir:

* **İkili dosyanın kopyalanması**: Yürütülebilir dosya, komut isteminden ADMIN$ paylaşımına kopyalanır, ancak gizli kalması için dosya sisteminin herhangi bir yerine yerleştirilebilir.
* **Hizmet oluşturma**: Uzak Windows hizmetlerini sorgulamaya, oluşturmaya ve silmeye izin veren Windows `sc` komutu kullanılarak, yüklenen ikili dosyaya işaret eden "meterpreter" adında bir hizmet oluşturulur.
* **Hizmeti başlatma**: Son adım, hizmetin başlatılmasını içerir, bu da büyük olasılıkla beklenen yanıt kodunu döndüremeyen gerçek bir hizmet ikili dosyası olmadığı için "zaman aşımı" hatası ile sonuçlanabilir. Bu hata, asıl amaç ikili dosyanın yürütülmesidir.

Metasploit dinleyicisinin oturumun başarıyla başlatıldığını göstereceği gözlemlenir.

[`sc` komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha detaylı adımları [buradan](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/) bulabilirsiniz.

**Ayrıca Windows Sysinternals ikili dosyası PsExec.exe'yi de kullanabilirsiniz:**

![](<../../.gitbook/assets/image (928).png>)

[**SharpLateral**](https://github.com/mertdas/SharpLateral)ı da kullanabilirsiniz:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına. 

</details>
