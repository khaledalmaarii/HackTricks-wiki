# SmbExec/ScExec

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Nasıl Çalışır

**Smbexec**, hedef sistemlere uzaktan komut yürütme için kullanılan bir araçtır. **Psexec** gibi, ancak hedef sisteme herhangi bir zararlı dosya yerleştirmeyi önler.

### **SMBExec** Hakkında Önemli Noktalar

- Komutları cmd.exe (%COMSPEC%) aracılığıyla (%COMSPEC%) çalıştırmak için hedef makinede geçici bir hizmet (örneğin, "BTOBTO") oluşturarak çalışır ve herhangi bir ikili dosya bırakmaz.
- Gizli yaklaşımına rağmen, her bir komutun yürütülmesi için olay günlükleri oluşturur ve etkileşimsiz bir "shell" sunar.
- **Smbexec** kullanarak bağlanmak için kullanılan komut şu şekildedir:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Komutları Binaries Olmadan Çalıştırma

- **Smbexec**, hedefte fiziksel binarylere ihtiyaç duymadan hizmet binPaths üzerinden doğrudan komut yürütme imkanı sağlar.
- Bu yöntem, Windows hedefinde tek seferlik komutları çalıştırmak için kullanışlıdır. Örneğin, Metasploit'in `web_delivery` modülü ile eşleştirilerek PowerShell hedefli ters Meterpreter yükü çalıştırılabilir.
- Saldırganın makinesinde, binPath'in cmd.exe üzerinden sağlanan komutu çalıştırmasını sağlayacak şekilde uzaktan bir hizmet oluşturarak, payload başarıyla çalıştırılabilir ve Metasploit dinleyicisi ile geri çağrı ve payload yürütme elde edilebilir, hatta hizmet yanıt hataları oluşsa bile.

### Komut Örneği

Hizmetin oluşturulması ve başlatılması aşağıdaki komutlarla gerçekleştirilebilir:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Daha fazla ayrıntı için [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/) adresini kontrol edin.


## Referanslar
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
