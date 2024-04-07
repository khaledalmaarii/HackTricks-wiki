# SmbExec/ScExec

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'da **takip edin**.
* **Hacking püf noktalarınızı göndererek PR'ler aracılığıyla** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Nasıl Çalışır

**Smbexec**, hedef sistemlerde uzaktan komut yürütme için kullanılan bir araçtır, **Psexec** gibi, ancak hedef sistemde herhangi bir kötü amaçlı dosya bırakmadan çalışır.

### **SMBExec** Hakkında Ana Noktalar

- Komutları cmd.exe (%COMSPEC%) aracılığıyla yürütmek için hedef makinede geçici bir hizmet oluşturarak çalışır (örneğin, "BTOBTO"), herhangi bir ikili dosya bırakmadan.
- Gizli yaklaşımına rağmen, her yürütülen komut için olay günlükleri oluşturur, etkileşimsiz bir "shell" sunar.
- **Smbexec** kullanarak bağlanma komutu şu şekildedir:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Komutlar Olmadan Komut Yürütme

- **Smbexec**, hedefte fiziksel ikili dosyalara gerek olmadan hizmet binPaths aracılığıyla doğrudan komut yürütme imkanı sağlar.
- Bu yöntem, Windows hedefinde tek seferlik komutların yürütülmesi için kullanışlıdır. Örneğin, Metasploit'in `web_delivery` modülü ile eşleştirilerek PowerShell hedefli ters Meterpreter yükü yürütülmesine olanak tanır.
- Saldırganın makinesinde, cmd.exe aracılığıyla sağlanan komutu çalıştırmak üzere binPath ayarlanmış uzaktan bir hizmet oluşturarak, hizmet yanıt hataları meydana gelse bile, payload'ın başarılı bir şekilde yürütülmesi ve Metasploit dinleyicisi ile geri arama yapılması mümkündür.

### Komut Örneği

Hizmetin oluşturulması ve başlatılması aşağıdaki komutlarla gerçekleştirilebilir:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
## Referanslar
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>A'dan Z'ye AWS hackleme konusunda bilgi edinin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
