<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek**.

</details>


İnternette, LDAP ile yapılandırılmış yazıcıların varsayılan/zayıf giriş kimlik bilgileriyle bırakılmasının tehlikelerini vurgulayan birkaç blog bulunmaktadır.\
Bu, bir saldırganın yazıcıyı, genellikle bir `nc -vv -l -p 444` yeterli olan sahte bir LDAP sunucusuna kimlik doğrulaması yapmaya ve yazıcıdaki kimlik bilgilerini açık metin olarak yakalamaya kandırabileceği anlamına gelir.

Ayrıca, birçok yazıcı **kullanıcı adlarıyla günlükler içerebilir** veya etki alanı denetleyicisinden **tüm kullanıcı adlarını indirebilir**.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksikliği**, saldırganlar için yazıcıları çok ilginç hale getirir.

Konuyla ilgili bazı bloglar:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Yazıcı Yapılandırması
- **Konum**: LDAP sunucu listesi şurada bulunur: `Ağ > LDAP Ayarı > LDAP Kurulumu`.
- **Davranış**: Arayüz, kimlik bilgilerini yeniden girmeden LDAP sunucusu değişikliklerine izin verir, bu da kullanıcı kolaylığı hedeflerken güvenlik riskleri oluşturur.
- **Sömürü**: Sömürü, LDAP sunucusu adresini kontrol edilen bir makineye yönlendirmeyi ve kimlik bilgilerini yakalamak için "Bağlantıyı Test Et" özelliğini kullanmayı içerir.

## Kimlik Bilgilerini Yakalama

**Daha ayrıntılı adımlar için, orijinal [kaynağa](https://grimhacker.com/2018/03/09/just-a-printer/) bakın.**

### Yöntem 1: Netcat Dinleyici
Basit bir netcat dinleyicisi yeterli olabilir:
```bash
sudo nc -k -v -l -p 386
```
### Yöntem 2: Slapd ile Tam LDAP Sunucusu
Daha güvenilir bir yaklaşım, yazıcının kimlik bilgisi bağlama girişiminden önce bir null bağlama ve sorgu gerçekleştirmesi nedeniyle tam bir LDAP sunucusu kurmaktır.

1. **LDAP Sunucusu Kurulumu**: Kılavuz, [bu kaynaktaki](https://www.server-world.info/en/note?os=Fedora_26&p=openldap) adımları takip eder.
2. **Ana Adımlar**:
- OpenLDAP'ı kurun.
- Yönetici şifresini yapılandırın.
- Temel şemaları içe aktarın.
- LDAP DB üzerinde etki alanı adını ayarlayın.
- LDAP TLS'yi yapılandırın.
3. **LDAP Hizmeti Yürütme**: Kurulum tamamlandıktan sonra, LDAP hizmeti aşağıdaki komutla çalıştırılabilir:
```bash
slapd -d 2
```
## Referanslar
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın**.

</details>
