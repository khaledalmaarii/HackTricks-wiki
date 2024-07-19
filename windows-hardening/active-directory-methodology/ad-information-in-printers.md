{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


İnternette, **varsayılan/zayıf** oturum açma kimlik bilgileriyle yapılandırılmış yazıcıların tehlikelerini **vurgulayan** birkaç blog bulunmaktadır.\
Bu, bir saldırganın yazıcıyı **kötü niyetli bir LDAP sunucusuna kimlik doğrulaması yapmaya kandırabileceği** anlamına gelir (genellikle bir `nc -vv -l -p 444` yeterlidir) ve yazıcının **kimlik bilgilerini açık metin olarak** yakalayabilir.

Ayrıca, birçok yazıcı **kullanıcı adlarıyla günlükler** içerebilir veya hatta **Tüm kullanıcı adlarını** Alan Denetleyicisinden **indirme** yeteneğine sahip olabilir.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksiklikleri**, yazıcıları saldırganlar için çok ilginç hale getirir.

Konu hakkında bazı bloglar:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Yazıcı Yapılandırması
- **Konum**: LDAP sunucu listesi şurada bulunur: `Ağ > LDAP Ayarı > LDAP Kurulumu`.
- **Davranış**: Arayüz, kimlik bilgilerini yeniden girmeden LDAP sunucu değişikliklerine izin verir, bu kullanıcı kolaylığı için tasarlanmıştır ancak güvenlik riskleri taşır.
- **Sömürü**: Sömürü, LDAP sunucu adresini kontrol edilen bir makineye yönlendirmeyi ve kimlik bilgilerini yakalamak için "Bağlantıyı Test Et" özelliğini kullanmayı içerir.

## Kimlik Bilgilerini Yakalama

**Daha ayrıntılı adımlar için, orijinal [kaynağa](https://grimhacker.com/2018/03/09/just-a-printer/) bakın.**

### Yöntem 1: Netcat Dinleyici
Basit bir netcat dinleyici yeterli olabilir:
```bash
sudo nc -k -v -l -p 386
```
Ancak, bu yöntemin başarısı değişkenlik gösterir.

### Yöntem 2: Tam LDAP Sunucusu ile Slapd
Daha güvenilir bir yaklaşım, tam bir LDAP sunucusu kurmaktır çünkü yazıcı, kimlik bilgisi bağlamadan önce bir null bind ve ardından bir sorgu gerçekleştirir.

1. **LDAP Sunucu Kurulumu**: Kılavuz, [bu kaynaktan](https://www.server-world.info/en/note?os=Fedora_26&p=openldap) adımları takip eder.
2. **Ana Adımlar**:
- OpenLDAP'ı kurun.
- Yönetici şifresini yapılandırın.
- Temel şemaları içe aktarın.
- LDAP DB üzerinde alan adını ayarlayın.
- LDAP TLS'yi yapılandırın.
3. **LDAP Servisi Çalıştırma**: Kurulduktan sonra, LDAP servisi şu komutla çalıştırılabilir:
```bash
slapd -d 2
```
## Referanslar
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
