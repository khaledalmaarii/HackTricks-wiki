<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


## Logstash

Logstash, **günlükleri toplamak, dönüştürmek ve iletmek** için bir sistem olan **pipeline'lar** aracılığıyla kullanılır. Bu pipeline'lar, **giriş**, **filtre** ve **çıkış** aşamalarından oluşur. Logstash, bir kompromize uğramış bir makinede çalıştığında ilginç bir yön ortaya çıkar.

### Pipeline Yapılandırması

Pipeline'lar, **/etc/logstash/pipelines.yml** dosyasında yapılandırılır ve bu dosya pipeline yapılandırmalarının konumlarını listeler:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Bu dosya, pipeline yapılandırmalarını içeren **.conf** dosyalarının nerede bulunduğunu ortaya çıkarır. Bir **Elasticsearch çıkış modülü** kullanırken, genellikle **pipelines** Elasticsearch kimlik bilgilerini içerir. Bu kimlik bilgileri, Logstash'in Elasticsearch'e veri yazma ihtiyacından dolayı genellikle geniş yetkilere sahiptir. Yapılandırma yollarındaki joker karakterler, Logstash'in belirtilen dizindeki tüm eşleşen pipeline'ları çalıştırmasına olanak tanır.

### Yazılabilir Pipeline'lar Aracılığıyla Yetki Yükseltme

Yetki yükseltme denemeleri için öncelikle Logstash servisinin hangi kullanıcı altında çalıştığını belirleyin, genellikle **logstash** kullanıcısıdır. Aşağıdaki kriterlerden **birini** karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **yazma erişiminiz** var **veya**
- **/etc/logstash/pipelines.yml** dosyası bir joker karakter kullanıyor ve hedef klasöre yazabilirsiniz

Ek olarak, aşağıdaki koşullardan **birini** karşılamak gerekmektedir:

- Logstash servisini yeniden başlatma yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarlıdır

Yapılandırmada bir joker karakter olduğunda, bu joker karakterle eşleşen bir dosya oluşturmak komut yürütme imkanı sağlar. Örneğin:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
İşte, **interval** saniye cinsinden çalışma sıklığını belirler. Verilen örnekte, **whoami** komutu 120 saniyede bir çalışır ve çıktısı **/tmp/output.log** dosyasına yönlendirilir.

**/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** olduğunda, Logstash yeni veya değiştirilmiş pipeline yapılandırmalarını otomatik olarak algılar ve uygular, yeniden başlatma gerektirmez. Joker karakteri yoksa, mevcut yapılandırmalara hala değişiklikler yapılabilir, ancak kesintileri önlemek için dikkatli olunması önerilir.


## Referanslar

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
