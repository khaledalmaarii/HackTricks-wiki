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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Logstash

Logstash, **logları toplamak, dönüştürmek ve dağıtmak** için **pipeline** olarak bilinen bir sistem kullanır. Bu pipeline'lar **giriş**, **filtre** ve **çıkış** aşamalarından oluşur. Logstash, ele geçirilmiş bir makinede çalıştığında ilginç bir durum ortaya çıkar.

### Pipeline Yapılandırması

Pipeline'lar, pipeline yapılandırmalarının yerlerini listeleyen **/etc/logstash/pipelines.yml** dosyasında yapılandırılır:
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
Bu dosya, **.conf** dosyalarının, pipeline yapılandırmalarını içeren yerlerini ortaya koymaktadır. **Elasticsearch output module** kullanıldığında, **pipelines**'in genellikle **Elasticsearch kimlik bilgilerini** içerdiği yaygındır; bu kimlik bilgileri, Logstash'ın Elasticsearch'e veri yazma gereksinimi nedeniyle genellikle geniş yetkilere sahiptir. Yapılandırma yollarındaki joker karakterler, Logstash'ın belirlenen dizindeki tüm eşleşen pipeline'ları çalıştırmasına olanak tanır.

### Yazılabilir Pipelines ile Yetki Yükseltme

Yetki yükseltme girişiminde bulunmak için, öncelikle Logstash hizmetinin çalıştığı kullanıcıyı belirleyin, genellikle **logstash** kullanıcısıdır. Aşağıdaki **bir** kriterden birine sahip olduğunuzdan emin olun:

- Bir pipeline **.conf** dosyasına **yazma erişiminiz** var **veya**
- **/etc/logstash/pipelines.yml** dosyası bir joker karakter kullanıyor ve hedef klasöre yazabiliyorsunuz

Ayrıca, **bir** bu koşullardan biri yerine getirilmelidir:

- Logstash hizmetini yeniden başlatma yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarı var

Yapılandırmada bir joker karakter verildiğinde, bu joker karakterle eşleşen bir dosya oluşturmak, komut yürütmeye olanak tanır. Örneğin:
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
Burada, **interval** yürütme sıklığını saniye cinsinden belirler. Verilen örnekte, **whoami** komutu her 120 saniyede bir çalışır ve çıktısı **/tmp/output.log** dosyasına yönlendirilir.

**/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarı ile Logstash, yeni veya değiştirilmiş boru hattı yapılandırmalarını otomatik olarak algılayacak ve uygulayacaktır; yeniden başlatmaya gerek kalmadan. Eğer bir joker karakter yoksa, mevcut yapılandırmalarda değişiklikler yapılabilir, ancak kesintileri önlemek için dikkatli olunması önerilir.
