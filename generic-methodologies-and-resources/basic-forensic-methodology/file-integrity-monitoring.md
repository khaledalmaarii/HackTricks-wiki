{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}


# Temel

Bir temel, bir sistemin belirli parçalarının anlık bir görüntüsünü alarak **gelecekteki bir durumla karşılaştırmak ve değişiklikleri vurgulamak** için oluşturulur.

Örneğin, dosya sistemindeki her dosyanın karma değerini hesaplayıp depolayarak hangi dosyaların değiştirildiğini bulabilirsiniz.\
Bu aynı zamanda oluşturulan kullanıcı hesapları, çalışan işlemler, çalışan hizmetler ve hiç veya çok az değişmemesi gereken diğer herhangi bir şey ile de yapılabilir.

## Dosya Bütünlüğü İzleme

Dosya Bütünlüğü İzleme (FIM), dosyalardaki değişiklikleri izleyerek IT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. İki temel adım içerir:

1. **Temel Karşılaştırma:** Gelecekteki karşılaştırmalar için değişiklikleri tespit etmek için dosya öznitelikleri veya kriptografik karma değerleri (örneğin MD5 veya SHA-2) kullanarak bir temel oluşturun.
2. **Gerçek Zamanlı Değişiklik Bildirimi:** Dosyalara erişildiğinde veya değiştirildiğinde anında uyarılar alın, genellikle işletim sistemi çekirdek uzantıları aracılığıyla.

## Araçlar

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referanslar

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


{% hint style="success" %}
Öğren ve AWS Hacking pratiği yap:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Öğren ve GCP Hacking pratiği yap: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekle</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol et!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katıl veya [**telegram grubuna**](https://t.me/peass) katıl veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip et.**
* **Hacking püf noktalarını paylaşmak için PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulun.

</details>
{% endhint %}
