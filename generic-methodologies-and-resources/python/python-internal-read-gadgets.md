# Python İçsel Okuma Araçları

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Temel Bilgiler

[**Python Format Strings**](bypass-python-sandboxes/#python-format-string) veya [**Sınıf Kirliliği**](class-pollution-pythons-prototype-pollution.md) gibi farklı zafiyetler size **Python iç verilerini okuma imkanı sağlayabilir ancak kodu yürütmenize izin vermeyebilir**. Bu nedenle, bir pentester'ın bu okuma izinlerinden en iyi şekilde yararlanarak **duyarlı ayrıcalıkları elde etmesi ve zafiyeti yükseltmesi gerekecektir**.

### Flask - Gizli anahtarı okuma

Bir Flask uygulamasının ana sayfasında muhtemelen **`app`** global nesnesi bulunur ve bu nesne üzerinde **gizli anahtar yapılandırılmış olabilir**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, bu nesneye erişmek için sadece herhangi bir araca sahip olmak mümkündür ve [**Python kum havuzlarını atlatma sayfasından**](bypass-python-sandboxes/) **global nesnelere erişmek** mümkündür.

**Zafiyet farklı bir python dosyasında olduğunda**, ana dosyaya ulaşmak için dosyalar arasında gezinmek için bir araca ihtiyacınız vardır ve Flask gizli anahtarını değiştirmek ve [**bu anahtarı bilerek ayrıcalıkları yükseltmek** için](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) **global nesne `app.secret_key`'e erişmek** gerekir.

Bu yazıdan bir payload gibi:

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Bu payload'ı kullanarak `app.secret_key`'i (uygulamanızdaki ad farklı olabilir) değiştirin ve yeni ve daha fazla ayrıcalıklı flask çerezlerini imzalayabilin.

### Werkzeug - machine\_id ve node uuid

[**Bu yazıdan bu payload'ı kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine\_id** ve **uuid** düğmesine erişebilecek ve [**Werkzeug pinini oluşturmak için gereken ana sırlara**](../../network-services-pentesting/pentesting-web/werkzeug.md) erişebileceksiniz. Bu pin'i kullanarak `/console` içinde python konsoluna erişebilirsiniz eğer **hata ayıklama modu etkinse:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
**Sunucunun yerel yolunu** `app.py` **dosyasına** ulaşmak için web sayfasında **bazı hatalar oluşturarak** yolunuzu **alabilirsiniz**.
{% endhint %}

Eğer zafiyet farklı bir python dosyasında ise, ana python dosyasından nesnelere erişmek için önceki Flask hilesini kontrol edin.

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>**HackTricks'i Destekleyin**</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) **kontrol edin**!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) **katılın** veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) **ve** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github depolarına katkıda bulunun**.

</details>
{% endhint %}
