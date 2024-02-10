# Python İçsel Okuma Araçları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'i **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

[**Python Format Dizeleri**](bypass-python-sandboxes/#python-format-string) veya [**Sınıf Kirliliği**](class-pollution-pythons-prototype-pollution.md) gibi farklı zayıflıklar, **python içsel verilerini okumanıza izin verebilir, ancak kodu yürütmenize izin vermeyebilir**. Bu nedenle, bir pentester, bu okuma izinlerinden **duyarlı ayrıcalıklar elde etmek ve zayıflığı yükseltmek** için en iyi şekilde yararlanmalıdır.

### Flask - Gizli anahtarı okuma

Bir Flask uygulamasının ana sayfasında, bu **gizli anahtarın yapılandırıldığı** **`app`** global nesnesi olabilir.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, [Python kum havuzlarını atlatma sayfasından](bypass-python-sandboxes/) herhangi bir araç kullanarak bu nesneye erişmek mümkündür.

**Zafiyet başka bir Python dosyasında ise**, ana dosyaya ulaşmak için dosyaları gezinmek için bir araca ihtiyacınız vardır. Bu şekilde Flask gizli anahtarını değiştirerek [bu anahtarı bilerek](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) ayrıcalıkları yükseltebilirsiniz.

Bu yazıdan bir örnek yük:

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Bu payload'ı kullanarak `app.secret_key`'i (uygulamanızdaki adı farklı olabilir) değiştirerek yeni ve daha fazla yetkiye sahip flask çerezlerini imzalayabilirsiniz.

### Werkzeug - machine\_id ve node uuid

[**Bu yazıdan bu payload'ı kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine\_id** ve **uuid** düğümüne erişebilirsiniz, bunlar [**Werkzeug pinini oluşturmak için**](../../network-services-pentesting/pentesting-web/werkzeug.md) ihtiyaç duyduğunuz **ana sırlardır**. Eğer **hata ayıklama modu etkinse**, `/console` içinde python konsoluna erişmek için kullanabileceğiniz Werkzeug pinini oluşturabilirsiniz:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Dikkat, `app.py` dosyasının **sunucunun yerel yolunu** alabilirsiniz, web sayfasında bir **hata** oluşturarak yolunuzu **elde edebilirsiniz**.
{% endhint %}

Eğer zafiyet başka bir python dosyasında ise, ana python dosyasından nesnelere erişmek için önceki Flask hilesine bakın.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
