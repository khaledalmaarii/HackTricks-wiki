# Linux Ortam Değişkenleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Global değişkenler

Global değişkenler **alt süreçler** tarafından **miras alınır**.

Mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişken mevcut oturumunuz ve onun alt süreçleri tarafından erişilebilir olacak.

Bir değişkeni **kaldırmak** için şunu yapabilirsiniz:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenler**, yalnızca **geçerli kabuk/yazılım** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Mevcut değişkenleri listele

To list the current environment variables in Linux, you can use the following command:

```bash
printenv
```

This command will display a list of all the environment variables currently set in your Linux system.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Ortak değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** - **X** tarafından kullanılan ekran. Bu değişken genellikle mevcut bilgisayardaki ilk ekran olan **:0.0** olarak ayarlanır.
* **EDITOR** - kullanıcının tercih ettiği metin düzenleyici.
* **HISTFILESIZE** - geçmiş dosyasında bulunan satır sayısının maksimum değeri.
* **HISTSIZE** - Kullanıcı oturumunu bitirdiğinde geçmiş dosyasına eklenen satır sayısı.
* **HOME** - ev dizininiz.
* **HOSTNAME** - bilgisayarın ana bilgisayarı.
* **LANG** - mevcut diliniz.
* **MAIL** - kullanıcının posta spool'unun konumu. Genellikle **/var/spool/mail/USER**.
* **MANPATH** - man sayfalarını aramak için kullanılan dizinlerin listesi.
* **OSTYPE** - işletim sistemi türü.
* **PS1** - bash'teki varsayılan komut istemi.
* **PATH** - yürütmek istediğiniz ikili dosyaların bulunduğu tüm dizinlerin yolu. Dosyanın adını belirtmek için göreli veya mutlak yol kullanmadan yürütmek istediğiniz ikili dosyaların bulunduğu tüm dizinlerin yolu.
* **PWD** - mevcut çalışma dizini.
* **SHELL** - geçerli komut kabuğunun yolu (örneğin, **/bin/bash**).
* **TERM** - mevcut terminal türü (örneğin, **xterm**).
* **TZ** - zaman diliminiz.
* **USER** - mevcut kullanıcı adınız.

## Sızma testi için ilginç değişkenler

### **HISTFILESIZE**

Bu değişkenin **değerini 0** olarak değiştirin, böylece **oturumunuzu sonlandırdığınızda** geçmiş dosyası (\~/.bash\_history) **silinir**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Bu değişkenin değerini 0 olarak değiştirin, böylece **oturumunuzu sonlandırdığınızda** herhangi bir komut **geçmiş dosyasına** (\~/.bash\_history) eklenmeyecektir.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

İşlemler, internete bağlanmak için burada belirtilen **proxy**'yi kullanacak. Bu proxy, **http veya https** üzerinden bağlantı kurmak için kullanılır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Bu ortam değişkenlerinde belirtilen sertifikaları işlemler güvenecektir.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Prompt görünümünü nasıl değiştireceğinizi öğrenin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Normal kullanıcı:

![](<../.gitbook/assets/image (88).png>)

Bir, iki ve üç arka planda çalışan iş:

![](<../.gitbook/assets/image (89).png>)

Bir arka planda çalışan iş, bir durdurulan iş ve son komut doğru şekilde tamamlanmadı:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
