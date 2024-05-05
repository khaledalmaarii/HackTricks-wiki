# Linux Ortam Değişkenleri

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

**Try Hard Güvenlik Grubu**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Global değişkenler

Global değişkenler **çocuk işlemler tarafından** devralınacaktır.

Mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişken mevcut oturumunuz ve onun alt süreçleri tarafından erişilebilir olacaktır.

Değişkeni **kaldırmak** için şunu yapabilirsiniz:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenler** yalnızca **mevcut kabuk / betik** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Mevcut değişkenleri listele
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Ortak değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır, bu da mevcut bilgisayardaki ilk ekranı ifade eder.
* **EDITOR** – kullanıcının tercih ettiği metin düzenleyici.
* **HISTFILESIZE** – geçmiş dosyasında bulunan maksimum satır sayısı.
* **HISTSIZE** – Kullanıcı oturumu sona erdiğinde geçmiş dosyasına eklenen satır sayısı.
* **HOME** – ev dizininiz.
* **HOSTNAME** – bilgisayarın ana bilgisayarı.
* **LANG** – mevcut diliniz.
* **MAIL** – kullanıcının posta spool'unun konumu. Genellikle **/var/spool/mail/USER**.
* **MANPATH** – man sayfalarını aramak için kullanılan dizinlerin listesi.
* **OSTYPE** – işletim sistemi türü.
* **PS1** – bash'teki varsayılan komut istemi.
* **PATH** – yürütmek istediğiniz ikili dosyaların bulunduğu tüm dizinlerin yolunu saklar, dosyanın adını belirterek yürütmek için göreli veya mutlak yol belirtmek zorunda kalmazsınız.
* **PWD** – mevcut çalışma dizini.
* **SHELL** – geçerli komut kabuğunun yolu (örneğin, **/bin/bash**).
* **TERM** – mevcut terminal türü (örneğin, **xterm**).
* **TZ** – zaman diliminiz.
* **USER** – mevcut kullanıcı adınız.

## Hacking için ilginç değişkenler

### **HISTFILESIZE**

Bu değişkenin **değerini 0 olarak değiştirin**, böylece oturumunuzu sonlandırdığınızda geçmiş dosyası (\~/.bash\_history) **silinecektir**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Bu değişkenin **değerini 0 yapın**, böylece **oturumunuzu sonlandırdığınızda** herhangi bir komut **geçmiş dosyasına** (\~/.bash\_history) eklenmeyecektir.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

İşlemler, internete bağlanmak için burada belirtilen **proxy**'yi kullanacaklar.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

**Bu ortam değişkenlerinde** belirtilen sertifikalara işlemler güvenecektir.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Prompt'unuzu nasıl göründüğünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Kök:

![](<../.gitbook/assets/image (897).png>)

Normal kullanıcı:

![](<../.gitbook/assets/image (740).png>)

Bir, iki ve üç arka planda çalışan işler:

![](<../.gitbook/assets/image (145).png>)

Bir arka planda çalışan iş, bir durdurulan iş ve son komut doğru bir şekilde tamamlanmadı:

![](<../.gitbook/assets/image (715).png>)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking hilelerinizi paylaşarak PR'lar göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
