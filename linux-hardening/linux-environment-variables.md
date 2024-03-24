# Linux Ortam Değişkenleri

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Ailesi**]'ni keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**] koleksiyonumuz (https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**] (https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] veya bizi **Twitter** 🐦 [**@hacktricks_live**] (https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**] (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

**Try Hard Güvenlik Grubu**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Global değişkenler

Global değişkenler **çocuk işlemler** tarafından **devralınacaktır**.

Mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişken mevcut oturumlarınız ve onun alt süreçleri tarafından erişilebilir olacaktır.

Değişkeni **kaldırmak** için şunu yapabilirsiniz:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenler** yalnızca **mevcut kabuk/senkron** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Mevcut değişkenleri listele

```bash
printenv
```
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Ortak değişkenler

Kaynak: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır, bu da mevcut bilgisayardaki ilk ekranı temsil eder.
* **EDITOR** – kullanıcının tercih ettiği metin düzenleyici.
* **HISTFILESIZE** – geçmiş dosyasında bulunan maksimum satır sayısı.
* **HISTSIZE** – Kullanıcı oturumu sona erdiğinde geçmiş dosyasına eklenen satır sayısı.
* **HOME** – ev dizininiz.
* **HOSTNAME** – bilgisayarın ana bilgisayarı.
* **LANG** – mevcut diliniz.
* **MAIL** – kullanıcının posta havuzunun konumu. Genellikle **/var/spool/mail/USER**.
* **MANPATH** – kılavuz sayfalarını aramak için kullanılan dizinlerin listesi.
* **OSTYPE** – işletim sistemi türü.
* **PS1** – bash'teki varsayılan komut istemi.
* **PATH** – yürütmek istediğiniz ikili dosyaların bulunduğu tüm dizinlerin yolunu saklar, dosyanın adını belirterek yürütmek istediğiniz dosyayı göreceli veya mutlak yol belirtmeden yürütebilirsiniz.
* **PWD** – mevcut çalışma dizini.
* **SHELL** – geçerli komut kabuğunun yolu (örneğin, **/bin/bash**).
* **TERM** – mevcut terminal türü (örneğin, **xterm**).
* **TZ** – zaman diliminiz.
* **USER** – mevcut kullanıcı adınız.

## Hackleme için ilginç değişkenler

### **HISTFILESIZE**

Bu değişkenin **değerini 0 olarak değiştirin**, böylece **oturumunuzu sonlandırdığınızda** geçmiş dosyası (\~/.bash\_history) **silinecektir**.
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

**Bu çevre değişkenlerinde** belirtilen sertifikalara işlemler güvenecektir.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Promptunuzu nasıl göründüğünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Normal kullanıcı:

![](<../.gitbook/assets/image (88).png>)

Bir, iki ve üç arka planda çalışan işler:

![](<../.gitbook/assets/image (89).png>)

Bir arka planda çalışan iş, bir durdurulan iş ve son komut doğru bir şekilde tamamlanmadı:

![](<../.gitbook/assets/image (90).png>)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
