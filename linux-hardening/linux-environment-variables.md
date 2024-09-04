# Linux Ortam Değişkenleri

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Küresel değişkenler

Küresel değişkenler **çocuk süreçler** tarafından **devralınacaktır**.

Mevcut oturumunuz için bir küresel değişken oluşturmak için:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişken, mevcut oturumlarınız ve bunların alt süreçleri tarafından erişilebilir olacaktır.

Bir değişkeni **kaldırmak** için:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenler** yalnızca **geçerli shell/script** tarafından **erişilebilir**.
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
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır, bu da mevcut bilgisayardaki ilk ekranı ifade eder.
* **EDITOR** – kullanıcının tercih ettiği metin düzenleyici.
* **HISTFILESIZE** – geçmiş dosyasında bulunan maksimum satır sayısı.
* **HISTSIZE** – kullanıcının oturumunu bitirdiğinde geçmiş dosyasına eklenen satır sayısı.
* **HOME** – ev dizininiz.
* **HOSTNAME** – bilgisayarın ana bilgisayar adı.
* **LANG** – mevcut diliniz.
* **MAIL** – kullanıcının posta kuyruğunun yeri. Genellikle **/var/spool/mail/USER**.
* **MANPATH** – kılavuz sayfalarını aramak için dizinler listesi.
* **OSTYPE** – işletim sisteminin türü.
* **PS1** – bash'deki varsayılan istem.
* **PATH** – yalnızca dosya adını belirterek çalıştırmak istediğiniz ikili dosyaların bulunduğu tüm dizinlerin yolunu saklar, göreli veya mutlak yol ile değil.
* **PWD** – mevcut çalışma dizini.
* **SHELL** – mevcut komut kabuğunun yolu (örneğin, **/bin/bash**).
* **TERM** – mevcut terminal türü (örneğin, **xterm**).
* **TZ** – zaman diliminiz.
* **USER** – mevcut kullanıcı adınız.

## Interesting variables for hacking

### **HISTFILESIZE**

Bu değişkenin **değerini 0 olarak değiştirin**, böylece **oturumunuzu bitirdiğinizde** **geçmiş dosyası** (\~/.bash\_history) **silinecektir**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Bu **değişkenin değerini 0 olarak değiştirin**, böylece **oturumunuzu sonlandırdığınızda** herhangi bir komut **tarih dosyasına** (\~/.bash\_history) eklenecektir.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

İşlemler, **http veya https** üzerinden internete bağlanmak için burada belirtilen **proxy**'yi kullanacaktır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

İşlemler, **bu ortam değişkenlerinde** belirtilen sertifikalara güvenecektir.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

İstediğiniz şekilde istemci görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Normal kullanıcı:

![](<../.gitbook/assets/image (740).png>)

Bir, iki ve üç arka planda çalışan iş:

![](<../.gitbook/assets/image (145).png>)

Bir arka planda çalışan iş, bir durdurulmuş ve son komut doğru bir şekilde bitmedi:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
