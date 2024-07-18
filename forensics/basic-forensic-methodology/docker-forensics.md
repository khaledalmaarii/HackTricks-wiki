# Docker Adli Bilişim

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Konteyner Değişikliği

Bazı docker konteynerinin tehlikeye atıldığına dair şüpheler var:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Aşağıdaki komutla bu konteynıra yapılan değişiklikleri görüntüleyebilirsiniz:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Önceki komutta **C** **Değiştirildi** anlamına gelir ve **A,** **Eklendi** anlamına gelir.\
Eğer `/etc/shadow` gibi ilginç bir dosyanın değiştirildiğini fark ederseniz, kötü amaçlı faaliyetleri kontrol etmek için dosyayı konteynerden indirebilirsiniz:
```bash
docker cp wordpress:/etc/shadow.
```
Ayrıca, yeni bir konteyner çalıştırarak ve dosyayı ondan çıkararak **orijinaliyle karşılaştırabilirsiniz**:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Eğer **şüpheli bir dosyanın eklendiğini** tespit ederseniz, konteynıra erişebilir ve kontrol edebilirsiniz:
```bash
docker exec -it wordpress bash
```
## Resim Modifikasyonları

Size bir dışa aktarılmış docker imajı verildiğinde (muhtemelen `.tar` formatında) **modifikasyonların özetini çıkarmak** için [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanabilirsiniz:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ardından, görüntüyü **çözebilir** ve şüpheli dosyalar aramak için **bloklara erişebilirsiniz** bulduğunuz değişiklik geçmişinde:
```bash
tar -xf image.tar
```
### Temel Analiz

Çalışan görüntüden **temel bilgileri** alabilirsiniz:
```bash
docker inspect <image>
```
Ayrıca bir özet **değişiklik geçmişi** alabilirsiniz:
```bash
docker history --no-trunc <image>
```
Ayrıca bir görüntüden bir **dockerfile oluşturabilirsiniz** şu şekilde:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dalış

Docker görüntülerinde eklenen/değiştirilen dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) aracını da kullanabilirsiniz (indirmek için [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) sayfasına gidin):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, Docker görüntülerinin farklı blokları arasında gezinmenizi sağlar ve hangi dosyaların değiştirildiğini/eklendiğini kontrol edebilirsiniz. **Kırmızı** eklenen anlamına gelir ve **sarı** değiştirilen anlamına gelir. Diğer görünüme geçmek için **tab** tuşunu kullanın ve klasörleri kapatmak/açmak için **boşluk** tuşunu kullanın.

Die ile görüntünün farklı aşamalarının içeriğine erişemezsiniz. Bunun için **her katmanı açmanız ve erişmeniz gerekir**.\
Görüntünün tüm katmanlarını açmak için görüntünün açıldığı dizinden şu komutu çalıştırarak açabilirsiniz:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten Kimlik Bilgileri

Dikkat edin, bir ana makine içinde bir docker konteyneri çalıştırdığınızda **ana makineden konteynerde çalışan işlemleri görebilirsiniz** sadece `ps -ef` komutunu çalıştırarak

Bu nedenle (kök olarak) ana makineden işlemlerin belleğini **dökerek** ve [**aşağıdaki örnekte olduğu gibi**](../../linux-hardening/privilege-escalation/#process-memory) **kimlik bilgilerini arayabilirsiniz**.

{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
