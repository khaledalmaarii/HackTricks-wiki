# Docker Forensiği

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Konteyner değişikliği

Bir docker konteynerinin bazı şekilde tehlikeye atıldığından şüpheleniliyor:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Bu konteynerde yapılan değişiklikleri görmeniz için şunları yapabilirsiniz:
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
Önceki komutta **C** **Değiştirildi** ve **A,** **Eklendi** anlamına gelir.\
Eğer `/etc/shadow` gibi ilginç bir dosyanın değiştirildiğini tespit ederseniz, kötü amaçlı faaliyetleri kontrol etmek için bu dosyayı konteynırdan indirebilirsiniz:
```bash
docker cp wordpress:/etc/shadow.
```
Ayrıca, yeni bir konteyner çalıştırarak ve içinden dosyayı çıkararak orijinaliyle **karşılaştırabilirsiniz**:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Eğer **şüpheli bir dosya eklenmişse** konteynere erişebilir ve kontrol edebilirsiniz:
```bash
docker exec -it wordpress bash
```
## Görüntü değişiklikleri

Bir dışa aktarılmış docker görüntüsü (muhtemelen `.tar` formatında) verildiğinde, [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanarak **değişikliklerin bir özetini çıkarmak** için aşağıdaki adımları izleyebilirsiniz:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ardından, görüntüyü **sıkıştırılmış** hâlden çıkarabilir ve şüpheli dosyaları aramak için **bloklara erişebilirsiniz**. Bu dosyaları değişiklik geçmişinde bulmuş olabilirsiniz:
```bash
tar -xf image.tar
```
### Temel Analiz

Çalışan görüntüden **temel bilgiler** alabilirsiniz:
```bash
docker inspect <image>
```
Ayrıca, bir özet **değişiklik geçmişi** alabilirsiniz:
```bash
docker history --no-trunc <image>
```
Ayrıca bir görüntüden bir **dockerfile oluşturabilirsiniz**:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker görüntülerinde eklenen/değiştirilen dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) (indirin: [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) aracını da kullanabilirsiniz:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, farklı docker görüntülerinin farklı bloblarında gezinmenizi sağlar ve hangi dosyaların değiştirildiğini/eklendiğini kontrol edebilirsiniz. **Kırmızı** eklenen anlamına gelir ve **sarı** değiştirilen anlamına gelir. Diğer görünüme geçmek için **tab** tuşunu kullanın ve klasörleri daraltmak/açmak için **boşluk** tuşunu kullanın.

Die ile görüntünün farklı aşamalarının içeriğine erişemezsiniz. Bunun için her katmanı açmanız ve erişmeniz gerekecektir.\
Görüntünün tüm katmanlarını açmak için görüntünün açıldığı dizinde aşağıdaki komutu çalıştırın:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten Kimlik Bilgileri

Docker konteynerini bir ana bilgisayar içinde çalıştırdığınızda, ana bilgisayardan sadece `ps -ef` komutunu çalıştırarak konteynerde çalışan işlemleri görebilirsiniz.

Bu nedenle (root olarak), ana bilgisayardan işlemlerin belleğini **dökerek** ve [**aşağıdaki örnekte olduğu gibi**](../../linux-hardening/privilege-escalation/#process-memory) **kimlik bilgilerini arayabilirsiniz**.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'i öğrenin</strong>!</summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
