<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'ler**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


Doğru namespace izolasyonu olmadan `/proc` ve `/sys` dizinlerinin açığa çıkarılması, saldırı yüzeyini genişletme ve bilgi sızdırma gibi önemli güvenlik risklerine neden olur. Bu dizinler, yanlış yapılandırılmış veya yetkisiz bir kullanıcı tarafından erişildiğinde, konteyner kaçışına, ana bilgisayarın değiştirilmesine veya daha fazla saldırıya yardımcı olacak bilgilerin sağlanmasına yol açabilir. Örneğin, `-v /proc:/host/proc` yanlış bir şekilde bağlandığında, yol tabanlı doğası nedeniyle AppArmor korumasını atlayabilir ve `/host/proc` korumasız bırakabilir.

**Her potansiyel zafiyetin daha fazla ayrıntısını [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts) adresinde bulabilirsiniz.**

# procfs Zafiyetleri

## `/proc/sys`
Bu dizin, genellikle `sysctl(2)` aracılığıyla çekirdek değişkenlerini değiştirmeye izin verir ve endişe kaynağı olan birkaç alt dizin içerir:

### **`/proc/sys/kernel/core_pattern`**
- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) adresinde açıklanmıştır.
- İlk 128 baytı argüman olarak kullanan bir programın çekirdek dosyası oluşturulduğunda yürütülmesine izin verir. Bu, dosyanın bir boru `|` ile başlaması durumunda kod yürütülmesine yol açabilir.
- **Test Etme ve Sömürme Örneği**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Evet # Yazma erişimini test et
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Özel işleyiciyi ayarla
sleep 5 && ./crash & # İşleyiciyi tetikle
```

### **`/proc/sys/kernel/modprobe`**
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) adresinde detaylı olarak açıklanmıştır.
- Çekirdek modül yükleyicisinin yolunu içerir.
- **Erişimi Kontrol Etme Örneği**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobe erişimini kontrol et
```

### **`/proc/sys/vm/panic_on_oom`**
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) adresinde referans gösterilmiştir.
- Bir OOM durumu meydana geldiğinde çekirdeğin panik yapmasını veya OOM öldürücüyü çağırmasını kontrol eden bir global bayrak.

### **`/proc/sys/fs`**
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) adresinde belirtildiği gibi, dosya sistemi hakkında seçenekler ve bilgiler içerir.
- Yazma erişimi, ana bilgisayara karşı çeşitli hizmet reddi saldırılarını etkinleştirebilir.

### **`/proc/sys/fs/binfmt_misc`**
- Sihirli sayılarına dayalı olmayan ikili biçimler için yorumlayıcıları kaydetmeye olanak tanır.
- `/proc/sys/fs/binfmt_misc/register` yazılabilirse, ayrıcalık yükseltmesine veya kök kabuğu erişimine yol açabilir.
- İlgili saldırı ve açıklama:
- [binfmt_misc aracılığıyla yoksul adamın kök kiti](https://github.com/toffan/binfmt_misc)
- Detaylı öğretici: [Video bağlantısı](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Diğerleri `/proc` içinde

### **`/proc/config.gz`**
- `CONFIG_IKCONFIG_PROC` etkinleştirilmişse, çekirdek yapılandırmasını ortaya çıkarabilir.
- Çalışan çekirdekteki zafiyetleri belirlemek için saldırganlar için faydalıdır.

### **`/proc/sysrq-trigger`**
- Sysrq komutlarını çağırmaya izin verir, potansiyel olarak anında sistem yeniden başlatmalar veya diğer kritik eylemler yapabilir.
- **Ana Bilgisayarı Yeniden Başlatma Örneği**:
```bash
echo b > /proc/sysrq-trigger # Ana bilgisayarı yeniden başlatır
```

### **`/proc/kmsg`**
- Çekirdek halka tamponu mesajlarını açığa çıkarır.
- Çekirdek saldırılarına, adres sızıntılarına ve hassas sistem bilgilerine yardımcı olabilir.

### **`/proc/kallsyms`**
- Çekirdek dışa aktarılan sembolleri ve adreslerini listeler.
- Özellikle KASLR'yi aşmak için çekirdek saldırı geliştirme için temel öneme sahiptir.
- Adres bilgisi, `kptr_restrict` `1` veya `2` olarak ayarlandığında kısıtlanır.
- Detaylar [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) adresinde bulunur.

### **`/proc/[pid]/mem`**
- Çekirdek bellek cihazı `/dev/mem` ile etkileşim sağlar.
- Tarihsel olarak ayrıcalık yükseltme saldırılarına karşı savunmasızdır.
- Daha fazlası için [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) adresine bakın.

### **`/proc/kcore`**
- Sistemin ELF çekirdek biçimindeki fiziksel belleğini temsil eder.
- Okuma, ana bilgisayar sistemi ve diğer konteynerlerin bellek içeriğini sızdırabilir.
- Büyük dosya boyutu okuma sorunlarına veya yazılım çökmelerine neden olabilir.
- Ayrıntılı kullanım [2019'da /proc/kcore Dökme](https://schlafwandler.github.io/posts/dumping-/proc/kcore/) adresinde bulunur.

### **`/proc/kmem`**
- Çekirdek sanal belleğini temsil eden `/dev/kmem` için alternatif bir arayüz.
- Okuma ve yazma izin verir, bu nedenle çekirdek belleğini doğrudan değiştirme imkanı sağlar.

### **`/proc/mem`**
- Fiziksel belleği temsil eden `/dev/mem` için alternatif bir arayüz.
- Okuma ve yazma izin verir, tüm belleğin değiştirilmesi sanal adresleri fiziksel adreslere çözme gerektirir.

### **`/proc/sched_debug`**
- PID ad alanı korumalarını atlayarak işlem planlama bilgilerini döndürür.
- İşlem adlarını, kimliklerini ve cgroup tanımlayıcılarını açığa çıkarır.

### **`/proc/[pid]/mountinfo`**
- İşlemin bağlama ad alanındaki bağlama noktaları hakkında bilgi sağlar.
- Kontey
### **`/sys/class/thermal`**
- Sıcaklık ayarlarını kontrol eder, potansiyel olarak DoS saldırılarına veya fiziksel hasara neden olabilir.

### **`/sys/kernel/vmcoreinfo`**
- Kernel adreslerini sızdırır, KASLR'yi tehlikeye atabilir.

### **`/sys/kernel/security`**
- AppArmor gibi Linux Güvenlik Modülleri'nin yapılandırılmasına izin veren `securityfs` arayüzünü barındırır.
- Erişim, bir konteynerin MAC sistemini devre dışı bırakmasına olanak tanıyabilir.

### **`/sys/firmware/efi/vars` ve `/sys/firmware/efi/efivars`**
- NVRAM'daki EFI değişkenleriyle etkileşim için arayüzler sunar.
- Yanlış yapılandırma veya kötüye kullanım, kullanılamaz hale getirilmiş dizüstü bilgisayarlar veya başlatılamayan ana bilgisayar makinelerine yol açabilir.

### **`/sys/kernel/debug`**
- `debugfs`, çekirdeğe yönelik "kurallar olmadan" hata ayıklama arayüzü sunar.
- Sınırlamasız doğası nedeniyle güvenlik sorunları geçmişi vardır.


## Referanslar
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
