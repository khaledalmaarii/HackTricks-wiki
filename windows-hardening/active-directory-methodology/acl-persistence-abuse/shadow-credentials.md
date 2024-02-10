# Shadow Kimlik Bilgileri

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) sahip olun.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Giriş <a href="#3f17" id="3f17"></a>

**Bu teknik hakkındaki tüm bilgiler için orijinal yazıyı kontrol edin [buradan](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Özet olarak: bir kullanıcının/bilgisayarın **msDS-KeyCredentialLink** özelliğine yazabilirseniz, **nesnenin NT hash'ini alabilirsiniz**.

Yazıda, **genel-özel anahtar kimlik doğrulama kimlik bilgileri** kurarak hedefin NTLM hash'ini içeren benzersiz bir **Hizmet Bileti** elde etmek için bir yöntem açıklanmaktadır. Bu süreç, şifrelenmiş NTLM_SUPPLEMENTAL_CREDENTIAL'ı içeren Privilege Attribute Certificate (PAC) içerir ve bu PAC çözülebilir.

### Gereksinimler

Bu teknik uygulanabilmesi için belirli koşulların sağlanması gerekmektedir:
- En az bir Windows Server 2016 Etki Alanı Denetleyicisi gerekmektedir.
- Etki Alanı Denetleyicisi üzerinde bir sunucu kimlik doğrulama dijital sertifikası yüklü olmalıdır.
- Active Directory, Windows Server 2016 İşlevsel Düzeyinde olmalıdır.
- Hedef nesnenin msDS-KeyCredentialLink özelliğini değiştirme yetkisine sahip bir hesap gerekmektedir.

## Kötüye Kullanım

Bilgisayar nesneleri için Key Trust'ın kötüye kullanımı, bir Bilet Verme Bileti (TGT) ve NTLM hash'ini elde etmekten öte adımları içerir. Seçenekler şunları içerir:
1. Ayrıcalıklı kullanıcılar olarak hareket etmek için bir **RC4 gümüş bileti** oluşturma.
2. **S4U2Self** ile TGT kullanarak **ayrıcalıklı kullanıcıları taklit etme**, hizmet adına bir hizmet sınıfı eklemek için Hizmet Biletinde değişiklik yapılmasını gerektirir.

Key Trust kötüye kullanımının önemli bir avantajı, saldırgan tarafından oluşturulan özel anahtarla sınırlı olmasıdır. Bu, potansiyel olarak savunmasız hesaplara yetkilendirme yapmadan ve zor kaldırılabilecek bir bilgisayar hesabı oluşturmayı gerektirmez.

## Araçlar

### [**Whisker**](https://github.com/eladshamir/Whisker)

Bu saldırı için bir C# arabirimi sağlayan DSInternals'e dayanmaktadır. Whisker ve Python karşılığı olan **pyWhisker**, `msDS-KeyCredentialLink` özelliğini manipüle etmek için kullanılır ve Active Directory hesapları üzerinde kontrol sağlar. Bu araçlar, hedef nesneden anahtar kimlik bilgileri eklemeyi, listelemeyi, kaldırmayı ve temizlemeyi içeren çeşitli işlemleri destekler.

**Whisker** işlevleri şunları içerir:
- **Ekle**: Bir anahtar çifti oluşturur ve bir anahtar kimlik bilgisi ekler.
- **Listele**: Tüm anahtar kimlik bilgisi girişlerini görüntüler.
- **Kaldır**: Belirtilen bir anahtar kimlik bilgisini siler.
- **Temizle**: Tüm anahtar kimlik bilgilerini siler, meşru WHfB kullanımını bozabilir.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Bu, Whisker işlevselliğini **UNIX tabanlı sistemlere** genişletir ve Impacket ve PyDSInternals'i kullanarak kapsamlı saldırı yetenekleri sağlar. Bu yetenekler arasında KeyCredentials'ın listelenmesi, ekleme ve kaldırma işlemleri ile JSON formatında içe aktarma ve dışa aktarma bulunur.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray, geniş kullanıcı gruplarının etki alanı nesneleri üzerinde sahip olabileceği GenericWrite/GenericAll izinlerini sömürerek ShadowCredentials'ı geniş kapsamda uygulamayı amaçlar. Bu, etki alanına giriş yapmayı, etki alanının işlevsel seviyesini doğrulamayı, etki alanı nesnelerini numaralandırmayı ve TGT edinimi ve NT hash açığa çıkarmak için KeyCredentials eklemeyi denemeyi içerir. Temizleme seçenekleri ve özyinelemeli sömürü taktikleri, kullanışlılığını artırır.


## Referanslar

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) edinin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
