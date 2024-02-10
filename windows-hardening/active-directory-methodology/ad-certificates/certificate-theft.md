# AD CS Sertifika Hırsızlığı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

**Bu, [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)** adresindeki harika araştırmanın Hırsızlık bölümlerinin küçük bir özetidir.


## Bir sertifika ile ne yapabilirim

Sertifikaları nasıl çalacağınızı kontrol etmeden önce, sertifikanın ne için kullanışlı olduğu hakkında bazı bilgilere sahip olmanız önemlidir:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Crypto API'leri Kullanarak Sertifikaları Çalma - HIRSIZLIK1

**Etkileşimli bir masaüstü oturumu** içinde, özellikle **özel anahtar ihrac edilebilir** ise, bir kullanıcı veya makine sertifikası ile birlikte özel anahtarı çalmak oldukça kolaydır. Bu, `certmgr.msc` içinde sertifikaya giderek, üzerine sağ tıklayıp `Tüm Görevler → Dışa Aktar` seçeneğini seçerek şifre korumalı bir .pfx dosyası oluşturarak gerçekleştirilebilir.

**Programatik bir yaklaşım** için, PowerShell `ExportPfxCertificate` cmdlet veya [TheWover's CertStealer C# projesi](https://github.com/TheWover/CertStealer) gibi araçlar mevcuttur. Bu araçlar, sertifika deposuyla etkileşimde bulunmak için Microsoft CryptoAPI (CAPI) veya Cryptography API: Next Generation (CNG) gibi araçları kullanır. Bu API'ler, sertifika depolama ve kimlik doğrulama için gerekli olan çeşitli kriptografik hizmetleri sağlar.

Ancak, bir özel anahtar ihrac edilemez olarak ayarlandıysa, CAPI ve CNG genellikle bu tür sertifikaların çalınmasını engeller. Bu kısıtlamayı aşmak için, Mimikatz gibi araçlar kullanılabilir. Mimikatz, özel anahtarların ihracını sağlamak için ilgili API'leri yamalamak için `crypto::capi` ve `crypto::cng` komutlarını sunar. Özellikle, `crypto::capi` mevcut işlem içinde CAPI'yi yamar, `crypto::cng` ise yamalama için **lsass.exe** belleğini hedef alır.

## DPAPI Aracılığıyla Kullanıcı Sertifikası Çalma - HIRSIZLIK2

DPAPI hakkında daha fazla bilgi için:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows'ta, **sertifika özel anahtarları DPAPI ile korunur**. Önemli olan, **kullanıcı ve makine özel anahtarlarının depolama konumlarının** farklı olduğunu ve dosya yapılarının işletim sistemi tarafından kullanılan kriptografik API'ye bağlı olarak değiştiğini bilmektir. **SharpDPAPI**, DPAPI bloklarını çözerken bu farklılıkları otomatik olarak takip edebilen bir araçtır.

**Kullanıcı sertifikaları** genellikle `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` altında kaydedilir, ancak bazıları `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` dizininde de bulunabilir. Bu sertifikaların **özel anahtarları** genellikle **CAPI** anahtarları için `%APPDATA%\Microsoft\Crypto\RSA\User SID\` ve **CNG** anahtarları için `%APPDATA%\Microsoft\Crypto\Keys\` dizininde saklanır.

Bir **sertifikayı ve ilişkili özel anahtarını çalmak** için, aşağıdaki adımlar izlenir:

1. Kullanıcının deposundan **hedef sertifikayı seçmek** ve anahtar deposu adını almak.
2. İlgili özel anahtarı şifrelemek için gereken **DPAPI anahtarını bulmak**.
3. Şifreli özel anahtarı, düz metin DPAPI anahtarı kullanarak **şifresini çözmek**.

Düz metin DPAPI anahtarını elde etmek için, aşağıdaki yaklaşımlar kullanılabilir:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Master anahtar dosyalarının ve özel anahtar dosyalarının şifresinin çözülmesini kolaylaştırmak için [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) tarafından sağlanan `certificates` komutu faydalı olmaktadır. Bu komut, özel anahtarları ve ilişkili sertifikaları çözmek için `/pvk`, `/mkfile`, `/password` veya `{GUID}:KEY` argümanlarını kabul eder ve sonuç olarak bir `.pem` dosyası oluşturur.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPI Aracılığıyla Makine Sertifikası Çalma – THEFT3

Windows tarafından kaydedilen makine sertifikaları, kayıt defterinde `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` ve ilgili özel anahtarlar `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI için) ve `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG için) konumunda depolanır ve makinenin DPAPI anahtarlarıyla şifrelenir. Bu anahtarlar, etki alanının DPAPI yedek anahtarıyla çözülemez; bunun yerine yalnızca SYSTEM kullanıcısının erişebileceği **DPAPI_SYSTEM LSA gizli**si gereklidir.

Manuel çözümleme, DPAPI_SYSTEM LSA gizlisini çıkarmak için **Mimikatz**'ın `lsadump::secrets` komutunun çalıştırılmasıyla ve ardından bu anahtarı kullanarak makine anahtarlarını çözerek gerçekleştirilebilir. Alternatif olarak, CAPI/CNG'yi önceden açıklanan şekilde yamaladıktan sonra Mimikatz'ın `crypto::certificates /export /systemstore:LOCAL_MACHINE` komutu kullanılabilir.

**SharpDPAPI**, sertifikalar komutuyla daha otomatik bir yaklaşım sunar. Yükseltilmiş izinlerle `/machine` bayrağı kullanıldığında, sistem kullanıcısına yükselir, DPAPI_SYSTEM LSA gizlisini döker, bunu kullanarak makine DPAPI anahtarlarını çözer ve ardından bu düz metin anahtarları, herhangi bir makine sertifikası özel anahtarını çözmek için bir arama tablosu olarak kullanır.


## Sertifika Dosyalarını Bulma – THEFT4

Sertifikalar bazen dosya paylaşımlarında veya İndirilenler klasöründe doğrudan dosya sistemine yerleştirilir. Windows ortamlarına yönelik en sık karşılaşılan sertifika dosyası türleri `.pfx` ve `.p12` dosyalarıdır. Daha az sıklıkla, `.pkcs12` ve `.pem` uzantılı dosyalar da bulunur. Ek olarak, dikkate değer diğer sertifika ile ilgili dosya uzantıları şunlardır:
- Özel anahtarlar için `.key`,
- Sadece sertifikalar için `.crt`/`.cer`,
- Sertifika İmzalama İstekleri için (Certificate Signing Requests) `.csr`, bu dosyalar sertifikalar veya özel anahtarlar içermez,
- Java Keystore'lar için `.jks`/`.keystore`/`.keys`, Java uygulamaları tarafından kullanılan sertifikaları ve özel anahtarları içerebilir.

Bu dosyalar, PowerShell veya komut istemcisini kullanarak belirtilen uzantıları arayarak aranabilir.

Bir PKCS#12 sertifika dosyası bulunduğunda ve bir parola tarafından korunduğunda, `pfx2john.py` kullanılarak bir karma çıkarılabilir. Bu araç [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) adresinde bulunabilir. Ardından, parolanın kırılmaya çalışılması için JohnTheRipper kullanılabilir.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## PKINIT Aracılığıyla NTLM Kimlik Bilgisi Çalma - THEFT5

Verilen içerik, PKINIT aracılığıyla NTLM kimlik bilgisi çalma yöntemini, özellikle THEFT5 olarak adlandırılan çalma yöntemini açıklar. İşte içeriğin anonimleştirilmiş ve gerektiğinde özetlenmiş bir şekilde pasif sesle yeniden açıklanması:

Kerberos kimlik doğrulamasını kolaylaştırmayan uygulamalar için NTLM kimlik doğrulamasını [MS-NLMP] desteklemek için, KDC, PKCA kullanıldığında kullanıcının NTLM tek yönlü işlevini (OWF) ayrıcalık öznitelik sertifikası (PAC) içinde, özellikle `PAC_CREDENTIAL_INFO` tamponunda döndürmek üzere tasarlanmıştır. Sonuç olarak, bir hesap PKINIT aracılığıyla Kimlik Doğrulama Bileti (TGT) kimlik doğrulaması yaparsa, mevcut ana bilgisayarın eski kimlik doğrulama protokollerini desteklemek için TGT'den NTLM karmaşasını çıkarmasına olanak sağlayan bir mekanizma sağlanır. Bu işlem, temelde NTLM düz metninin NDR serileştirilmiş bir tasviri olan `PAC_CREDENTIAL_DATA` yapısının şifresinin çözülmesini içerir.

Bu özel veriyi içeren bir TGT talep etme yeteneğine sahip olan **Kekeo** adlı araç, [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) adresinden erişilebilir. Bu amaçla kullanılan komut aşağıdaki gibidir:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Ayrıca, Kekeo'nun akıllı kart korumalı sertifikaları işleyebileceği, pin'in alınabileceği belirtilmektedir. Bu konuda [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) referansına bakılabilir. Aynı yeteneğin **Rubeus** tarafından da desteklendiği belirtilmektedir. Rubeus, [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) adresinde bulunabilir.

Bu açıklama, PKINIT aracılığıyla NTLM kimlik bilgilerinin çalınması sürecini ve bu süreci kolaylaştıran araçları ele almaktadır. PKINIT kullanarak elde edilen TGT ile NTLM karmaşalarının alınması odaklanmaktadır.

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
