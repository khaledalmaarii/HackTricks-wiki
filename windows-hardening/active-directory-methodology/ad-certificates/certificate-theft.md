# AD CS Sertifika Hırsızlığı

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

**Bu, [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) adresindeki harika araştırmanın Hırsızlık bölümlerinin küçük bir özetidir.**

## Bir sertifika ile ne yapabilirim

Sertifikaları nasıl çalacağınızı kontrol etmeden önce, sertifikanın ne için yararlı olduğunu bulmak hakkında bazı bilgilere sahip olmalısınız:
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
## Sertifikaların Crypto API'leri Kullanılarak Dışa Aktarılması – THEFT1

Bir **etkileşimli masaüstü oturumu** sırasında, bir kullanıcı veya makine sertifikasını, özel anahtarıyla birlikte çıkarmak kolayca yapılabilir, özellikle de **özel anahtar dışa aktarılabilir** ise. Bu, `certmgr.msc` içinde sertifikaya giderek, üzerine sağ tıklayıp `Tüm Görevler → Dışa Aktar` seçeneğini seçerek şifre korumalı bir .pfx dosyası oluşturmakla gerçekleştirilebilir.

**Programatik bir yaklaşım** için, PowerShell `ExportPfxCertificate` cmdlet'i veya [TheWover’ın CertStealer C# projesi](https://github.com/TheWover/CertStealer) gibi araçlar mevcuttur. Bu araçlar, sertifika deposuyla etkileşimde bulunmak için **Microsoft CryptoAPI** (CAPI) veya Kriptografi API: Next Generation (CNG) kullanır. Bu API'ler, sertifika depolama ve kimlik doğrulama için gerekli olanlar da dahil olmak üzere çeşitli kriptografik hizmetler sunar.

Ancak, bir özel anahtar dışa aktarılabilir olarak ayarlandığında, hem CAPI hem de CNG genellikle bu tür sertifikaların çıkarılmasını engeller. Bu kısıtlamayı aşmak için, **Mimikatz** gibi araçlar kullanılabilir. Mimikatz, özel anahtarların dışa aktarımına izin vermek için ilgili API'leri yamanmak üzere `crypto::capi` ve `crypto::cng` komutları sunar. Özellikle, `crypto::capi` mevcut süreçte CAPI'yi yamarken, `crypto::cng` **lsass.exe**'nin belleğini yamalamayı hedefler.

## DPAPI Üzerinden Kullanıcı Sertifikası Hırsızlığı – THEFT2

DPAPI hakkında daha fazla bilgi için:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows'ta, **sertifika özel anahtarları DPAPI ile korunmaktadır**. **Kullanıcı ve makine özel anahtarları için depolama yerlerinin** farklı olduğunu ve dosya yapıların, işletim sistemi tarafından kullanılan kriptografik API'ye bağlı olarak değiştiğini anlamak önemlidir. **SharpDPAPI**, DPAPI blob'larını şifrelerini çözme sırasında bu farklılıkları otomatik olarak yönetebilen bir araçtır.

**Kullanıcı sertifikaları**, esasen `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` altında kayıt defterinde yer alır, ancak bazıları `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` dizininde de bulunabilir. Bu sertifikalar için ilgili **özel anahtarlar**, genellikle **CAPI** anahtarları için `%APPDATA%\Microsoft\Crypto\RSA\User SID\` ve **CNG** anahtarları için `%APPDATA%\Microsoft\Crypto\Keys\` içinde saklanır.

Bir **sertifikayı ve ona bağlı özel anahtarı çıkarmak** için süreç şunları içerir:

1. Kullanıcının deposundan **hedef sertifikayı seçmek** ve anahtar deposu adını almak.
2. İlgili özel anahtarı şifrelemek için gerekli DPAPI anahtarını **bulmak**.
3. Düz metin DPAPI anahtarını kullanarak **özel anahtarı şifre çözmek**.

Düz metin DPAPI anahtarını **edinmek için** aşağıdaki yaklaşımlar kullanılabilir:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Anahtar dosyalarının ve özel anahtar dosyalarının şifre çözümünü kolaylaştırmak için, [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) içindeki `certificates` komutu faydalıdır. Özel anahtarları ve bağlantılı sertifikaları şifre çözmek için `/pvk`, `/mkfile`, `/password` veya `{GUID}:KEY` argümanlarını kabul eder ve ardından bir `.pem` dosyası oluşturur.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Machine Certificate Theft via DPAPI – THEFT3

Windows tarafından `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` kayıt defterinde saklanan makine sertifikaları ve `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI için) ve `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG için) konumunda bulunan ilgili özel anahtarlar, makinenin DPAPI anahtarları ile şifrelenmiştir. Bu anahtarlar, alanın DPAPI yedek anahtarı ile çözülemez; bunun yerine yalnızca SYSTEM kullanıcısının erişebildiği **DPAPI_SYSTEM LSA sırrı** gereklidir.

Manuel şifre çözme, **Mimikatz** içinde `lsadump::secrets` komutunu çalıştırarak DPAPI_SYSTEM LSA sırrını çıkarmak ve ardından bu anahtarı makine anahtarlarını çözmek için kullanmakla gerçekleştirilebilir. Alternatif olarak, daha önce açıklandığı gibi CAPI/CNG yamanmasının ardından Mimikatz’ın `crypto::certificates /export /systemstore:LOCAL_MACHINE` komutu kullanılabilir.

**SharpDPAPI**, sertifikalar komutuyla daha otomatik bir yaklaşım sunar. `/machine` bayrağı yükseltilmiş izinlerle kullanıldığında, SYSTEM'e yükselir, DPAPI_SYSTEM LSA sırrını döker, bunu makine DPAPI anahtarlarını çözmek için kullanır ve ardından bu düz metin anahtarlarını herhangi bir makine sertifikası özel anahtarını çözmek için bir arama tablosu olarak kullanır.

## Finding Certificate Files – THEFT4

Sertifikalar bazen dosya sisteminde, örneğin dosya paylaşımlarında veya İndirilenler klasöründe doğrudan bulunabilir. Windows ortamlarına yönelik en yaygın karşılaşılan sertifika dosyası türleri `.pfx` ve `.p12` dosyalarıdır. Daha az sıklıkla, `.pkcs12` ve `.pem` uzantılı dosyalar da görünür. Diğer dikkate değer sertifika ile ilgili dosya uzantıları şunlardır:
- Özel anahtarlar için `.key`,
- Sadece sertifikalar için `.crt`/`.cer`,
- Sertifika İmzalama Talepleri için `.csr`, bu dosyalar sertifikalar veya özel anahtarlar içermez,
- Java uygulamaları tarafından kullanılan sertifikalar ile birlikte özel anahtarlar içerebilecek Java Anahtar Depoları için `.jks`/`.keystore`/`.keys`.

Bu dosyalar, belirtilen uzantıları arayarak PowerShell veya komut istemcisi kullanılarak aranabilir.

Bir PKCS#12 sertifika dosyası bulunduğunda ve bir şifre ile korunduğunda, `pfx2john.py` kullanılarak bir hash çıkarılması mümkündür; bu dosya [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) adresinde mevcuttur. Ardından, şifreyi kırmaya çalışmak için JohnTheRipper kullanılabilir.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Kimlik Bilgisi Hırsızlığı PKINIT Üzerinden – THEFT5

Verilen içerik, PKINIT aracılığıyla NTLM kimlik bilgisi hırsızlığı için THEFT5 olarak etiketlenen hırsızlık yöntemini açıklamaktadır. İşte içeriğin pasif sesle yeniden açıklaması, anonimleştirilmiş ve gerektiğinde özetlenmiştir:

Kerberos kimlik doğrulamasını desteklemeyen uygulamalar için NTLM kimlik doğrulamasını [MS-NLMP] sağlamak amacıyla, KDC, PKCA kullanıldığında, kullanıcının NTLM tek yönlü fonksiyonunu (OWF) ayrıcalık niteliği sertifikası (PAC) içinde, özellikle `PAC_CREDENTIAL_INFO` tamponunda döndürmek üzere tasarlanmıştır. Sonuç olarak, bir hesap PKINIT aracılığıyla bir Ticket-Granting Ticket (TGT) ile kimlik doğrulaması yapıp güvence altına alırsa, mevcut ana bilgisayarın NTLM hash'ini TGT'den çıkarmasını sağlayan bir mekanizma sağlanmış olur; bu, eski kimlik doğrulama protokollerini sürdürmek içindir. Bu süreç, NTLM düz metninin NDR serileştirilmiş tasvirini içeren `PAC_CREDENTIAL_DATA` yapısının şifre çözümlemesini içerir.

**Kekeo** aracı, [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) adresinde erişilebilir olup, bu belirli veriyi içeren bir TGT talep edebilme yeteneğine sahip olduğu belirtilmektedir; böylece kullanıcının NTLM'sinin geri alınmasını kolaylaştırır. Bu amaçla kullanılan komut aşağıdaki gibidir:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Ayrıca, pin'in alınabileceği durumlarda Kekeo'nun akıllı kart korumalı sertifikaları işleyebileceği belirtilmiştir, [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) referans verilmiştir. Aynı yeteneğin **Rubeus** tarafından desteklendiği belirtilmektedir, [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) adresinde mevcuttur.

Bu açıklama, PKINIT aracılığıyla NTLM kimlik bilgisi çalınma sürecini ve bu süreçte yer alan araçları kapsar, PKINIT kullanılarak elde edilen TGT aracılığıyla NTLM hash'lerinin alınmasına odaklanır ve bu süreci kolaylaştıran yardımcı programları içerir.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
