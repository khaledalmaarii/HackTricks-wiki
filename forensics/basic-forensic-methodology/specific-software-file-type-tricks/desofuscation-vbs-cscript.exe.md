<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine çıkarın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>


Bir kötü amaçlı VBS dosyasını hata ayıklamak/deşifre etmek için faydalı olabilecek bazı şeyler:

## echo
```bash
Wscript.Echo "Like this?"
```
## Yorumlar

Yorumlar, bir VBS dosyasının içindeki kodun anlaşılmasını kolaylaştırmak için kullanılabilir. Yorumlar, kodun ne yaptığını açıklamak veya belirli bir bölümü devre dışı bırakmak için kullanılabilir. VBS dosyalarında iki tür yorum bulunur: tek satır yorumları ve çok satırlı yorumlar.

### Tek Satır Yorumları

Tek satır yorumları, bir satırın sonuna eklenen bir tane tek tırnak işareti (') ile başlar. Bu işaretten sonra gelen her şey yorum olarak kabul edilir ve çalıştırılmaz.

Örnek:

```vbs
MsgBox "Bu kod çalışacak" ' Bu bir yorumdur ve çalıştırılmayacak
```

### Çok Satırlı Yorumlar

Çok satırlı yorumlar, bir tane tek tırnak işareti ile başlar ve bir tane daha tek tırnak işareti ile sona erer. İçerisindeki tüm satırlar yorum olarak kabul edilir ve çalıştırılmaz.

Örnek:

```vbs
' Bu bir çok satırlı yorumdur ve çalıştırılmayacak
' MsgBox "Bu kod çalışmayacak"
' WScript.Echo "Bu kod da çalışmayacak"
```

Yorumlar, VBS dosyalarında kodun anlaşılmasını ve düzenlenmesini kolaylaştırır. Ayrıca, belirli bir kod bloğunu geçici olarak devre dışı bırakmak veya kodun ne yaptığını açıklamak için kullanılabilir.
```bash
' this is a comment
```
## Test

Bu bir testtir.
```bash
cscript.exe file.vbs
```
## Bir dosyaya veri yazma

To write data to a file, you can use the following steps:

1. Open the file in write mode. You can specify the file path and name.
```python
file = open("dosya.txt", "w")
```

2. Write the data to the file using the `write()` method. You can pass a string as an argument.
```python
file.write("Merhaba, dünya!")
```

3. Close the file to ensure that all the data is saved.
```python
file.close()
```

By following these steps, you will be able to write data to a file in Python.
```js
Function writeBinary(strBinary, strPath)

Dim oFSO: Set oFSO = CreateObject("Scripting.FileSystemObject")

' below lines purpose: checks that write access is possible!
Dim oTxtStream

On Error Resume Next
Set oTxtStream = oFSO.createTextFile(strPath)

If Err.number <> 0 Then MsgBox(Err.message) : Exit Function
On Error GoTo 0

Set oTxtStream = Nothing
' end check of write access

With oFSO.createTextFile(strPath)
.Write(strBinary)
.Close
End With

End Function
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
