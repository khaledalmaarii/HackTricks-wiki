{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Treinamento AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Treinamento GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


Algumas coisas que podem ser úteis para depurar/desofuscar um arquivo VBS malicioso:

## echo
```bash
Wscript.Echo "Like this?"
```
## Comentários
```bash
' this is a comment
```
## Test
```bash
cscript.exe file.vbs
```
## Escrever dados em um arquivo
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
{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
