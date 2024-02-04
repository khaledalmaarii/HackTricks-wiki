# Pickle Rick

## Pickle Rick

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

![](../../.gitbook/assets/picklerick.gif)

Esta máquina foi categorizada como fácil e foi bastante simples.

## Enumeração

Comecei **enumerando a máquina usando minha ferramenta** [**Legion**](https://github.com/carlospolop/legion):

![](<../../.gitbook/assets/image (79) (2).png>)

Como você pode ver, 2 portas estão abertas: 80 (**HTTP**) e 22 (**SSH**)

Então, iniciei o legion para enumerar o serviço HTTP:

![](<../../.gitbook/assets/image (234).png>)

Observe que na imagem você pode ver que `robots.txt` contém a string `Wubbalubbadubdub`

Após alguns segundos, revisei o que `disearch` já havia descoberto:

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

E como você pode ver na última imagem, uma página de **login** foi descoberta.

Verificando o código-fonte da página raiz, um nome de usuário é descoberto: `R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

Portanto, você pode fazer login na página de login usando as credenciais `R1ckRul3s:Wubbalubbadubdub`

## Usuário

Usando essas credenciais, você terá acesso a um portal onde pode executar comandos:

![](<../../.gitbook/assets/image (241).png>)

Alguns comandos como cat não são permitidos, mas você pode ler o primeiro ingrediente (bandeira) usando, por exemplo, grep:

![](<../../.gitbook/assets/image (242).png>)

Então eu usei:

![](<../../.gitbook/assets/image (243) (1).png>)

Para obter um shell reverso:

![](<../../.gitbook/assets/image (239) (1).png>)

O **segundo ingrediente** pode ser encontrado em `/home/rick`

![](<../../.gitbook/assets/image (240).png>)

## Root

O usuário **www-data pode executar qualquer coisa como sudo**:

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
