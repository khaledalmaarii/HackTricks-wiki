<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Identificando binários empacotados

* **falta de strings**: É comum encontrar binários empacotados que não possuem quase nenhuma string
* Muitas **strings não utilizadas**: Também é comum, quando um malware usa algum tipo de empacotador comercial, encontrar muitas strings sem referências cruzadas. Mesmo que essas strings existam, isso não significa que o binário não esteja empacotado.
* Você também pode usar algumas ferramentas para tentar descobrir qual empacotador foi usado para empacotar um binário:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recomendações Básicas

* **Comece** a análise do binário empacotado **de baixo para cima no IDA e mova-se para cima**. Desempacotadores saem uma vez que o código desempacotado sai, então é improvável que o desempacotador passe a execução para o código desempacotado no início.
* Procure por **JMP's** ou **CALLs** para **registradores** ou **regiões** de **memória**. Procure também por **funções empurrando argumentos e um endereço e depois chamando `retn`**, porque o retorno da função nesse caso pode chamar o endereço que acabou de ser empurrado para a pilha antes de chamá-lo.
* Coloque um **ponto de interrupção** em `VirtualAlloc`, pois isso aloca espaço na memória onde o programa pode escrever código desempacotado. Use "executar até o código do usuário" ou use F8 para **chegar ao valor dentro de EAX** após executar a função e "**siga esse endereço no dump**". Você nunca sabe se essa é a região onde o código desempacotado vai ser salvo.
* **`VirtualAlloc`** com o valor "**40**" como argumento significa Read+Write+Execute (algum código que precisa de execução vai ser copiado aqui).
* **Durante o desempacotamento** de código, é normal encontrar **várias chamadas** para **operações aritméticas** e funções como **`memcopy`** ou **`Virtual`**`Alloc`. Se você se encontrar em uma função que aparentemente só realiza operações aritméticas e talvez algum `memcopy`, a recomendação é tentar **encontrar o fim da função** (talvez um JMP ou chamada para algum registrador) **ou** pelo menos a **chamada para a última função** e executar até lá, pois o código não é interessante.
* Durante o desempacotamento de código **observe** sempre que você **mudar de região de memória**, pois uma mudança de região de memória pode indicar o **início do código de desempacotamento**. Você pode facilmente despejar uma região de memória usando o Process Hacker (processo --> propriedades --> memória).
* Ao tentar desempacotar código, uma boa maneira de **saber se você já está trabalhando com o código desempacotado** (para que você possa apenas despejá-lo) é **verificar as strings do binário**. Se em algum momento você realizar um salto (talvez mudando a região de memória) e notar que **muito mais strings foram adicionadas**, então você pode saber **que está trabalhando com o código desempacotado**.\
No entanto, se o empacotador já contém muitas strings, você pode ver quantas strings contêm a palavra "http" e ver se esse número aumenta.
* Quando você despeja um executável de uma região de memória, você pode corrigir alguns cabeçalhos usando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
