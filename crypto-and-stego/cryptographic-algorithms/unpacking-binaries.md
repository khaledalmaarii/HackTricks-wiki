<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Identificando binários empacotados

* **Falta de strings**: É comum encontrar binários empacotados que quase não possuem strings.
* Muitas **strings não utilizadas**: Além disso, quando um malware está usando algum tipo de empacotador comercial, é comum encontrar muitas strings sem referências cruzadas. Mesmo que essas strings existam, isso não significa que o binário não está empacotado.
* Você também pode usar algumas ferramentas para tentar descobrir qual empacotador foi usado para empacotar um binário:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recomendações Básicas

* **Comece** analisando o binário empacotado **de baixo para cima no IDA e mova para cima**. Desempacotadores saem assim que o código desempacotado sai, então é improvável que o desempacotador passe a execução para o código desempacotado no início.
* Procure por **JMP's** ou **CALLs** para **registradores** ou **regiões** de **memória**. Procure também por **funções que empurram argumentos e um endereço de direção e então chamam `retn`**, porque o retorno da função nesse caso pode chamar o endereço acabado de empurrar para a pilha antes de chamá-lo.
* Coloque um **ponto de interrupção** em `VirtualAlloc`, pois isso aloca espaço na memória onde o programa pode escrever o código desempacotado. "Execute até o código do usuário" ou use F8 para **chegar ao valor dentro de EAX** após executar a função e "**seguir esse endereço no dump**". Você nunca sabe se essa é a região onde o código desempacotado será salvo.
* **`VirtualAlloc`** com o valor "**40**" como argumento significa Ler+Escrever+Executar (algum código que precisa de execução será copiado aqui).
* **Enquanto desempacotando** o código, é normal encontrar **várias chamadas** para **operações aritméticas** e funções como **`memcopy`** ou **`Virtual`**`Alloc`. Se você se encontrar em uma função que aparentemente realiza apenas operações aritméticas e talvez algum `memcopy`, a recomendação é tentar **encontrar o final da função** (talvez um JMP ou chamada a algum registrador) **ou** pelo menos a **chamada para a última função** e executar até então, já que o código não é interessante.
* Enquanto desempacotando o código, **observe** sempre que você **altera a região de memória**, pois uma mudança na região de memória pode indicar o **início do código desempacotado**. Você pode facilmente despejar uma região de memória usando o Process Hacker (processo --> propriedades --> memória).
* Ao tentar desempacotar o código, uma boa maneira de **saber se você já está trabalhando com o código desempacotado** (para que você possa simplesmente despejá-lo) é **verificar as strings do binário**. Se em algum momento você realizar um salto (talvez alterando a região de memória) e perceber que **muitas mais strings foram adicionadas**, então você pode saber **que está trabalhando com o código desempacotado**.\
No entanto, se o empacotador já contiver muitas strings, você pode ver quantas strings contêm a palavra "http" e ver se esse número aumenta.
* Ao despejar um executável de uma região de memória, você pode corrigir alguns cabeçalhos usando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

</details>
