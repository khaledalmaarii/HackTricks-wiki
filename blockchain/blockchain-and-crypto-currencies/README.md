<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Terminologia Básica

* **Smart contract**: Smart contracts são simplesmente **programas armazenados em uma blockchain que são executados quando condições predeterminadas são atendidas**. Eles são tipicamente usados para automatizar a **execução** de um **acordo** para que todos os participantes possam estar imediatamente certos do resultado, sem a necessidade de um intermediário ou perda de tempo. (De [aqui](https://www.ibm.com/topics/smart-contracts)).
* Basicamente, um smart contract é um **pedaço de código** que será executado quando as pessoas acessarem e aceitarem o contrato. Smart contracts **funcionam em blockchains** (então os resultados são armazenados de forma imutável) e podem ser lidos pelas pessoas antes de aceitá-los.
* **dApps**: **Aplicações descentralizadas** são implementadas em cima de **smart contracts**. Elas geralmente têm uma interface onde o usuário pode interagir com o aplicativo, o **back-end** é público (então pode ser auditado) e é implementado como um **smart contract**. Às vezes o uso de um banco de dados é necessário, a blockchain Ethereum aloca um certo armazenamento para cada conta.
* **Tokens & coins**: Uma **coin** é uma criptomoeda que atua como **dinheiro digital** e um **token** é algo que **representa** algum **valor** mas não é uma coin.
* **Utility Tokens**: Esses tokens permitem ao usuário **acessar um determinado serviço mais tarde** (é algo que tem algum valor em um ambiente específico).
* **Security Tokens**: Estes representam a **propriedade** de algum ativo.
* **DeFi**: **Finanças Descentralizadas**.
* **DEX: Plataformas de Troca Descentralizadas**.
* **DAOs**: **Organizações Autônomas Descentralizadas**.

# Mecanismos de Consenso

Para que uma transação de blockchain seja reconhecida, ela deve ser **anexada** à **blockchain**. Validadores (mineradores) realizam esse anexo; na maioria dos protocolos, eles **recebem uma recompensa** por fazer isso. Para que a blockchain permaneça segura, deve haver um mecanismo para **prevenir que um usuário malicioso ou grupo assuma a maioria da validação**.

Proof of work, outro mecanismo de consenso comumente usado, utiliza uma validação de proeza computacional para verificar transações, exigindo que um atacante potencial adquira uma grande fração do poder computacional da rede de validadores.

## Proof Of Work (PoW)

Isso usa uma **validação de proeza computacional** para verificar transações, exigindo que um atacante potencial adquira uma grande fração do poder computacional da rede de validadores.\
Os **mineradores** vão **selecionar várias transações** e então começar **computando o Proof Of Work**. O **minerador com os maiores recursos computacionais** é mais provável de **terminar** **mais cedo** o Proof of Work e receber as taxas de todas as transações.

## Proof Of Stake (PoS)

PoS consegue isso **exigindo que os validadores possuam uma certa quantidade de tokens da blockchain**, exigindo que **atacantes potenciais adquiram uma grande fração dos tokens** na blockchain para realizar um ataque.\
Neste tipo de consenso, quanto mais tokens um minerador tem, mais provável será que o minerador seja escolhido para criar o próximo bloco.\
Comparado com PoW, isso reduz significativamente o **consumo de energia** que os mineradores estão gastando.

# Bitcoin

## Transações

Uma **transação** simples é um **movimento de dinheiro** de um endereço para outro.\
Um **endereço** no bitcoin é o hash da **chave pública**, portanto, alguém para fazer uma transação de um endereço precisa conhecer a chave privada associada a essa chave pública (o endereço).\
Então, quando uma **transação** é realizada, ela é **assinada** com a chave privada do endereço para mostrar que a transação é **legítima**.

A primeira parte da produção de uma assinatura digital no Bitcoin pode ser representada matematicamente da seguinte maneira:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Onde:

* \_d\_A é a **chave privada** de assinatura
* _m_ é a **transação**
* Fhash é a função de hash
* Fsig é o algoritmo de assinatura
* Sig é a assinatura resultante

A função de assinatura (Fsig) produz uma assinatura (Sig) que consiste em dois valores: R e S:

* Sig = (R, S)

Uma vez que R e S foram calculados, eles são serializados em um fluxo de bytes que é codificado usando um esquema de codificação padrão internacional conhecido como Distinguished Encoding Rules (ou DER). Para verificar que a assinatura é válida, um algoritmo de verificação de assinatura é usado. A verificação de uma assinatura digital requer o seguinte:

* Assinatura (R e S)
* Hash da transação
* A chave pública que corresponde à chave privada que foi usada para criar a assinatura

A verificação de uma assinatura efetivamente significa que apenas o proprietário da chave privada (que gerou a chave pública) poderia ter produzido a assinatura na transação. O algoritmo de verificação de assinatura retornará ‘TRUE’ se a assinatura for de fato válida.

### Transações Multisignature

Um **endereço** multi-assinatura é um endereço que está associado a mais de uma chave privada ECDSA. O tipo mais simples é um endereço m-de-n - ele está associado a n chaves privadas, e enviar bitcoins deste endereço requer assinaturas de pelo menos m chaves. Uma **transação** multi-assinatura é aquela que envia fundos de um endereço multi-assinatura.

### Campos das Transações

Cada transação bitcoin tem vários campos:

* **Inputs**: A quantidade e endereço **de onde** os **bitcoins** estão **sendo transferidos**
* **Outputs**: O endereço e as quantias que cada um **transferiu** para **cada** **output**
* **Taxa:** A quantidade de **dinheiro** que é **paga** ao **minerador** da transação
* **Script\_sig**: Assinatura do script da transação
* **Script\_type**: Tipo de transação

Existem **2 tipos principais** de transações:

* **P2PKH: "Pay To Public Key Hash"**: É assim que as transações são feitas. Você está exigindo que o **remetente** forneça uma **assinatura válida** (da chave privada) e **chave pública**. O script de saída da transação usará a assinatura e a chave pública e, por meio de algumas funções criptográficas, verificará **se corresponde** ao hash da chave pública, se corresponder, então os **fundos** serão **gastáveis**. Este método oculta sua chave pública na forma de um hash para segurança extra.
* **P2SH: "Pay To Script Hash":** As saídas de uma transação são apenas **scripts** (isso significa que a pessoa que quer esse dinheiro envia um script) que, se **executados com parâmetros específicos, resultarão em um booleano de `true` ou `false`**. Se um minerador executar o script de saída com os parâmetros fornecidos e resultar em `true`, o **dinheiro será enviado para a saída desejada**. `P2SH` é usado para **carteiras multi-assinatura** tornando os scripts de saída **lógica que verifica várias assinaturas antes de aceitar a transação**. `P2SH` também pode ser usado para permitir que qualquer pessoa, ou ninguém, gaste os fundos. Se o script de saída de uma transação P2SH for apenas `1` para verdadeiro, então tentar gastar a saída sem fornecer parâmetros resultará apenas em `1` tornando o dinheiro gastável por qualquer um que tentar. Isso também se aplica a scripts que retornam `0`, tornando a saída gastável por ninguém.

## Lightning Network

Este protocolo ajuda a **realizar várias transações em um canal** e **apenas** **enviar** o **estado final** para a blockchain para salvá-lo.\
Isso **melhora** a **velocidade** da blockchain bitcoin (ela permite apenas 7 pagamentos por segundo) e permite criar **transações mais difíceis de rastrear**, pois o canal é criado através de nós da blockchain bitcoin:

![](<../../.gitbook/assets/image (611).png>)

O uso normal da Lightning Network consiste em **abrir um canal de pagamento** comprometendo uma transação de financiamento na blockchain base relevante (camada 1), seguido por fazer **qualquer número** de transações da Lightning Network que atualizem a distribuição tentativa dos fundos do canal **sem transmiti-las para a blockchain**, opcionalmente seguido pelo fechamento do canal de pagamento **transmitindo** a **versão final** da transação de liquidação para distribuir os fundos do canal.

Note que qualquer um dos membros do canal pode parar e enviar o estado final do canal para a blockchain a qualquer momento.

# Ataques à Privacidade do Bitcoin

## Entrada Comum

Teoricamente as entradas de uma transação podem pertencer a usuários diferentes, mas na realidade isso é incomum, pois requer passos extras. Portanto, muitas vezes pode-se assumir que **2 endereços de entrada na mesma transação pertencem ao mesmo proprietário**.

## Detecção de Endereço de Troco UTXO

**UTXO** significa **Saídas de Transações Não Gastas** (UTXOs). Em uma transação que usa a saída de uma transação anterior como entrada, a **saída inteira precisa ser gasta** (para evitar ataques de dupla despesa). Portanto, se a intenção era **enviar** apenas **parte** do dinheiro dessa saída para um endereço e **manter** a **outra** **parte**, **2 saídas diferentes** aparecerão: a **destinada** e um **novo endereço de troco aleatório** onde o resto do dinheiro será salvo.

Então, um observador pode fazer a suposição de que **o novo endereço de troco gerado pertence ao proprietário do UTXO**.

## Redes Sociais & Fóruns

Algumas pessoas fornecem dados sobre seus endereços bitcoin em diferentes sites na Internet. **Isso torna bastante fácil identificar o proprietário de um endereço**.

## Gráficos de Transações

Ao representar as transações em gráficos, **é possível saber com certa probabilidade para onde o dinheiro de uma conta foi**. Portanto, é possível saber algo sobre **usuários** que estão **relacionados** na blockchain.

## **Heurística de entrada desnecessária**

Também chamada de "heurística de troco ótimo". Considere esta transação bitcoin. Ela tem duas entradas no valor de 2 BTC e 3 BTC e duas saídas no valor de 4 BTC e 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Assumindo que uma das saídas é o troco e a outra saída é o pagamento. Existem duas interpretações: a saída do pagamento é ou a saída de 4 BTC ou a saída de 1 BTC. Mas se a saída de 1 BTC é o montante do pagamento, então a entrada de 3 BTC é desnecessária, pois a carteira poderia ter gasto apenas a entrada de 2 BTC e pago taxas de mineração mais baixas por isso. Isso é uma indicação de que a verdadeira saída de pagamento é de 4 BTC e que 1 BTC é a saída de troco.

Isso é um problema para transações que têm mais de uma entrada. Uma maneira de corrigir esse vazamento é adicionar mais entradas até que a saída de troco seja maior que qualquer entrada, por exemplo:
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Reutilização forçada de endereço

**Reutilização forçada de endereço** ou **reutilização incentivada de endereço** ocorre quando um adversário paga uma quantidade (geralmente pequena) de bitcoin para endereços que já foram utilizados na blockchain. O adversário espera que os usuários ou seus softwares de carteira **utilizem os pagamentos como entradas para uma transação maior, o que revelará outros endereços através da heurística de propriedade de entrada comum**. Esses pagamentos podem ser entendidos como uma forma de coagir o proprietário do endereço a reutilizar o endereço sem intenção.

Este ataque é às vezes incorretamente chamado de **ataque de poeira**.

O comportamento correto por parte das carteiras é não gastar moedas que caíram em endereços vazios já utilizados.

## Outras Análises de Blockchain

* **Quantias Exatas de Pagamento**: Para evitar transações com troco, o pagamento precisa ser igual ao UTXO (o que é altamente inesperado). Portanto, uma **transação sem endereço de troco provavelmente é uma transferência entre 2 endereços do mesmo usuário**.
* **Números Redondos**: Em uma transação, se uma das saídas é um "**número redondo**", é altamente provável que este seja um **pagamento a um humano que estipulou esse preço** "número redondo", então a outra parte deve ser o troco.
* **Identificação de Carteira:** Um analista cuidadoso às vezes pode deduzir qual software criou uma certa transação, porque os **diferentes softwares de carteira nem sempre criam transações exatamente da mesma maneira**. A identificação de carteira pode ser usada para detectar saídas de troco, pois uma saída de troco é aquela gasta com a mesma identificação de carteira.
* **Correlações de Quantia e Tempo**: Se a pessoa que realizou a transação **divulga** o **tempo** e/ou a **quantia** da transação, ela pode ser facilmente **descoberta**.

## Análise de Tráfego

Alguma organização **farejando seu tráfego** pode ver você se comunicando na rede bitcoin.\
Se o adversário vê uma transação ou bloco **saindo do seu nó que não entrou anteriormente**, então ele pode saber com quase certeza que **a transação foi feita por você ou o bloco foi minerado por você**. Como conexões de internet estão envolvidas, o adversário será capaz de **vincular o endereço IP com as informações descobertas do bitcoin**.

Um atacante que não é capaz de farejar todo o tráfego da Internet, mas que tem **muitos nós de Bitcoin** para ficar **mais próximo** das **fontes**, poderia ser capaz de conhecer o endereço IP que está anunciando transações ou blocos.\
Além disso, algumas carteiras periodicamente retransmitem suas transações não confirmadas para que elas tenham mais chances de se propagar amplamente pela rede e serem mineradas.

## Outros ataques para encontrar informações sobre o proprietário de endereços

Para mais ataques, leia [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins Anônimos

## Obtendo Bitcoins Anonimamente

* **Comércio com dinheiro:** Compre bitcoin usando dinheiro.
* **Substituto de dinheiro:** Compre cartões-presente ou similares e troque-os por bitcoin online.
* **Mineração:** A mineração é a forma mais anônima de obter bitcoin. Isso se aplica à mineração solo, pois [pools de mineração](https://en.bitcoin.it/wiki/Pooled\_mining) geralmente conhecem o endereço IP do minerador.
* **Roubo:** Em teoria, outra forma de obter bitcoin anonimamente é roubá-los.

## Mixers

Um usuário **envia bitcoins para um serviço de mistura** e o serviço **devolve bitcoins diferentes para o usuário**, menos uma taxa. Teoricamente, um adversário observando a blockchain seria **incapaz de vincular** as transações de entrada e saída.

No entanto, o usuário precisa confiar que o serviço de mistura devolverá o bitcoin e também que não está salvando registros sobre as relações entre o dinheiro recebido e enviado.\
Outros serviços também podem ser usados como mixers, como cassinos Bitcoin onde você pode enviar bitcoins e recuperá-los mais tarde.

## CoinJoin

**CoinJoin** irá **misturar várias transações de diferentes usuários em apenas uma** para tornar mais **difícil** para um observador descobrir **qual entrada está relacionada a qual saída**.\
Isso oferece um novo nível de privacidade, no entanto, **algumas** **transações** onde algumas quantias de entrada e saída estão correlacionadas ou são muito diferentes do restante das entradas e saídas **ainda podem ser correlacionadas** pelo observador externo.

Exemplos de IDs de transações (prováveis) CoinJoin na blockchain do bitcoin são `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Semelhante ao coinjoin, mas melhor e para ethereum você tem** [**Tornado Cash**](https://tornado.cash) **(o dinheiro é fornecido pelos mineradores, então ele apenas aparece na sua carteira).**

## PayJoin

O tipo de CoinJoin discutido na seção anterior pode ser facilmente identificado como tal verificando as múltiplas saídas com o mesmo valor.

PayJoin (também chamado de pagamento para ponto final ou P2EP) é um tipo especial de CoinJoin entre duas partes onde uma parte paga a outra. A transação então **não tem as distintas múltiplas saídas** com o mesmo valor, e assim não é visivelmente óbvia como um CoinJoin de saídas iguais. Considere esta transação:
```
2 btc --> 3 btc
5 btc     4 btc
```
```markdown
Pode ser interpretado como uma simples transação pagando para algum lugar com troco sobrando (ignore por agora a questão de qual saída é pagamento e qual é troco). Outra maneira de interpretar esta transação é que a entrada de 2 BTC é de propriedade de um comerciante e 5 BTC é de propriedade de seu cliente, e que esta transação envolve o cliente pagando 1 BTC ao comerciante. Não há como dizer qual dessas duas interpretações está correta. O resultado é uma transação coinjoin que quebra a heurística de propriedade de entrada comum e melhora a privacidade, mas também é **indetectável e indistinguível de qualquer transação regular de bitcoin**.

Se as transações PayJoin se tornassem até moderadamente usadas, então faria com que a **heurística de propriedade de entrada comum fosse completamente falha na prática**. Como são indetectáveis, nem saberíamos se estão sendo usadas hoje. Como as empresas de vigilância de transações dependem principalmente dessa heurística, a partir de 2019 há grande entusiasmo sobre a ideia do PayJoin.

# Boas Práticas de Privacidade no Bitcoin

## Sincronização de Carteira

Carteiras de Bitcoin devem de alguma forma obter informações sobre seu saldo e histórico. Até o final de 2018, as soluções existentes mais práticas e privadas são usar uma **carteira de nó completo** (que é maximamente privada) e **filtragem de blocos do lado do cliente** (que é muito boa).

* **Nó completo:** Nós completos baixam toda a blockchain, que contém todas as [transações](https://en.bitcoin.it/wiki/Transaction) on-chain que já aconteceram no bitcoin. Assim, um adversário observando a conexão de internet do usuário não será capaz de aprender quais transações ou endereços o usuário está interessado.
* **Filtragem de blocos do lado do cliente:** A filtragem de blocos do lado do cliente funciona criando **filtros** que contêm todos os **endereços** para cada transação em um bloco. Os filtros podem testar se um **elemento está no conjunto**; falsos positivos são possíveis, mas não falsos negativos. Uma carteira leve iria **baixar** todos os filtros para cada **bloco** na **blockchain** e verificar se há correspondências com seus **próprios** **endereços**. Blocos que contêm correspondências seriam baixados na íntegra da rede peer-to-peer, e esses blocos seriam usados para obter o histórico e saldo atual da carteira.

## Tor

A rede Bitcoin usa uma rede peer-to-peer, o que significa que outros pares podem aprender seu endereço IP. É por isso que é recomendado **conectar-se através do Tor toda vez que você quiser interagir com a rede bitcoin**.

## Evitando reutilização de endereço

**Endereços sendo usados mais de uma vez é muito prejudicial para a privacidade porque isso liga mais transações na blockchain com prova de que foram criadas pela mesma entidade**. A maneira mais privada e segura de usar bitcoin é enviar um **novo endereço para cada pessoa que lhe paga**. Após os bitcoins recebidos terem sido gastos, o endereço nunca deve ser usado novamente. Além disso, um novo endereço de bitcoin deve ser exigido ao enviar bitcoin. Todas as boas carteiras de bitcoin têm uma interface de usuário que desencoraja a reutilização de endereço.

## Múltiplas transações

**Pagar** alguém com **mais de uma transação on-chain** pode reduzir muito o poder de ataques de privacidade baseados em quantia, como correlação de quantias e números redondos. Por exemplo, se o usuário quer pagar 5 BTC para alguém e não quer que o valor de 5 BTC seja facilmente pesquisável, então ele pode enviar duas transações pelos valores de 2 BTC e 3 BTC que juntos somam 5 BTC.

## Evitando troco

Evitar troco é onde as entradas e saídas de uma transação são cuidadosamente escolhidas para não requerer uma saída de troco. **Não ter uma saída de troco é excelente para a privacidade**, pois quebra as heurísticas de detecção de troco.

## Múltiplas saídas de troco

Se evitar troco não for uma opção, então **criar mais de uma saída de troco pode melhorar a privacidade**. Isso também quebra as heurísticas de detecção de troco que geralmente assumem que há apenas uma única saída de troco. Como este método usa mais espaço de bloco do que o usual, evitar troco é preferível.

# Monero

Quando o Monero foi desenvolvido, a necessidade gritante por **anonimato completo** foi o que buscou resolver, e em grande medida, preencheu esse vazio.

# Ethereum

## Gas

Gas refere-se à unidade que mede a **quantidade** de **esforço computacional** necessário para executar operações específicas na rede Ethereum. Gas refere-se à **taxa** necessária para realizar uma **transação** com sucesso no Ethereum.

Os preços do gas são denominados em **gwei**, que é uma denominação de ETH - cada gwei é igual a **0.000000001 ETH** (10-9 ETH). Por exemplo, em vez de dizer que seu gas custa 0.000000001 ether, você pode dizer que seu gas custa 1 gwei. A palavra 'gwei' significa 'giga-wei', e é igual a **1.000.000.000 wei**. Wei é a **menor unidade de ETH**.

Para calcular o gas que uma transação vai custar leia este exemplo:

Vamos dizer que Jordan tem que pagar Taylor 1 ETH. Na transação o limite de gas é de 21.000 unidades e a taxa base é de 100 gwei. Jordan inclui uma gorjeta de 10 gwei.

Usando a fórmula acima podemos calcular isso como `21.000 * (100 + 10) = 2.310.000 gwei` ou 0.00231 ETH.

Quando Jordan envia o dinheiro, 1.00231 ETH serão deduzidos da conta de Jordan. Taylor será creditado com 1.0000 ETH. O minerador recebe a gorjeta de 0.00021 ETH. A taxa base de 0.0021 ETH é queimada.

Além disso, Jordan também pode definir uma taxa máxima (`maxFeePerGas`) para a transação. A diferença entre a taxa máxima e a taxa real é reembolsada a Jordan, ou seja, `reembolso = taxa máxima - (taxa base + taxa de prioridade)`. Jordan pode definir um valor máximo a pagar pela transação para executar e não se preocupar em pagar "além" da taxa base quando a transação for executada.

Como a taxa base é calculada pela rede com base na demanda por espaço de bloco, este último parâmetro: maxFeePerGas ajuda a controlar a taxa máxima que será paga.

## Transações

Note que na rede **Ethereum** uma transação é realizada entre 2 endereços e estes podem ser **endereços de usuário ou de contrato inteligente**.\
**Contratos Inteligentes** são armazenados no livro-razão distribuído por meio de uma **transação especial**.

Transações, que mudam o estado da EVM, precisam ser transmitidas para toda a rede. Qualquer nó pode transmitir um pedido para que uma transação seja executada na EVM; após isso acontecer, um **minerador** irá **executar** a **transação** e propagar a mudança de estado resultante para o resto da rede.\
Transações requerem uma **taxa** e devem ser mineradas para se tornarem válidas.

Uma transação submetida inclui as seguintes informações:

* `recipient` – o endereço receptor (se for uma conta de propriedade externa, a transação transferirá valor. Se for uma conta de contrato, a transação executará o código do contrato)
* `signature` – o identificador do remetente. Isso é gerado quando a chave privada do remetente assina a transação e confirma que o remetente autorizou esta transação
* `value` – quantidade de ETH para transferir do remetente para o receptor (em WEI, uma denominação de ETH)
* `data` – campo opcional para incluir dados arbitrários
* `gasLimit` – a quantidade máxima de unidades de gas que podem ser consumidas pela transação. Unidades de gas representam passos computacionais
* `maxPriorityFeePerGas` - a quantidade máxima de gas a ser incluída como gorjeta para o minerador
* `maxFeePerGas` - a quantidade máxima de gas disposta a ser paga pela transação (inclusive de `baseFeePerGas` e `maxPriorityFeePerGas`)

Note que não há nenhum campo para o endereço de origem, isso porque isso pode ser extrapolado da assinatura.

# Referências

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
```
