<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# Terminologia Básica

* **Contrato inteligente**: Contratos inteligentes são simplesmente **programas armazenados em um blockchain que são executados quando condições predeterminadas são atendidas**. Eles são tipicamente usados para automatizar a **execução** de um **acordo** para que todos os participantes possam ter certeza imediata do resultado, sem envolvimento ou perda de tempo de intermediários. (De [aqui](https://www.ibm.com/topics/smart-contracts)).
* Basicamente, um contrato inteligente é um **pedaço de código** que será executado quando as pessoas acessarem e aceitarem o contrato. Contratos inteligentes **rodam em blockchains** (então os resultados são armazenados de forma imutável) e podem ser lidos pelas pessoas antes de aceitá-los.
* **dApps**: **Aplicações descentralizadas** são implementadas em cima de **contratos** **inteligentes**. Elas geralmente têm uma interface onde o usuário pode interagir com o aplicativo, o **back-end** é público (para que possa ser auditado) e é implementado como um **contrato inteligente**. Às vezes, o uso de um banco de dados é necessário, o blockchain Ethereum aloca determinado armazenamento para cada conta.
* **Tokens & moedas**: Uma **moeda** é uma criptomoeda que age como **dinheiro digital** e um **token** é algo que **representa** algum **valor**, mas não é uma moeda.
* **Tokens de utilidade**: Esses tokens permitem que o usuário **acesso a determinado serviço posteriormente** (é algo que tem algum valor em um ambiente específico).
* **Tokens de segurança**: Estes representam a **propriedade** ou algum ativo.
* **DeFi**: **Finanças Descentralizadas**.
* **DEX: Plataformas de Câmbio Descentralizadas**.
* **DAOs**: **Organizações Autônomas Descentralizadas**.

# Mecanismos de Consenso

Para que uma transação em blockchain seja reconhecida, ela deve ser **anexada** ao **blockchain**. Validadores (mineradores) realizam essa anexação; na maioria dos protocolos, eles **recebem uma recompensa** por fazê-lo. Para que o blockchain permaneça seguro, ele deve ter um mecanismo para **impedir que um usuário ou grupo malicioso assuma a maioria da validação**.

Prova de trabalho, outro mecanismo de consenso comumente usado, usa uma validação de poder computacional para verificar transações, exigindo que um potencial atacante adquira uma grande fração do poder computacional da rede de validadores.

## Prova de Trabalho (PoW)

Isso usa uma **validação de poder computacional** para verificar transações, exigindo que um potencial atacante adquira uma grande fração do poder computacional da rede de validadores.\
Os **mineradores** irão **selecionar várias transações** e então começar a **calcular a Prova de Trabalho**. O **minerador com os maiores recursos computacionais** é mais provável de **terminar mais cedo** a Prova de Trabalho e receber as taxas de todas as transações.

## Prova de Participação (PoS)

O PoS alcança isso ao **exigir que os validadores tenham uma quantidade de tokens de blockchain**, exigindo que **potenciais atacantes adquiram uma grande fração dos tokens** no blockchain para montar um ataque.\
Nesse tipo de consenso, quanto mais tokens um minerador possui, mais provável será que o minerador seja solicitado a criar o próximo bloco.\
Comparado com o PoW, isso **reduziu significativamente o consumo de energia** que os mineradores estão gastando.

# Bitcoin

## Transações

Uma **transação** simples é um **movimento de dinheiro** de um endereço para outro.\
Um **endereço** no bitcoin é o hash da **chave pública**, portanto, alguém para fazer uma transação a partir de um endereço precisa saber a chave privada associada a essa chave pública (o endereço).\
Então, quando uma **transação** é realizada, ela é **assinada** com a chave privada do endereço para mostrar que a transação é **legítima**.

A primeira parte da produção de uma assinatura digital no Bitcoin pode ser representada matematicamente da seguinte forma:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Onde:

* \_d\_A é a **chave privada** de assinatura
* _m_ é a **transação**
* Fhash é a função de hash
* Fsig é o algoritmo de assinatura
* Sig é a assinatura resultante

A função de assinatura (Fsig) produz uma assinatura (Sig) que consiste em dois valores: R e S:

* Sig = (R, S)

Uma vez que R e S foram calculados, eles são serializados em um fluxo de bytes que é codificado usando um esquema de codificação de padrão internacional conhecido como Regras de Codificação Distintas (ou DER). Para verificar se a assinatura é válida, é usado um algoritmo de verificação de assinatura. A verificação de uma assinatura digital requer o seguinte:

* Assinatura (R e S)
* Hash da transação
* A chave pública que corresponde à chave privada usada para criar a assinatura

A verificação de uma assinatura efetivamente significa que apenas o proprietário da chave privada (que gerou a chave pública) poderia ter produzido a assinatura na transação. O algoritmo de verificação de assinatura retornará 'VERDADEIRO' se a assinatura for realmente válida.

### Transações Multisig

Um **endereço** multi-assinatura é um endereço associado a mais de uma chave privada ECDSA. O tipo mais simples é um endereço m-de-n - ele está associado a n chaves privadas e enviar bitcoins deste endereço requer assinaturas de pelo menos m chaves. Uma **transação** multi-assinatura é aquela que envia fundos de um endereço multi-assinatura.

### Campos de Transações

Cada transação bitcoin tem vários campos:

* **Inputs**: A quantidade e o endereço **de onde** os **bitcoins** estão **sendo** transferidos
* **Outputs**: O endereço e as quantidades que são **transferidas** para **cada** **saída**
* **Taxa:** A quantidade de **dinheiro** que é **paga** ao **minerador** da transação
* **Script\_sig**: Assinatura de script da transação
* **Script\_type**: Tipo de transação

Existem **2 tipos principais** de transações:

* **P2PKH: "Pagar ao Hash da Chave Pública"**: É assim que as transações são feitas. Você está exigindo que o **remetente** forneça uma **assinatura** válida (da chave privada) e **chave pública**. O script de saída da transação usará a assinatura e a chave pública e, por meio de algumas funções criptográficas, verificará **se corresponde** ao hash da chave pública, se corresponder, então os **fundos** serão **gastáveis**. Este método oculta sua chave pública na forma de um hash para segurança adicional.
* **P2SH: "Pagar ao Hash do Script":** As saídas de uma transação são apenas **scripts** (isso significa que a pessoa que deseja esse dinheiro envia um script) que, se **executados com parâmetros específicos, resultarão em um booleano de `true` ou `false`**. Se um minerador executar o script de saída com os parâmetros fornecidos e resultar em `true`, o **dinheiro será enviado para a saída desejada**. `P2SH` é usado para **carteiras multi-assinatura, tornando os scripts de saída** lógica que verifica várias assinaturas antes de aceitar a transação**. `P2SH` também pode ser usado para permitir que qualquer pessoa, ou ninguém, gaste os fundos. Se o script de saída de uma transação P2SH for apenas `1` para verdadeiro, então tentar gastar a saída sem fornecer parâmetros resultará apenas em `1`, tornando o dinheiro gastável por qualquer pessoa que tente. Isso também se aplica a scripts que retornam `0`, tornando a saída gastável por ninguém.

## Rede Lightning

Este protocolo ajuda a **realizar várias transações para um canal** e **apenas** **envia** o **estado final** para o blockchain para salvá-lo.\
Isso **melhora** a velocidade do blockchain do bitcoin (ele permite apenas 7 pagamentos por segundo) e permite criar **transações mais difíceis de rastrear** à medida que o canal é criado por meio de nós do blockchain do bitcoin:

![](<../../.gitbook/assets/image (611).png>)

O uso normal da Rede Lightning consiste em **abrir um canal de pagamento** comprometendo uma transação de financiamento ao blockchain base relevante (camada 1), seguida por fazer **qualquer número** de transações da Rede Lightning que atualizam a distribuição provisória dos fundos do canal **sem transmiti-los para o blockchain**, opcionalmente seguido por fechar o canal de pagamento **transmitindo** a **versão final** da transação de liquidação para distribuir os fundos do canal.

Observe que qualquer um dos membros do canal pode parar e enviar o estado final do canal para o blockchain a qualquer momento.

# Ataques de Privacidade do Bitcoin

## Entrada Comum

Teoricamente, as entradas de uma transação podem pertencer a diferentes usuários, mas na realidade isso é incomum, pois requer etapas extras. Portanto, muitas vezes pode-se assumir que **2 endereços de entrada na mesma transação pertencem ao mesmo proprietário**.

## Detecção de Endereço de Troco UTXO

**UTXO** significa **Saídas de Transação Não Gasta** (UTXOs). Em uma transação que usa a saída de uma transação anterior como entrada, **toda a saída precisa ser gasta** (para evitar ataques de gasto duplo). Portanto, se a intenção era **enviar** apenas **parte** do dinheiro dessa saída para um endereço e **manter** a **outra** **parte**, **2 saídas diferentes** aparecerão: a **pretendida** e um **novo endereço de troco aleatório** onde o restante do dinheiro será salvo.

Então, um observador pode fazer a suposição de que **o novo endereço de troco gerado pertence ao proprietário do UTXO**.

## Redes Sociais e Fóruns

Algumas pessoas fornecem dados sobre seus endereços de bitcoin em diferentes sites na Internet. **Isso torna bastante fácil identificar o proprietário de um endereço**.

## Gráficos de Transações

Ao representar as transações em gráficos, **é possível saber com certa probabilidade para onde foi o dinheiro de uma conta**. Portanto, é possível saber algo sobre **usuários** que estão **relacionados** no blockchain.

## **Heurística de Entrada Desnecessária**

Também chamada de "heurística de troco ideal". Considere esta transação de bitcoin. Ela tem duas entradas no valor de 2 BTC e 3 BTC e duas saídas no valor de 4 BTC e 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Assumindo que uma das saídas é troco e a outra saída é o pagamento. Existem duas interpretações: a saída de pagamento é ou a saída de 4 BTC ou a saída de 1 BTC. Mas se a saída de 1 BTC for o valor do pagamento, então a entrada de 3 BTC é desnecessária, pois a carteira poderia ter gasto apenas a entrada de 2 BTC e pago taxas de mineradores mais baixas para fazê-lo. Isso é um indicativo de que a saída de pagamento real é de 4 BTC e que 1 BTC é a saída de troco.

Isso é um problema para transações que possuem mais de uma entrada. Uma maneira de corrigir essa falha é adicionar mais entradas até que a saída de troco seja maior do que qualquer entrada, por exemplo:
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Reutilização forçada de endereços

A **reutilização forçada de endereços** ou **reutilização incentivada de endereços** ocorre quando um adversário paga uma quantia (geralmente pequena) de bitcoin para endereços que já foram usados na cadeia de blocos. O adversário espera que os usuários ou seu software de carteira **utilizem os pagamentos como entradas para uma transação maior, o que revelará outros endereços por meio da heurística de propriedade de entrada comum**. Esses pagamentos podem ser entendidos como uma forma de coagir o proprietário do endereço a reutilizá-lo involuntariamente.

Essa técnica às vezes é incorretamente chamada de **ataque de poeira**.

O comportamento correto das carteiras é não gastar moedas que tenham sido depositadas em endereços vazios já utilizados.

## Outras Análises de Blockchain

* **Quantias de Pagamento Exatas**: Para evitar transações com troco, o pagamento precisa ser igual ao UTXO (o que é altamente inesperado). Portanto, uma **transação sem endereço de troco provavelmente é uma transferência entre 2 endereços do mesmo usuário**.
* **Números Redondos**: Em uma transação, se uma das saídas for um "**número redondo**", é altamente provável que seja um **pagamento a um humano que definiu aquele** "número redondo" **como preço**, então a outra parte deve ser o troco.
* **Identificação de Carteira**: Um analista cuidadoso às vezes pode deduzir qual software criou uma determinada transação, pois os **diferentes softwares de carteira nem sempre criam transações exatamente da mesma maneira**. A identificação de carteira pode ser usada para detectar saídas de troco, pois uma saída de troco é aquela gasta com a mesma identificação de carteira.
* **Correlações de Quantia e Tempo**: Se a pessoa que realizou a transação **divulgar** o **horário** e/ou **quantia** da transação, isso pode ser facilmente **descoberto**.

## Análise de Tráfego

Alguma organização **interceptando seu tráfego** pode ver você se comunicando na rede bitcoin.\
Se o adversário vir uma transação ou bloco **saindo do seu nó que não entrou anteriormente**, então ele pode saber com quase certeza que **a transação foi feita por você ou o bloco foi minerado por você**. Como conexões de internet estão envolvidas, o adversário poderá **vincular o endereço IP às informações de bitcoin descobertas**.

Um atacante que não consegue interceptar todo o tráfego da Internet, mas que possui **muitos nós Bitcoin** para ficar **mais próximo** das fontes, pode ser capaz de saber os endereços IP que estão anunciando transações ou blocos.\
Além disso, algumas carteiras periodicamente retransmitem suas transações não confirmadas para que tenham mais chances de se propagar amplamente pela rede e serem mineradas.

## Outros ataques para encontrar informações sobre o proprietário dos endereços

Para mais ataques, leia [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins Anônimos

## Obtendo Bitcoins de forma Anônima

* **Negociações em dinheiro:** Compre bitcoin usando dinheiro.
* **Substituto de dinheiro:** Compre cartões-presente ou similares e troque-os por bitcoin online.
* **Mineração:** A mineração é a maneira mais anônima de obter bitcoin. Isso se aplica à mineração solo, pois [pools de mineração](https://en.bitcoin.it/wiki/Pooled\_mining) geralmente conhecem o endereço IP do minerador.
* **Roubo:** Em teoria, outra forma de obter bitcoin de forma anônima é roubá-los.

## Misturadores

Um usuário **enviaria bitcoins para um serviço de mistura** e o serviço **enviaria bitcoins diferentes de volta para o usuário**, com uma taxa. Em teoria, um adversário observando a blockchain seria **incapaz de vincular** as transações de entrada e saída.

No entanto, o usuário precisa confiar no serviço de mistura para devolver o bitcoin e também para não salvar logs sobre as relações entre o dinheiro recebido e enviado.\
Alguns outros serviços também podem ser usados como misturadores, como cassinos de Bitcoin onde você pode enviar bitcoins e recuperá-los posteriormente.

## CoinJoin

**CoinJoin** irá **misturar várias transações de diferentes usuários em apenas uma** para tornar mais **difícil** para um observador descobrir **qual entrada está relacionada a qual saída**.\
Isso oferece um novo nível de privacidade, no entanto, **algumas** **transações** em que algumas quantias de entrada e saída estão correlacionadas ou são muito diferentes das demais entradas e saídas **ainda podem ser correlacionadas** pelo observador externo.

Exemplos de IDs de transações (provavelmente) CoinJoin na blockchain do bitcoin são `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similar ao CoinJoin, mas melhor e para o ethereum você tem** [**Tornado Cash**](https://tornado.cash) **(o dinheiro é fornecido pelos mineradores, então ele aparece apenas em sua carteira).**

## PayJoin

O tipo de CoinJoin discutido na seção anterior pode ser facilmente identificado como tal verificando as múltiplas saídas com o mesmo valor.

PayJoin (também chamado de pay-to-end-point ou P2EP) é um tipo especial de CoinJoin entre duas partes, onde uma parte paga à outra. A transação então **não tem as distintas múltiplas saídas** com o mesmo valor e, portanto, não é visível de forma óbvia como um CoinJoin de saída igual. Considere esta transação:
```
2 btc --> 3 btc
5 btc     4 btc
```
Pode ser interpretado como uma simples transação pagando para algum lugar com troco restante (ignore por enquanto a questão de qual saída é pagamento e qual é troco). Outra maneira de interpretar essa transação é que a entrada de 2 BTC é de propriedade de um comerciante e 5 BTC é de propriedade de seu cliente, e que essa transação envolve o cliente pagando 1 BTC ao comerciante. Não há como dizer qual dessas duas interpretações está correta. O resultado é uma transação de coinjoin que quebra a heurística comum de propriedade de entrada e melhora a privacidade, mas também é **indetectável e indistinguível de qualquer transação de bitcoin regular**.

Se as transações PayJoin se tornassem moderadamente usadas, isso faria com que a **heurística comum de propriedade de entrada seja completamente falha na prática**. Como são indetectáveis, nem mesmo saberíamos se estão sendo usadas hoje. Como as empresas de vigilância de transações dependem principalmente dessa heurística, a ideia do PayJoin tem gerado grande entusiasmo desde 2019.

# Boas Práticas de Privacidade do Bitcoin

## Sincronização da Carteira

As carteiras de Bitcoin devem de alguma forma obter informações sobre seu saldo e histórico. A partir do final de 2018, as soluções práticas e privadas mais existentes são usar uma **carteira de nó completo** (que é maximamente privada) e **filtragem de bloco do lado do cliente** (que é muito boa).

* **Nó completo:** Os nós completos baixam toda a blockchain que contém todas as [transações](https://en.bitcoin.it/wiki/Transaction) on-chain que já aconteceram no bitcoin. Portanto, um adversário que observe a conexão com a internet do usuário não será capaz de saber quais transações ou endereços o usuário está interessado.
* **Filtragem de bloco do lado do cliente:** A filtragem de bloco do lado do cliente funciona tendo **filtros** criados que contêm todos os **endereços** para cada transação em um bloco. Os filtros podem testar se um **elemento está no conjunto**; falsos positivos são possíveis, mas não falsos negativos. Uma carteira leve **baixaria** todos os filtros para cada **bloco** na **blockchain** e verifica se há correspondências com seus **próprios** **endereços**. Blocos que contêm correspondências seriam baixados na íntegra da rede peer-to-peer, e esses blocos seriam usados para obter o histórico e saldo atual da carteira.

## Tor

A rede Bitcoin usa uma rede peer-to-peer, o que significa que outros pares podem descobrir seu endereço IP. Por isso, é recomendável **conectar-se através do Tor sempre que quiser interagir com a rede Bitcoin**.

## Evitar reutilização de endereços

**Endereços sendo usados mais de uma vez é muito prejudicial para a privacidade, pois isso vincula mais transações de blockchain com a prova de que foram criadas pela mesma entidade**. A maneira mais privada e segura de usar bitcoin é enviar um **novo endereço para cada pessoa que lhe paga**. Depois que as moedas recebidas forem gastas, o endereço nunca deve ser usado novamente. Além disso, um novo endereço de bitcoin deve ser exigido ao enviar bitcoin. Todas as boas carteiras de bitcoin têm uma interface de usuário que desencoraja a reutilização de endereços.

## Múltiplas transações

**Pagar** alguém com **mais de uma transação on-chain** pode reduzir significativamente o poder de ataques de privacidade baseados em quantidades, como correlação de quantidades e números redondos. Por exemplo, se o usuário quiser pagar 5 BTC para alguém e não quiser que o valor de 5 BTC seja facilmente pesquisado, então ele pode enviar duas transações no valor de 2 BTC e 3 BTC, que juntas somam 5 BTC.

## Evitar troco

Evitar troco é quando as entradas e saídas da transação são cuidadosamente escolhidas para não exigir uma saída de troco. **Não ter uma saída de troco é excelente para a privacidade**, pois quebra as heurísticas de detecção de troco.

## Múltiplas saídas de troco

Se a evitação de troco não for uma opção, então **criar mais de uma saída de troco pode melhorar a privacidade**. Isso também quebra as heurísticas de detecção de troco, que geralmente assumem que há apenas uma única saída de troco. Como esse método usa mais espaço de bloco do que o usual, a evitação de troco é preferível.

# Monero

Quando o Monero foi desenvolvido, a grande necessidade de **anonimato completo** era o que ele buscava resolver, e em grande parte, preencheu esse vazio.

# Ethereum

## Gas

Gas refere-se à unidade que mede a **quantidade** de **esforço computacional** necessária para executar operações específicas na rede Ethereum. Gas refere-se à **taxa** necessária para conduzir com sucesso uma **transação** na Ethereum.

Os preços do gas são denominados em **gwei**, que por sua vez é uma denominação de ETH - cada gwei é igual a **0,000000001 ETH** (10-9 ETH). Por exemplo, em vez de dizer que seu gas custa 0,000000001 ether, você pode dizer que seu gas custa 1 gwei. A palavra 'gwei' significa 'giga-wei' e é igual a **1.000.000.000 wei**. Wei é a **menor unidade de ETH**.

Para calcular o gas que uma transação vai custar, leia este exemplo:

Digamos que Jordan tenha que pagar 1 ETH a Taylor. Na transação, o limite de gas é de 21.000 unidades e a taxa base é de 100 gwei. Jordan inclui uma gorjeta de 10 gwei.

Usando a fórmula acima, podemos calcular isso como `21.000 * (100 + 10) = 2.310.000 gwei` ou 0,00231 ETH.

Quando Jordan envia o dinheiro, 1,00231 ETH será deduzido da conta de Jordan. Taylor será creditado com 1,0000 ETH. O minerador recebe a gorjeta de 0,00021 ETH. A taxa base de 0,0021 ETH é queimada.

Além disso, Jordan também pode definir uma taxa máxima (`maxFeePerGas`) para a transação. A diferença entre a taxa máxima e a taxa real é reembolsada a Jordan, ou seja, `reembolso = taxa máxima - (taxa base + taxa de prioridade)`. Jordan pode definir um valor máximo a ser pago pela transação para ser executada e não se preocupar em pagar a mais "além" da taxa base quando a transação for executada.

Como a taxa base é calculada pela rede com base na demanda por espaço de bloco, esse último parâmetro: maxFeePerGas ajuda a controlar a taxa máxima que será paga.

## Transações

Observe que na rede **Ethereum** uma transação é realizada entre 2 endereços e estes podem ser **endereços de usuário ou contratos inteligentes**.\
**Contratos Inteligentes** são armazenados no livro-razão distribuído por meio de uma **transação especial**.

Transações, que alteram o estado do EVM, precisam ser transmitidas para toda a rede. Qualquer nó pode transmitir uma solicitação para que uma transação seja executada no EVM; depois que isso acontece, um **minerador** irá **executar** a **transação** e propagar a mudança de estado resultante para o resto da rede.\
Transações requerem uma **taxa** e devem ser mineradas para se tornarem válidas.

Uma transação enviada inclui as seguintes informações:

* `destinatário` – o endereço de recebimento (se for uma conta de propriedade externa, a transação transferirá valor. Se for uma conta de contrato, a transação executará o código do contrato)
* `assinatura` – o identificador do remetente. Isso é gerado quando a chave privada do remetente assina a transação e confirma que o remetente autorizou essa transação
* `valor` – quantidade de ETH a ser transferida do remetente para o destinatário (em WEI, uma denominação de ETH)
* `dados` – campo opcional para incluir dados arbitrários
* `gasLimit` – a quantidade máxima de unidades de gas que podem ser consumidas pela transação. Unidades de gas representam etapas computacionais
* `maxPriorityFeePerGas` - a quantidade máxima de gas a ser incluída como gorjeta para o minerador
* `maxFeePerGas` - a quantidade máxima de gas disposta a ser paga pela transação (inclusive de `baseFeePerGas` e `maxPriorityFeePerGas`)

Observe que não há nenhum campo para o endereço de origem, isso porque isso pode ser extrapolado da assinatura.

# Referências

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
