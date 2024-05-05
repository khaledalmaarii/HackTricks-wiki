# O Protocolo Modbus

## Introdução ao Protocolo Modbus

O protocolo Modbus é um protocolo amplamente utilizado em Sistemas de Automação e Controle Industrial. O Modbus permite a comunicação entre vários dispositivos, como controladores lógicos programáveis (CLPs), sensores, atuadores e outros dispositivos industriais. Compreender o Protocolo Modbus é essencial, pois este é o protocolo de comunicação mais utilizado nos Sistemas de Controle Industrial (ICS) e possui uma grande superfície de ataque potencial para sniffing e até mesmo para injetar comandos nos CLPs.

Aqui, os conceitos são apresentados de forma pontual, fornecendo contexto sobre o protocolo e sua natureza de operação. O maior desafio na segurança do sistema ICS é o custo de implementação e atualização. Esses protocolos e padrões foram projetados no início dos anos 80 e 90 e ainda são amplamente utilizados. Como uma indústria possui muitos dispositivos e conexões, atualizar os dispositivos é muito difícil, o que proporciona aos hackers uma vantagem ao lidar com protocolos desatualizados. Ataques ao Modbus são praticamente inevitáveis, uma vez que ele continuará sendo usado sem atualização, e sua operação é crítica para a indústria.

## A Arquitetura Cliente-Servidor

O Protocolo Modbus é tipicamente utilizado em uma Arquitetura Cliente-Servidor, onde um dispositivo mestre (cliente) inicia a comunicação com um ou mais dispositivos escravos (servidores). Isso também é conhecido como arquitetura Mestre-Escravo, amplamente utilizada em eletrônicos e IoT com SPI, I2C, etc.

## Versões Serial e Ethernet

O Protocolo Modbus é projetado tanto para Comunicação Serial quanto para Comunicações Ethernet. A Comunicação Serial é amplamente utilizada em sistemas legados, enquanto dispositivos modernos suportam Ethernet, que oferece altas taxas de dados e é mais adequada para redes industriais modernas.

## Representação de Dados

Os dados são transmitidos no protocolo Modbus como ASCII ou Binário, embora o formato binário seja utilizado devido à sua compatibilidade com dispositivos mais antigos.

## Códigos de Função

O Protocolo Modbus funciona com a transmissão de códigos de função específicos que são usados para operar os CLPs e vários dispositivos de controle. Esta parte é importante para entender, pois ataques de repetição podem ser feitos retransmitindo códigos de função. Dispositivos legados não suportam qualquer criptografia para a transmissão de dados e geralmente possuem fios longos que os conectam, o que resulta em manipulação desses fios e captura/injeção de dados.

## Endereçamento do Modbus

Cada dispositivo na rede possui um endereço único que é essencial para a comunicação entre dispositivos. Protocolos como Modbus RTU, Modbus TCP, etc. são usados para implementar o endereçamento e servem como uma camada de transporte para a transmissão de dados. Os dados transferidos estão no formato de protocolo Modbus que contém a mensagem.

Além disso, o Modbus também implementa verificações de erro para garantir a integridade dos dados transmitidos. Mas, acima de tudo, o Modbus é um Padrão Aberto e qualquer pessoa pode implementá-lo em seus dispositivos. Isso fez com que este protocolo se tornasse um padrão global e fosse amplamente utilizado na indústria de automação industrial.

Devido ao seu amplo uso e falta de atualizações, atacar o Modbus fornece uma vantagem significativa com sua superfície de ataque. Os ICS dependem muito da comunicação entre dispositivos e quaisquer ataques feitos neles podem ser perigosos para a operação dos sistemas industriais. Ataques como repetição, injeção de dados, sniffing e vazamento de dados, Negação de Serviço, falsificação de dados, etc. podem ser realizados se o meio de transmissão for identificado pelo atacante.
