# Performance e operação distribuída

- `parallel_map`: processos isolados e timeout por arquivo.
- `stream_lines`: leitura incremental de arquivos grandes.
- `RuleAutomaton`: uma passagem combinada para regex compatíveis.
- `ASTCache`: índice persistente por SHA-256.
- `profile`: tempo wall/CPU e pico de memória.
- `DistributedCoordinator/Worker`: protocolo independente de Kafka/RabbitMQ.

Configure limites de tamanho, tempo e quantidade de achados conforme a memória
disponível no runner.
