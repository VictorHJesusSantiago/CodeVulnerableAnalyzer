# Triagem e IA

O classificador local aprende rótulos de verdadeiro/falso positivo sem enviar
código para terceiros. Cada resultado inclui probabilidade e contribuições das
features. O ranking combina severidade, confiança, reachability,
exploitability, EPSS e criticidade de negócio.

Regras few-shot nascem com confiança baixa e `requires_review=true`. O gerador
escapa metacaracteres e exige um marcador comum discriminante.
