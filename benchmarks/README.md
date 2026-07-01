# Benchmarks de precisão

O executor usa um manifesto JSON independente do dataset. Cada caso informa o
arquivo, os IDs esperados e regras explicitamente ausentes. Isso permite usar
Juliet, OWASP Benchmark ou fixtures próprias sem copiar datasets de terceiros.

Execute `python benchmarks/run_precision.py manifest.json`. A saída contém
precision, recall, F1, falsos positivos e falsos negativos por regra.
