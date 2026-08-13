"""
Mini-corpus de regressão estilo NIST Juliet Test Suite: pares (bad/good)
de código conhecido vulnerável vs. sua correção idiomática, um por CWE
relevante. Usado por tests/test_benchmark.py para garantir que o
scanner detecta o padrão vulnerável ("bad") e não sinaliza (ou sinaliza
bem menos) a versão corrigida ("good") com a MESMA regra.

Convenção de nomes inspirada no Juliet: CWE<nnn>_<slug>.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BenchmarkCase:
    name: str
    language: str
    cwe: str
    bad_code: str
    good_code: str


CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="CWE089_sql_injection_python",
        language="py",
        cwe="CWE-89",
        bad_code=(
            "def get_user(conn, user_id):\n"
            "    cursor = conn.cursor()\n"
            '    query = "SELECT * FROM users WHERE id = " + user_id\n'
            "    cursor.execute(query)\n"
        ),
        good_code=(
            "def get_user(conn, user_id):\n"
            "    cursor = conn.cursor()\n"
            '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        ),
    ),
    BenchmarkCase(
        name="CWE078_command_injection_python",
        language="py",
        cwe="CWE-78",
        bad_code=('import os\ndef cleanup(filename):\n    os.system("rm -f " + filename)\n'),
        good_code=(
            'import subprocess\ndef cleanup(filename):\n    subprocess.run(["rm", "-f", filename], check=True)\n'
        ),
    ),
    BenchmarkCase(
        name="CWE095_eval_injection_python",
        language="py",
        cwe="CWE-95",
        bad_code=("def compute(expr):\n    return eval(expr)\n"),
        good_code=("import ast\ndef compute(expr):\n    return ast.literal_eval(expr)\n"),
    ),
    BenchmarkCase(
        name="CWE798_hardcoded_credentials_python",
        language="py",
        cwe="CWE-798",
        bad_code=('DB_PASSWORD = "SuperSecretP@ss123"\ndef connect():\n    return db.connect(password=DB_PASSWORD)\n'),
        good_code=(
            "import os\n"
            'DB_PASSWORD = os.environ["DB_PASSWORD"]\n'
            "def connect():\n"
            "    return db.connect(password=DB_PASSWORD)\n"
        ),
    ),
    BenchmarkCase(
        name="CWE327_weak_hash_python",
        language="py",
        cwe="CWE-327",
        bad_code=("import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"),
        good_code=("import hashlib\ndef hash_password(pw):\n    return hashlib.sha256(pw.encode()).hexdigest()\n"),
    ),
    BenchmarkCase(
        name="CWE022_path_traversal_python",
        language="py",
        cwe="CWE-22",
        bad_code=(
            "import os\n"
            "def read_upload(base_dir, filename):\n"
            "    return open(os.path.join(base_dir, filename)).read()\n"
        ),
        good_code=(
            "import os\n"
            "def read_upload(base_dir, filename):\n"
            "    safe_name = os.path.basename(filename)\n"
            "    full_path = os.path.realpath(os.path.join(base_dir, safe_name))\n"
            "    if not full_path.startswith(os.path.realpath(base_dir)):\n"
            '        raise ValueError("invalid path")\n'
            "    with open(full_path) as f:\n"
            "        return f.read()\n"
        ),
    ),
    BenchmarkCase(
        name="CWE502_insecure_deserialization_python",
        language="py",
        cwe="CWE-502",
        bad_code=("import pickle\ndef load(data):\n    return pickle.loads(data)\n"),
        good_code=("import json\ndef load(data):\n    return json.loads(data)\n"),
    ),
    BenchmarkCase(
        name="CWE078_command_injection_php",
        language="php",
        cwe="CWE-78",
        bad_code=('<?php\nfunction cleanup($filename) {\n    system("rm -f " . $filename);\n}\n'),
        good_code=(
            "<?php\n"
            "function cleanup($filename) {\n"
            "    $safe = basename($filename);\n"
            '    $path = __DIR__ . "/uploads/" . $safe;\n'
            "    if (file_exists($path)) {\n"
            "        unlink($path);\n"
            "    }\n"
            "}\n"
        ),
    ),
    BenchmarkCase(
        name="CWE089_sql_injection_php",
        language="php",
        cwe="CWE-89",
        bad_code=(
            "<?php\n"
            "function getUser($conn, $id) {\n"
            '    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);\n'
            "}\n"
        ),
        good_code=(
            "<?php\n"
            "function getUser($conn, $id) {\n"
            '    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");\n'
            '    $stmt->bind_param("i", $id);\n'
            "    $stmt->execute();\n"
            "}\n"
        ),
    ),
    BenchmarkCase(
        name="CWE079_xss_javascript",
        language="js",
        cwe="CWE-79",
        bad_code=('function render(comment) {\n    document.getElementById("out").innerHTML = comment;\n}\n'),
        good_code=('function render(comment) {\n    document.getElementById("out").textContent = comment;\n}\n'),
    ),
]
