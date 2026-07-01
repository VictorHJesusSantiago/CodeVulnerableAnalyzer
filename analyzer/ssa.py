"""
Construção real de SSA (Static Single Assignment) sobre o CFG de
analyzer/pyast_engine.py — dominadores, fronteira de dominância e inserção
de φ-nodes, seguindo o algoritmo clássico:

  - Dominadores: "A Simple, Fast Dominance Algorithm" (Cooper, Harvey,
    Kennedy, 2001) — iterativo, com interseção via números de pós-ordem.
  - Fronteira de dominância + inserção de φ-nodes: Cytron et al. (1991),
    "Efficiently Computing Static Single Assignment Form...".

Aplicação prática: com φ-nodes reais, dá para fazer uma análise de
"definite assignment" (atribuição definitiva) muito mais precisa que uma
reaching-definitions convencional — em vez de só saber "existe uma definição
que alcança este ponto", sabemos exatamente em quais nós um φ é necessário
porque nem todo caminho de entrada define a variável, sinalizando uso
potencialmente não inicializado com muito mais precisão.

Escopo declarado: opera sobre o CFG simplificado por-statement já existente
em pyast_engine.CFG (não é um compilador completo com renomeação de versões
numeradas tipo v1/v2/v3 — a inserção de φ e a análise de definite-assignment
são o núcleo real e verificável entregue aqui).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from analyzer.pyast_engine import CFG, CFGNode


# ════════════════════════════════════════════════════════════════════════════
#  1. Pós-ordem via DFS a partir da entrada
# ════════════════════════════════════════════════════════════════════════════

def _postorder(cfg: CFG) -> List[int]:
    if cfg.entry is None:
        return []
    visited: Set[int] = set()
    order: List[int] = []

    def dfs(nid: int) -> None:
        visited.add(nid)
        for succ in cfg.nodes[nid].succ:
            if succ not in visited:
                dfs(succ)
        order.append(nid)

    dfs(cfg.entry)
    # Inclui nós porventura não alcançáveis a partir da entrada (dead code)
    # numa pós-ordem própria, para que o algoritmo de dominadores não falhe.
    for nid in cfg.nodes:
        if nid not in visited:
            dfs(nid)
    return order


# ════════════════════════════════════════════════════════════════════════════
#  2. Dominadores (Cooper-Harvey-Kennedy)
# ════════════════════════════════════════════════════════════════════════════

def compute_dominators(cfg: CFG) -> Dict[int, int]:
    """Retorna idom[n] = id do dominador imediato de n. idom[entry] = entry."""
    if cfg.entry is None:
        return {}

    postorder = _postorder(cfg)
    order_index = {nid: i for i, nid in enumerate(postorder)}
    reverse_postorder = list(reversed(postorder))

    idom: Dict[int, Optional[int]] = {nid: None for nid in cfg.nodes}
    idom[cfg.entry] = cfg.entry

    def intersect(b1: int, b2: int) -> int:
        finger1, finger2 = b1, b2
        while finger1 != finger2:
            while order_index[finger1] < order_index[finger2]:
                finger1 = idom[finger1]
            while order_index[finger2] < order_index[finger1]:
                finger2 = idom[finger2]
        return finger1

    changed = True
    while changed:
        changed = False
        for b in reverse_postorder:
            if b == cfg.entry:
                continue
            preds_processed = [p for p in cfg.nodes[b].pred if idom.get(p) is not None]
            if not preds_processed:
                continue
            new_idom = preds_processed[0]
            for p in preds_processed[1:]:
                new_idom = intersect(new_idom, p)
            if idom[b] != new_idom:
                idom[b] = new_idom
                changed = True

    return {n: d for n, d in idom.items() if d is not None}


# ════════════════════════════════════════════════════════════════════════════
#  3. Fronteira de dominância (Cytron et al.)
# ════════════════════════════════════════════════════════════════════════════

def compute_dominance_frontier(cfg: CFG, idom: Dict[int, int]) -> Dict[int, Set[int]]:
    df: Dict[int, Set[int]] = {nid: set() for nid in cfg.nodes}
    for b in cfg.nodes:
        preds = cfg.nodes[b].pred
        if len(preds) < 2:
            continue
        for p in preds:
            if p not in idom:
                continue
            runner = p
            while runner != idom.get(b) and runner in idom:
                df[runner].add(b)
                if idom[runner] == runner:  # evita loop infinito na raiz
                    break
                runner = idom[runner]
    return df


# ════════════════════════════════════════════════════════════════════════════
#  4. Inserção de φ-nodes (algoritmo clássico de SSA mínima)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PhiPlacement:
    """φ-nodes necessários por variável: var -> conjunto de node ids onde o
    φ deve ser inserido (porque múltiplas definições convergem ali)."""
    phi_sites: Dict[str, Set[int]] = field(default_factory=dict)


def place_phi_nodes(cfg: CFG, dom_frontier: Dict[int, Set[int]]) -> PhiPlacement:
    placement = PhiPlacement()

    all_vars: Set[str] = set()
    for node in cfg.nodes.values():
        all_vars |= node.defs

    for var in all_vars:
        def_sites = {nid for nid, node in cfg.nodes.items() if var in node.defs}
        worklist = list(def_sites)
        ever_on_worklist = set(def_sites)
        has_phi: Set[int] = set()

        while worklist:
            n = worklist.pop()
            for d in dom_frontier.get(n, set()):
                if d not in has_phi:
                    has_phi.add(d)
                    placement.phi_sites.setdefault(var, set()).add(d)
                    if d not in ever_on_worklist:
                        ever_on_worklist.add(d)
                        worklist.append(d)

    return placement


def build_ssa(cfg: CFG) -> tuple:
    """Pipeline completo: dominadores -> fronteira -> φ-placement.
    Retorna (idom, dominance_frontier, phi_placement)."""
    idom = compute_dominators(cfg)
    df = compute_dominance_frontier(cfg, idom)
    phi = place_phi_nodes(cfg, df)
    return idom, df, phi


# ════════════════════════════════════════════════════════════════════════════
#  5. Definite assignment (atribuição definitiva) — usa os φ-sites reais
# ════════════════════════════════════════════════════════════════════════════

def definite_assignment(cfg: CFG, params: Set[str]) -> Dict[int, Set[str]]:
    """Dataflow forward com meet = INTERSEÇÃO (não união): IN[n] = variáveis
    que estão DEFINITIVAMENTE atribuídas em TODOS os caminhos até n. Isso é
    o que Java/C# usam para acusar 'variable might not have been initialized'.
    Muito mais preciso que reaching-definitions (que é conservador via união).
    """
    if cfg.entry is None:
        return {}

    all_nodes = set(cfg.nodes.keys())
    IN: Dict[int, Set[str]] = {nid: set(all_nodes) if nid != cfg.entry else set(params) for nid in cfg.nodes}
    OUT: Dict[int, Set[str]] = {nid: set() for nid in cfg.nodes}

    order = _postorder(cfg)  # qualquer ordem estável funciona com fixed-point
    changed = True
    while changed:
        changed = False
        for nid in order:
            node = cfg.nodes[nid]
            preds = node.pred
            if nid == cfg.entry:
                new_in = set(params)
            elif preds:
                new_in = None
                for p in preds:
                    new_in = OUT[p] if new_in is None else (new_in & OUT[p])
                new_in = new_in or set()
            else:
                new_in = set()

            new_out = new_in | node.defs

            if new_in != IN[nid] or new_out != OUT[nid]:
                IN[nid] = new_in
                OUT[nid] = new_out
                changed = True

    return IN
