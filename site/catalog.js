const rules=window.VULNSCAN_RULES||[];
const input=document.querySelector("#search"),root=document.querySelector("#rules"),status=document.querySelector("#status");
function render(){const q=input.value.toLowerCase(),rows=rules.filter(r=>JSON.stringify(r).toLowerCase().includes(q));status.textContent=`${rows.length} regras`;root.innerHTML=rows.map(r=>`<article class="rule"><h2>${esc(r.id)} — ${esc(r.name)}</h2><p class="severity">Severidade: ${esc(r.severity)}</p><p>${esc(r.description)}</p></article>`).join("")}
function esc(x){const n=document.createElement("span");n.textContent=x??"";return n.innerHTML}input.addEventListener("input",render);render();
