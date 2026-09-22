const directions = [
  ['Launch', 'An open upward arrow. Direct, confident and immediately legible.', ['#252A29','#F8F7F5','#C5372C','#647B72','#EFC55B']],
  ['Tether', 'Two linked endpoints. A persistent connection without a cloud-first bias.', ['#182D2D','#F1F8F6','#007D79','#507AA1','#EDAE69']],
  ['Portal', 'An open gateway with a deliberate entry point. Access with a boundary.', ['#212933','#F3F6FC','#275FE8','#558B80','#F1B95B']],
  ['Switch', 'Two routed lanes. A grounded, systems-oriented identity.', ['#202B25','#F3F7F2','#247447','#728DAD','#DFAA50']],
  ['Signal', 'Ascending fins. A more expressive, energetic developer brand.', ['#2E252B','#FBF5F7','#BC315C','#587D86','#D8B75A']],
  ['Aperture', 'A defined perimeter with an active centre. Precise and restrained.', ['#24292E','#F4F5F5','#393E43','#758FA0','#F1C63B']],
  ['Relay', 'Opposing brackets. Two sides of the same permissioned connection.', ['#202B31','#F0F8FA','#007EAB','#577569','#EDB46A']],
  ['Junction', 'Three converging paths. Multiple machines, one connection layer.', ['#2D2724','#FAF6F3','#B54C2F','#4C7E83','#D8BD61']],
  ['Lift', 'A U that becomes an arrow. The clearest literal uplink direction.', ['#292735','#F7F6FA','#5954B3','#4F897C','#E7BB5C']],
  ['Bridge', 'A span between two endpoints. Approachable infrastructure.', ['#1E2E28','#F1F8F4','#087853','#597BA8','#E7B764']],
  ['Socket', 'An open U with an active node. Local capabilities, intentionally exposed.', ['#2B2528','#FAF5F4','#BD323B','#567D80','#DAB954']],
  ['Beacon', 'A directional marker. Strong silhouette, but a familiar visual category.', ['#262B36','#F4F6FB','#344EC7','#659482','#E7A950']],
  ['Thread', 'One continuous connection. Softer, more human and less industrial.', ['#30252E','#FAF5F8','#8D396A','#4D898B','#DEB564']],
  ['Linkstep', 'A compact stepped chain. Progress expressed through connected blocks.', ['#2A2E24','#F6F8F1','#63752C','#657FA5','#D68C59']],
  ['Airlock', 'Two offset gates and one permissioned passage. Architectural and controlled.', ['#23292B','#F4F6F3','#454E48','#819770','#BEDD48']],
  ['Waypoint', 'A route and its destination. Clear addressing across a boundary.', ['#202C33','#F2F7F9','#176B8B','#66917B','#E6AA59']],
  ['Duplex', 'Two directions, one link. Explicit bidirectional transport.', ['#302923','#FBF7F2','#C85D1D','#557F8F','#B9C75E']],
  ['Anchorpoint', 'A grounded U with a connected node. Stable and quietly distinctive.', ['#24312B','#F3F7F3','#266458','#6E84A5','#D9B35A']],
  ['Connective', 'A joined A/U monogram. Product initials with a continuous path.', ['#222C36','#F3F7FB','#1764AD','#608977','#E5B253']],
  ['Vector', 'An ascending cut ribbon. Minimal, directional and adaptable.', ['#202323','#F5F7F6','#343C39','#63857A','#65D7A5']],
];
let saved;
try { saved = new Set(JSON.parse(localStorage.getItem('agentuplink-shortlist') || '[]')); } catch { saved = new Set(); }
const roles = ['Ink', 'Surface', 'Primary', 'Secondary', 'Signal'];
const container = document.querySelector('#options');
directions.forEach(([name, description, colors], index) => {
  const number = String(index + 1).padStart(2, '0');
  const article = document.createElement('article');
  article.className = 'option';
  article.id = `direction-${number}`;
  article.innerHTML = `<div class="logo" role="img" aria-label="${name} Agent Uplink logo concept" style="background-position:${(index % 5) * 25}% ${Math.floor(index / 5) * 100 / 3}%"></div><div><span class="number">${number} / AGENT UPLINK</span><h3>${name}</h3><p>${description}</p><label class="pick"><input type="checkbox" aria-label="Shortlist ${number} ${name}" ${saved.has(number) ? 'checked' : ''}> Shortlist</label></div><div class="system"><div class="palette">${colors.map((color, i) => `<div><div class="swatch" style="background:${color}"></div><span class="role">${roles[i]}</span><span class="hex">${color}</span></div>`).join('')}</div><div class="mini" style="--ink:${colors[0]};--surface:${colors[1]};--primary:${colors[2]}"><strong>Agent Uplink</strong><span>Connected</span></div></div>`;
  article.querySelector('input').addEventListener('change', event => {
    if (event.target.checked) saved.add(number); else saved.delete(number);
    try { localStorage.setItem('agentuplink-shortlist', JSON.stringify([...saved])); } catch {}
    update();
  });
  container.append(article);
});
function update() {
  const filtered = document.querySelector('#filter').checked;
  let shown = 0;
  [...container.children].forEach((article, index) => {
    article.hidden = filtered && !saved.has(String(index + 1).padStart(2, '0'));
    if (!article.hidden) shown++;
  });
  document.querySelector('#count').textContent = `${shown} directions / ${saved.size} shortlisted`;
  document.querySelector('#empty').hidden = shown !== 0;
}
document.querySelector('#filter').addEventListener('change', update);
update();
