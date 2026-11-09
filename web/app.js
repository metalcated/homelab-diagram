'use strict';
const $ = (id) => document.getElementById(id);
const escapeHTML = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const token = document.querySelector('meta[name="labmap-token"]').content;
let state = {sites:[],hosts:[],links:[],jobs:[],runs:[]}, selected = null, currentPlan = null, zoom = 1, panX = 0, panY = 0;
let refreshPending = false;

async function api(path, body) {
  const response = await fetch('/api/' + path, body === undefined ? {cache:'no-store'} : {
    method:'POST',headers:{'Content-Type':'application/json','X-Labmap-Token':token},body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The request could not be completed.');
  return data;
}
function notice(message, error=false) {
  $('notice').textContent = message;
  $('notice').classList.remove('hidden');
  $('notice').classList.toggle('error', error);
}
function openDialog(id) {
  const dialog = $(id);
  dialog.querySelector('.form-error').textContent = '';
  dialog.showModal();
}
function currentSite() { return state.sites.find(s => s.id === selected); }
function currentHosts() { return state.hosts.filter(h => h.site === selected); }
function hostName(host) { return host.name || host.hostname || host.address; }
function deviceModel(host) { return host.manual_model || host.model || host.vendor || 'Model unknown'; }
function clip(text, limit=29) { return text.length > limit ? text.slice(0,limit-1)+'…' : text; }
function formData(form) { return Object.fromEntries(new FormData(form).entries()); }

async function refresh() {
  if (refreshPending) return;
  refreshPending = true;
  try {
    state = await api('state');
    if (!state.sites.some(s => s.id === selected)) selected = state.sites[0]?.id || null;
    render();
  } catch(error) { notice(error.message, true); }
  finally { refreshPending = false; }
}
function render() {
  $('demo-badge').classList.toggle('hidden', !state.demo);
  $('sites').innerHTML = state.sites.map(s => `<button class="site-button ${s.id === selected ? 'active' : ''}" data-site="${escapeHTML(s.id)}">${escapeHTML(s.label)}<span>${state.hosts.filter(h => h.site===s.id).length} observed addresses</span></button>`).join('');
  $('sites').querySelectorAll('[data-site]').forEach(b => b.addEventListener('click', () => { selected=b.dataset.site; zoom=1; panX=0; panY=0; render(); }));
  const site = currentSite();
  $('empty').classList.toggle('hidden', !!site);
  $('workspace').classList.toggle('hidden', !site);
  for (const id of ['edit-site','import-data','scan']) $(id).classList.toggle('hidden', !site);
  $('breadcrumb').textContent = site ? 'Your workspace / ' + site.label : 'Your workspace';
  $('site-title').textContent = site ? site.label : 'Map your lab, one observation at a time.';
  $('site-subtitle').textContent = site ? site.targets.join(' / ') : 'Add a site and the networks you want to discover.';
  if (!site) return;
  const running = state.jobs.some(j => j.status === 'running');
  $('scan').disabled = running || !state.nmap_available;
  $('scan').textContent = running ? 'Discovery running…' : 'Review scan';
  $('scan').title = state.nmap_available ? '' : 'Nmap is unavailable. Import existing results or install Nmap separately.';
  $('add-link').disabled = currentHosts().length < 2;
  $('counts').textContent = `${currentHosts().length} addresses / ${state.links.filter(l => l.site===selected).length} connections`;
  renderCanvas(); renderTables();
}
function renderCanvas() {
  const hosts = currentHosts(), links = state.links.filter(l => l.site===selected);
  const mobile = window.matchMedia('(max-width:720px)').matches, columns = mobile ? 1 : 3;
  const width = mobile ? 420 : 1170;
  const positions = new Map(hosts.map((h,i) => [h.address,{x:60+(i%columns)*370,y:55+Math.floor(i/columns)*185}]));
  const height = mobile ? 450 : Math.max(400, Math.ceil(hosts.length/columns)*185+75);
  const wires = links.map(l => {
    const a=positions.get(l.src), b=positions.get(l.dst); if(!a || !b) return '';
    const physical=l.kind==='physical' && l.source==='manual', neighbor=l.kind==='neighbor';
    const color=physical?'#78c4b1':neighbor?'#e7b45c':'#ada1df';
    const startX=a.x+300, endX=b.x, mid=(startX+endX)/2;
    return `<path d="M${startX},${a.y+62} C${mid+60},${a.y+62} ${mid-60},${b.y+62} ${endX},${b.y+62}" fill="none" stroke="${color}" stroke-width="${physical?3:2}" ${physical?'':'stroke-dasharray="6 5"'}><title>${escapeHTML(`${l.kind}: ${l.src} ${l.src_port} to ${l.dst} ${l.dst_port}; ${l.source}; ${l.label}`)}</title></path>`;
  }).join('');
  const cards=hosts.map((h,i) => {const p=positions.get(h.address);return `<g class="node" tabindex="0" role="button" aria-label="Edit ${escapeHTML(hostName(h))}" data-device-index="${i}" transform="translate(${p.x},${p.y})"><title>${escapeHTML(hostName(h)+' / '+deviceModel(h))}</title><rect class="node-body" width="300" height="125" rx="8" fill="#1b3041" stroke="#48667d"/><path d="M1 24H299" stroke="#324b60"/><circle cx="16" cy="12" r="3" fill="#78c4b1"/><text x="28" y="16" class="node-detail">${escapeHTML(h.source==='simulated'?'Simulated observation':h.source+' observation')}</text><text x="16" y="51" class="node-title">${escapeHTML(clip(hostName(h)))}</text><text x="16" y="76" class="node-address">${escapeHTML(h.address)}</text><text x="16" y="99" class="node-detail">${escapeHTML(clip(h.role || deviceModel(h)))}</text><text x="16" y="116" class="node-detail">${escapeHTML(h.role ? clip(deviceModel(h)) : 'Role unverified')}</text></g>`;}).join('');
  $('canvas').innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${panX} ${panY} ${width/zoom} ${height/zoom}" aria-label="${escapeHTML(currentSite().label)} device map">${wires}${cards}${hosts.length?'':'<text x="65" y="110" class="node-title">No observations yet.</text><text x="65" y="142" class="node-detail">Review a scan or import an existing discovery result to populate this canvas.</text>'}</svg>`;
  $('canvas').querySelectorAll('[data-device-index]').forEach(node => {
    const open=() => editDevice(hosts[Number(node.dataset.deviceIndex)]);
    node.addEventListener('click',open);node.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open();}});
  });
}
function renderTables() {
  const query=$('search').value.toLowerCase();
  const hosts=currentHosts().filter(h=>[hostName(h),h.address,deviceModel(h),h.role,h.notes].some(v=>String(v||'').toLowerCase().includes(query)));
  $('devices-panel').innerHTML=hosts.length?`<table><thead><tr><th>Device</th><th>Address</th><th>Role / hardware</th><th>Last observed (UTC)</th><th></th></tr></thead><tbody>${hosts.map((h,i)=>`<tr><td>${escapeHTML(hostName(h))}<small>${escapeHTML(h.source)}</small></td><td class="address">${escapeHTML(h.address)}<small>${escapeHTML(h.mac||'MAC not reported')}</small></td><td>${escapeHTML(h.role||'Unverified')}<small>${escapeHTML(deviceModel(h))}</small></td><td>${escapeHTML(h.last_seen.slice(0,16).replace('T',' '))}</td><td><button class="secondary" data-edit-index="${i}">Edit</button></td></tr>`).join('')}</tbody></table>`:'<p class="empty-table">No matching devices. Import results or review a discovery scan.</p>';
  $('devices-panel').querySelectorAll('[data-edit-index]').forEach(b=>b.addEventListener('click',()=>editDevice(hosts[Number(b.dataset.editIndex)])));
  const links=state.links.filter(l=>l.site===selected);
  $('connections-panel').innerHTML=links.length?`<table><thead><tr><th>From</th><th>To</th><th>Relationship</th><th>Evidence</th><th>Last recorded (UTC)</th></tr></thead><tbody>${links.map(l=>`<tr><td>${escapeHTML(l.src)}<small>${escapeHTML(l.src_port)}</small></td><td>${escapeHTML(l.dst)}<small>${escapeHTML(l.dst_port)}</small></td><td>${escapeHTML(l.kind)}<small>${escapeHTML(l.label)}</small></td><td>${escapeHTML(l.source==='manual'?'User confirmed':'RouterOS report — review')}</td><td>${escapeHTML(l.observed.slice(0,16).replace('T',' '))}</td></tr>`).join('')}</tbody></table>`:'<p class="empty-table">No connection evidence yet. Import RouterOS neighbors or add a connection you have verified.</p>';
  const jobs=state.jobs.filter(j=>j.site===selected),runs=state.runs.filter(r=>r.site===selected);
  $('history-panel').innerHTML=jobs.length||runs.length?`<table><thead><tr><th>When (UTC)</th><th>Source</th><th>Result</th></tr></thead><tbody>${jobs.map(j=>`<tr><td>${escapeHTML(j.started.slice(0,16).replace('T',' '))}</td><td>Discovery scan</td><td>${escapeHTML(j.status)}<small>${escapeHTML(j.message)}</small></td></tr>`).join('')}${runs.map(r=>`<tr><td>${escapeHTML(r.observed.slice(0,16).replace('T',' '))}</td><td>${escapeHTML(r.source)}</td><td>${r.hosts} observed addresses imported</td></tr>`).join('')}</tbody></table>`:'<p class="empty-table">Scans and imports will appear here.</p>';
}
function editSite(site=null) {
  const form=$('site-form');form.reset();
  form.elements.label.value=site?.label||'';form.elements.id.value=site?.id||'';form.elements.id.readOnly=!!site;
  form.elements.targets.value=site?.targets.join('\n')||'';form.elements.allow_public.checked=!!site?.allow_public;
  $('site-dialog-title').textContent=site?'Edit site scope':'Add a site';openDialog('site-dialog');
}
function editDevice(host) {
  const form=$('device-form');form.reset();
  for(const key of ['site','address','name','role','notes'])form.elements[key].value=host[key]||'';
  form.elements.model.value=host.manual_model||'';$('device-address').textContent=host.address;openDialog('device-dialog');
}
function busyForm(id, handler) {
  $(id).addEventListener('submit',async event=>{
    event.preventDefault();const form=event.currentTarget,button=form.querySelector('[type="submit"]');button.disabled=true;
    const error=form.querySelector('.form-error');error.textContent='';
    try{await handler(form);form.closest('dialog').close();await refresh();}
    catch(e){error.textContent=e.message;}finally{button.disabled=false;}
  });
}
document.querySelectorAll('.close-dialog').forEach(button=>button.addEventListener('click',()=>button.closest('dialog').close()));
$('add-site').addEventListener('click',()=>editSite());$('first-site').addEventListener('click',()=>editSite());
$('edit-site').addEventListener('click',()=>editSite(currentSite()));
$('site-form').elements.label.addEventListener('input',event=>{const id=$('site-form').elements.id;if(!id.readOnly)id.value=event.target.value.toLowerCase().replace(/[^a-z0-9_-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,40);});
busyForm('site-form',async form=>{const p=formData(form);p.targets=p.targets.split(/[\s,]+/).filter(Boolean);p.allow_public=form.elements.allow_public.checked;await api('sites',p);selected=p.id;notice('Site saved. Review its scope before scanning.');});
busyForm('device-form',async form=>{await api('annotate',formData(form));notice('Device details saved.');});
$('scan').addEventListener('click',async()=>{
  try{currentPlan=await api('plan',{site:selected});$('plan-summary').textContent=`${currentSite().label}: ${currentPlan.addresses.toLocaleString()} addresses in the following scope.`;$('plan-targets').textContent=currentPlan.targets.join('\n');$('plan-command').textContent=currentPlan.commands.map(c=>c.join(' ')).join('\n');$('start-scan').disabled=false;openDialog('scan-dialog');}
  catch(e){notice(e.message,true);}
});
$('start-scan').addEventListener('click',async()=>{
  $('start-scan').disabled=true;
  try{await api('scan',{plan_id:currentPlan.id,confirmed:true});$('scan-dialog').close();notice('Discovery started. Follow progress in History; no device settings will be changed.');await refresh();}
  catch(e){$('scan-dialog').querySelector('.form-error').textContent=e.message;}
  finally{$('start-scan').disabled=false;}
});
$('import-data').addEventListener('click',()=>{$('import-form').reset();$('observer-field').classList.add('hidden');openDialog('import-dialog');});
$('import-form').elements.format.addEventListener('change',e=>$('observer-field').classList.toggle('hidden',e.target.value!=='routeros'));
busyForm('import-form',async form=>{
  const file=form.elements.file.files[0], pasted=form.elements.contents.value.trim();if(!file&&!pasted)throw new Error('Choose a result file or paste its contents.');if(file&&pasted)throw new Error('Choose a file or pasted data, not both.');if(file&&file.size>3*1024*1024)throw new Error('Choose a result file smaller than 3 MiB.');
  const result=await api('import',{site:selected,format:form.elements.format.value,observer:form.elements.observer.value,contents:file?await file.text():pasted});notice(`Imported ${result.hosts} observed addresses. Your corrections were preserved.`);
});
$('add-link').addEventListener('click',()=>{const form=$('link-form');form.reset();const options=currentHosts().map(h=>`<option value="${escapeHTML(h.address)}">${escapeHTML(hostName(h)+' ('+h.address+')')}</option>`).join('');form.elements.src.innerHTML=options;form.elements.dst.innerHTML=options;form.elements.dst.selectedIndex=1;openDialog('link-dialog');});
busyForm('link-form',async form=>{await api('link',{...formData(form),site:selected});notice('Confirmed connection saved.');});
$('search').addEventListener('input',renderTables);
const tabs=['devices','connections','history'];
function selectTab(name){for(const tab of tabs){const active=tab===name;$(tab+'-tab').setAttribute('aria-selected',String(active));$(tab+'-tab').tabIndex=active?0:-1;$(tab+'-panel').classList.toggle('hidden',!active);}}
for(const [index,name] of tabs.entries()){$(name+'-tab').addEventListener('click',()=>selectTab(name));$(name+'-tab').addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const next=e.key==='Home'?0:e.key==='End'?2:(index+(e.key==='ArrowRight'?1:2))%3;selectTab(tabs[next]);$(tabs[next]+'-tab').focus();});}
$('zoom-in').addEventListener('click',()=>{zoom=Math.min(2,zoom+.2);renderCanvas();});$('zoom-out').addEventListener('click',()=>{zoom=Math.max(.5,zoom-.2);renderCanvas();});$('zoom-reset').addEventListener('click',()=>{zoom=1;panX=0;panY=0;renderCanvas();});
let drag = null;
$('canvas').addEventListener('pointerdown',event=>{
  if(event.target.closest('.node'))return;
  const svg=$('canvas').querySelector('svg');if(!svg)return;
  const box=svg.getBoundingClientRect();
  drag={x:event.clientX,y:event.clientY,px:panX,py:panY,scale:Math.max(svg.viewBox.baseVal.width/box.width,svg.viewBox.baseVal.height/box.height)};
  $('canvas').setPointerCapture(event.pointerId);
});
$('canvas').addEventListener('pointermove',event=>{
  if(!drag)return;
  panX=drag.px-(event.clientX-drag.x)*drag.scale;panY=drag.py-(event.clientY-drag.y)*drag.scale;
  const box=$('canvas').querySelector('svg').viewBox.baseVal;box.x=panX;box.y=panY;
});
for(const name of ['pointerup','pointercancel'])$('canvas').addEventListener(name,()=>{drag=null;});
window.matchMedia('(max-width:720px)').addEventListener('change',()=>{if(currentSite()){zoom=1;panX=0;panY=0;renderCanvas();}});
selectTab('devices');refresh();
setInterval(()=>{if(state.jobs.some(j=>j.status==='running')&&!document.querySelector('dialog[open]'))refresh();},2000);
