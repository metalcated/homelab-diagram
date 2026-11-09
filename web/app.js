'use strict';
const $ = (id) => document.getElementById(id);
const escapeHTML = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const token = document.querySelector('meta[name="labmap-token"]').content;
let state = {sites:[],hosts:[],links:[],jobs:[],runs:[]}, selected = null, currentPlan = null, zoom = 1, panX = 0, panY = 0;
let refreshPending = null, collectionReview = 0;
let activeTab='devices', outputJob=null, outputCursor=0, outputGeneration=0, outputBusy=false, outputFinished=false;
let outputAbort=null;

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
function currentHosts() {
  const parts=new Set(['CPU','Memory module','Storage controller','Disk']);
  return (state.assets||state.hosts).filter(h=>h.site===selected&&($('show-components').checked||!parts.has(h.auto_role||h.role)));
}
function assetKey(h){return h.id||h.address;}
function currentLinks(){return (state.asset_links||state.links).filter(l=>l.site===selected);}
function labelFor(id){const host=(state.assets||state.hosts).find(h=>assetKey(h)===id);return host?hostName(host):id;}
function hostName(host) { return host.name || host.hostname || host.address || host.mac || 'Unidentified asset'; }
function deviceModel(host) { return host.manual_model || host.model || host.vendor || 'Model unknown'; }
function clip(text, limit=29) { return text.length > limit ? text.slice(0,limit-1)+'…' : text; }
function formData(form) { return Object.fromEntries(new FormData(form).entries()); }

async function refresh(force=false) {
  if(refreshPending){await refreshPending;if(!force)return;}
  refreshPending=(async()=>{
    try {
      state = await api('state');
      if (!state.sites.some(s => s.id === selected)) selected = state.sites[0]?.id || null;
      render();
    } catch(error) { notice(error.message, true); }
    finally { refreshPending = null; }
  })();
  return refreshPending;
}
function render() {
  $('demo-badge').classList.toggle('hidden', !(state.demo||state.simulated));
  $('sites').innerHTML = state.sites.map(s => `<button class="site-button ${s.id === selected ? 'active' : ''}" data-site="${escapeHTML(s.id)}">${escapeHTML(s.label)}<span>${(state.assets||state.hosts).filter(h => h.site===s.id).length} assets</span></button>`).join('');
  $('sites').querySelectorAll('[data-site]').forEach(b => b.addEventListener('click', () => { selected=b.dataset.site; zoom=1; panX=0; panY=0; render(); }));
  const site = currentSite();
  $('empty').classList.toggle('hidden', !!site);
  $('workspace').classList.toggle('hidden', !site);
  for (const id of ['edit-site','import-data','scan','manage-collectors','collect-inventory']) $(id).classList.toggle('hidden', !site);
  $('breadcrumb').textContent = site ? 'Your workspace / ' + site.label : 'Your workspace';
  $('site-title').textContent = site ? site.label : 'Map your lab, one observation at a time.';
  $('site-subtitle').textContent = site ? site.targets.join(' / ') : 'Add a site and the networks you want to discover.';
  if (!site) return;
  const running = state.jobs.some(j => j.status === 'running');
  $('collect-inventory').disabled=running||!(state.collectors||[]).some(c=>c.site===selected&&c.enabled);
  $('scan').disabled = running || !state.nmap_available;
  $('scan').textContent = running ? 'Discovery running…' : 'Review scan';
  $('scan').title = state.nmap_available ? '' : 'Nmap is unavailable. Import existing results or install Nmap separately.';
  $('add-link').disabled = currentHosts().length < 2;
  $('counts').textContent = `${currentHosts().length} assets / ${currentLinks().length} relationships`;
  renderCanvas(); renderTables();
  renderOutputJobs();
}
function renderCanvas() {
  const hosts = currentHosts(), links = currentLinks();
  const mobile = window.matchMedia('(max-width:720px)').matches;
  const aspect = $('canvas').clientWidth / Math.max(1, $('canvas').clientHeight);
  const columns = Math.max(mobile ? 1 : 3, Math.round(Math.sqrt(hosts.length * 185 * aspect / 370)));
  const width = Math.max(mobile ? 420 : 1170, columns * 370 + 60);
  const positions = new Map(hosts.map((h,i) => [assetKey(h),{x:60+(i%columns)*370,y:55+Math.floor(i/columns)*185}]));
  const height = Math.max(mobile ? 450 : 400, Math.ceil(hosts.length/columns)*185+75);
  const wires = links.map(l => {
    const a=positions.get(l.src), b=positions.get(l.dst); if(!a || !b) return '';
    const physical=l.kind==='physical' && l.source==='manual', neighbor=['neighbor','learned'].includes(l.kind);
    const color=physical?'#78c4b1':neighbor?'#e7b45c':'#ada1df';
    const startX=a.x+300, endX=b.x, mid=(startX+endX)/2;
    return `<path d="M${startX},${a.y+62} C${mid+60},${a.y+62} ${mid-60},${b.y+62} ${endX},${b.y+62}" fill="none" stroke="${color}" stroke-width="${physical?3:2}" ${physical?'':'stroke-dasharray="6 5"'}><title>${escapeHTML(`${l.kind}: ${labelFor(l.src)} ${l.src_port} to ${labelFor(l.dst)} ${l.dst_port}; ${l.source}; ${l.label}`)}</title></path>`;
  }).join('');
  const cards=hosts.map((h,i) => {const p=positions.get(assetKey(h));return `<g class="node" tabindex="0" role="button" aria-label="Edit ${escapeHTML(hostName(h))}" data-device-index="${i}" transform="translate(${p.x},${p.y})"><title>${escapeHTML(hostName(h)+' / '+deviceModel(h))}</title><rect class="node-body" width="300" height="125" rx="8" fill="#1b3041" stroke="#48667d"/><path d="M1 24H299" stroke="#324b60"/><circle cx="16" cy="12" r="3" fill="#78c4b1"/><text x="28" y="16" class="node-detail">${escapeHTML(h.source==='simulated'?'Simulated observation':h.source+' observation')}</text><text x="16" y="51" class="node-title">${escapeHTML(clip(hostName(h)))}</text><text x="16" y="76" class="node-address">${escapeHTML(h.address||"No IP reported")}</text><text x="16" y="99" class="node-detail">${escapeHTML(clip(h.role || deviceModel(h)))}</text><text x="16" y="116" class="node-detail">${escapeHTML(h.role ? clip(deviceModel(h)) : 'Role unverified')}</text></g>`;}).join('');
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
  const links=currentLinks();
  $('connections-panel').innerHTML=links.length?`<table><thead><tr><th>From</th><th>To</th><th>Relationship</th><th>Evidence</th><th>Last recorded (UTC)</th></tr></thead><tbody>${links.map(l=>`<tr><td>${escapeHTML(labelFor(l.src))}<small>${escapeHTML(l.src_port)}</small></td><td>${escapeHTML(labelFor(l.dst))}<small>${escapeHTML(l.dst_port)}</small></td><td>${escapeHTML(l.kind)}<small>${escapeHTML(l.label)}</small></td><td>${escapeHTML(l.source==='manual'?'User confirmed':l.source+' report')}</td><td>${escapeHTML(l.observed.slice(0,16).replace('T',' '))}</td></tr>`).join('')}</tbody></table>`:'<p class="empty-table">No connection evidence yet. Import RouterOS neighbors or add a connection you have verified.</p>';
  const jobs=state.jobs.filter(j=>j.site===selected),runs=state.runs.filter(r=>r.site===selected);
  $('history-panel').innerHTML=jobs.length||runs.length?`<table><thead><tr><th>When (UTC)</th><th>Source</th><th>Result</th></tr></thead><tbody>${jobs.map(j=>`<tr><td>${escapeHTML(j.started.slice(0,16).replace('T',' '))}</td><td>Discovery job</td><td>${escapeHTML(j.status)}<small>${escapeHTML(j.message)}</small>${j.output_available?`<button class="secondary" data-output-job="${escapeHTML(j.id)}">View output</button>`:''}</td></tr>`).join('')}${runs.map(r=>`<tr><td>${escapeHTML(r.observed.slice(0,16).replace('T',' '))}</td><td>${escapeHTML(r.source)}</td><td>${r.hosts} observations imported</td></tr>`).join('')}</tbody></table>`:'<p class="empty-table">Collections, scans and imports will appear here.</p>';
  $('history-panel').querySelectorAll('[data-output-job]').forEach(button=>button.addEventListener('click',()=>{
    resetOutput(button.dataset.outputJob);renderOutputJobs();selectTab('output');$('output-panel').scrollIntoView({block:'start'});
  }));
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
  form.elements.asset_id.value=host.id||'';form.elements.model.value=host.manual_model||'';$('asset-details').textContent=JSON.stringify({addresses:host.addresses||[host.address],macs:host.macs||[host.mac],serial:host.serial||'',review:host.review||'',details:host.details||{}},null,2);$('device-address').textContent=host.address;openDialog('device-dialog');
}
function busyForm(id, handler) {
  $(id).addEventListener('submit',async event=>{
    event.preventDefault();const form=event.currentTarget,button=form.querySelector('[type="submit"]');button.disabled=true;
    const error=form.querySelector('.form-error');error.textContent='';
    try{await handler(form);form.closest('dialog').close();await refresh(true);}
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
  const request=++collectionReview, site=selected;currentPlan=null;
  try{
    const plan=await api('plan',{site});
    if(request!==collectionReview||selected!==site)return;
    currentPlan=plan;$('collection-choice').classList.add('hidden');
    $('plan-heading').textContent='Review discovery scan';$('start-scan').textContent='Start discovery';
    $('scan-explanation').textContent='Host discovery only. DNS lookup, service scanning, OS detection and scripts are disabled. Unprivileged TCP probes can miss filtered devices.';
    $('plan-summary').textContent=`${currentSite().label}: ${currentPlan.addresses.toLocaleString()} addresses in the following scope.`;
    $('plan-targets').textContent=currentPlan.targets.join('\n');$('plan-command').textContent=currentPlan.commands.map(c=>c.join(' ')).join('\n');
    $('start-scan').disabled=false;openDialog('scan-dialog');
  }catch(e){if(request===collectionReview)notice(e.message,true);}
});
$('start-scan').addEventListener('click',async()=>{
  if(!currentPlan)return;
  $('start-scan').disabled=true;$('collection-select').disabled=true;
  try{
    const result=await api('scan',{plan_id:currentPlan.id,confirmed:true});$('scan-dialog').close();
    notice('Collection started. Live output shows requests, responses and errors as they happen.');
    await refresh(true);resetOutput(result.job);renderOutputJobs();selectTab('output');$('output-panel').scrollIntoView({block:'start'});
  }
  catch(e){$('scan-dialog').querySelector('.form-error').textContent=e.message;}
  finally{$('start-scan').disabled=!currentPlan;$('collection-select').disabled=false;}
});
$('import-data').addEventListener('click',()=>{$('import-form').reset();$('observer-field').classList.add('hidden');openDialog('import-dialog');});
$('import-form').elements.format.addEventListener('change',e=>$('observer-field').classList.toggle('hidden',e.target.value!=='routeros'));
busyForm('import-form',async form=>{
  const file=form.elements.file.files[0], pasted=form.elements.contents.value.trim();if(!file&&!pasted)throw new Error('Choose a result file or paste its contents.');if(file&&pasted)throw new Error('Choose a file or pasted data, not both.');if(file&&file.size>3*1024*1024)throw new Error('Choose a result file smaller than 3 MiB.');
  const result=await api('import',{site:selected,format:form.elements.format.value,observer:form.elements.observer.value,contents:file?await file.text():pasted});notice(`Imported ${result.hosts} observed addresses. Your corrections were preserved.`);
});
$('add-link').addEventListener('click',()=>{const form=$('link-form');form.reset();const options=currentHosts().map(h=>`<option value="${escapeHTML(assetKey(h))}">${escapeHTML(hostName(h)+' ('+h.address+')')}</option>`).join('');form.elements.src.innerHTML=options;form.elements.dst.innerHTML=options;form.elements.dst.selectedIndex=1;openDialog('link-dialog');});
busyForm('link-form',async form=>{await api('link',{...formData(form),site:selected});notice('Confirmed connection saved.');});
$('search').addEventListener('input',renderTables);$('show-components').addEventListener('change',render);
const tabs=['devices','connections','history','output'];
function selectTab(name){activeTab=name;for(const tab of tabs){const active=tab===name;$(tab+'-tab').setAttribute('aria-selected',String(active));$(tab+'-tab').tabIndex=active?0:-1;$(tab+'-panel').classList.toggle('hidden',!active);}$('search').closest('label').classList.toggle('hidden',name==='output');if(name==='output')refreshOutput();}
for(const [index,name] of tabs.entries()){$(name+'-tab').addEventListener('click',()=>selectTab(name));$(name+'-tab').addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const next=e.key==='Home'?0:e.key==='End'?tabs.length-1:(index+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length;selectTab(tabs[next]);$(tabs[next]+'-tab').focus();});}
$('zoom-in').addEventListener('click',()=>{zoom=Math.min(8,zoom*1.25);renderCanvas();});$('zoom-out').addEventListener('click',()=>{zoom=Math.max(.5,zoom/1.25);renderCanvas();});$('zoom-reset').addEventListener('click',()=>{zoom=1;panX=0;panY=0;renderCanvas();});
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

function resetOutput(job){
  outputJob=job;outputCursor=0;outputGeneration++;outputFinished=false;
  outputAbort?.abort();
  $('output-events').replaceChildren();
  $('output-status').textContent=job?'Loading scan output…':'Start a scan to see its requests and responses here.';
}
function renderOutputJobs(){
  const jobs=state.jobs.filter(j=>j.site===selected);
  if(!jobs.some(j=>j.id===outputJob))resetOutput(jobs[0]?.id||null);
  const options=jobs.map(j=>`<option value="${escapeHTML(j.id)}">${escapeHTML(j.started.slice(0,19).replace('T',' '))} UTC / ${escapeHTML(j.status)}</option>`).join('');
  if($('output-job').innerHTML!==options)$('output-job').innerHTML=options;
  $('output-job').value=outputJob||'';$('output-job').disabled=!jobs.length;
  if(activeTab==='output')refreshOutput();
}
async function refreshOutput(){
  if(outputBusy||!outputJob||activeTab!=='output'||outputFinished)return;
  outputBusy=true;
  const generation=outputGeneration,job=outputJob,site=selected;
  try{
    for(let page=0;page<5;page++){
      const query=new URLSearchParams({site,job,after:String(outputCursor)});
      const controller=new AbortController();outputAbort=controller;
      const timeout=setTimeout(()=>controller.abort(),10000);
      let response,data;
      try{
        response=await fetch('/api/events?'+query,{cache:'no-store',headers:{'X-Labmap-Token':token},signal:controller.signal});
        data=await response.json();
      }finally{clearTimeout(timeout);}
      if(generation!==outputGeneration||job!==outputJob||site!==selected)return;
      if(response.status===404){outputFinished=true;throw new Error('Restart the local Lab Map app to enable live output.');}
      if(!response.ok)throw new Error(data.error||'Scan output could not be loaded.');
      const stream=$('output-events');
      for(const event of data.events){
        const row=document.createElement('article');row.className='output-event output-'+event.level;
        const heading=`<span class="output-time">${escapeHTML(event.observed.slice(11,23))}</span><span class="output-level">${escapeHTML(event.level)}</span><span class="output-message"><strong>${escapeHTML(event.collector||'Scan')}</strong>${event.target?` <span class="address">${escapeHTML(event.target)}</span>`:''}<span>${escapeHTML(event.message)}</span></span>`;
        let details=event.details;
        if(details){try{details=JSON.stringify(JSON.parse(details),null,2);}catch{/* Truncated previews remain readable text. */}}
        row.innerHTML=details?`<details><summary>${heading}</summary><pre>${escapeHTML(details)}</pre></details>`:`<div class="output-line">${heading}</div>`;
        stream.append(row);
      }
      outputCursor=data.next;
      const status=`${data.job.status} / ${stream.childElementCount.toLocaleString()} events (UTC)`;
      $('output-status').textContent=stream.childElementCount?status:data.job.status==='running'?'Waiting for the first event…':'No detailed output was recorded for this scan.';
      if($('output-follow').checked)stream.scrollTop=stream.scrollHeight;
      outputFinished=data.job.status!=='running'&&!data.has_more;
      if(!data.has_more)break;
    }
  }catch(error){
    if(generation===outputGeneration)$('output-status').textContent=(error.name==='AbortError'?'Connection interrupted.':error.message)+(outputFinished?'':' Retrying…');
  }finally{outputBusy=false;}
}
$('output-job').addEventListener('change',()=>{resetOutput($('output-job').value);refreshOutput();});
$('output-follow').addEventListener('change',()=>{if($('output-follow').checked)$('output-events').scrollTop=$('output-events').scrollHeight;});
setInterval(refreshOutput,1000);

function renderSources(){
  const sources=(state.collectors||[]).filter(c=>c.site===selected);
  $('source-list').innerHTML=sources.length?sources.map(c=>`<div class="source-card"><div class="source-title"><strong>${escapeHTML(c.label)}</strong><button class="secondary" data-source-id="${escapeHTML(c.id)}">Edit</button></div><p>${escapeHTML(state.collector_catalog?.[c.kind]?.transport||c.kind)} / ${escapeHTML(c.enabled?'Enabled':'Disabled')}</p><p class="muted">${escapeHTML(c.config.endpoint||'Discover agents across the saved site scope')}</p><p class="muted">${escapeHTML(c.credential_status)}</p>${c.last_result?`<p>${escapeHTML(c.last_result)}</p>`:''}</div>`).join(''):'<p class="empty-table">Add a router, hypervisor, storage system, iDRAC, or a shared SNMP profile. The collector will identify its assets automatically.</p>';
  $('source-list').querySelectorAll('[data-source-id]').forEach(button=>button.addEventListener('click',()=>editSource(sources.find(c=>c.id===button.dataset.sourceId))));
}
function sourceFields(){
  const form=$('source-form'),kind=form.elements.kind.value,snmp=['snmp','apc','cyberpower'].includes(kind),v3=form.elements.snmp_version.value==='3';
  $('snmp-fields').classList.toggle('hidden',!snmp);$('api-credential-fields').classList.toggle('hidden',snmp);
  $('v3-fields').classList.toggle('hidden',!v3);$('community-field').classList.toggle('hidden',v3);
  $('username-field').classList.toggle('hidden',snmp&&!v3);
  $('username-label').textContent=snmp?'SNMPv3 security name':kind==='proxmox'?'Proxmox user@realm!tokenid':kind==='truenas'?'TrueNAS API-key username':'Username';
  $('endpoint-label').textContent=snmp?'Management IP (blank for a shared SNMP discovery profile)':'Management URL';
  form.elements.endpoint.placeholder=snmp?'10.20.0.1, or leave blank for discovery':'https://device.example'+(kind==='proxmox'?':8006':'');
  $('endpoint-help').textContent=snmp?'An auto-detect profile can discover all responding SNMP agents in the saved scope with one shared credential.':'Endpoint resolution is restricted to the saved site scope. TLS verification or an explicit certificate pin is required.';
  form.elements.save_keychain.disabled=!state.keychain_available;
}
function editSource(source=null){
  $('sources-dialog').close();const form=$('source-form');form.reset();
  form.elements.id.value=source?.id||'';form.elements.kind.value=source?.kind||'routeros';form.elements.label.value=source?.label||'';
  for(const key of ['endpoint','username','fingerprint','snmp_version','security_level','auth_protocol','privacy_protocol','snmp_port'])if(source?.config?.[key]!==undefined)form.elements[key].value=source.config[key];
  form.elements.enabled.checked=source?.enabled??true;form.elements.save_keychain.checked=source?.secret_mode==='keychain';
  $('source-title').textContent=source?'Edit collector':'Add collector';sourceFields();openDialog('source-dialog');
}
$('manage-collectors').addEventListener('click',()=>{renderSources();openDialog('sources-dialog');});
$('add-source').addEventListener('click',()=>editSource());
for(const name of ['kind','snmp_version','security_level'])$('source-form').elements[name].addEventListener('change',sourceFields);
busyForm('source-form',async form=>{
  const config={},credentials={};
  for(const key of ['endpoint','username','fingerprint','snmp_version','security_level','auth_protocol','privacy_protocol','snmp_port'])config[key]=form.elements[key].value;
  for(const key of ['password','community','auth_password','privacy_password'])credentials[key]=form.elements[key].value;
  await api('collectors/save',{id:form.elements.id.value||undefined,site:selected,kind:form.elements.kind.value,label:form.elements.label.value,enabled:form.elements.enabled.checked,save_keychain:form.elements.save_keychain.checked,config,credentials});
  for(const key of ['password','community','auth_password','privacy_password'])form.elements[key].value='';
  notice('Collector saved. Review collection to discover and enrich its assets.');
});
$('scan-dialog').addEventListener('close',()=>{collectionReview++;currentPlan=null;});
async function updateCollectionPlan(){
  const request=++collectionReview, site=selected, choice=$('collection-select').value;
  currentPlan=null;$('start-scan').disabled=true;
  $('scan-dialog').querySelector('.form-error').textContent='';
  $('plan-summary').textContent='Preparing collection review…';
  $('plan-targets').textContent='';$('plan-command').textContent='';
  try{
    const plan=await api('collectors/plan',{site,connections:choice?[choice]:null});
    if(request!==collectionReview||!$('scan-dialog').open||selected!==site)return;
    currentPlan=plan;
    const count=currentPlan.connections.length, targets=currentPlan.addresses;
    $('plan-summary').textContent=`${currentSite().label}: ${targets.toLocaleString()} management ${targets===1?'target':'targets'} across ${count} ${count===1?'collector':'collectors'}.`;
    $('plan-targets').textContent=currentPlan.summaries.join('\n')+'\n\nSite scope:\n'+currentPlan.targets.join('\n');
    $('plan-command').textContent=currentPlan.connections.map(c=>`${(state.collectors||[]).find(s=>s.id===c.id)?.label||c.id}\n${c.addresses.join(', ')}`).join('\n\n');
    $('start-scan').disabled=false;
  }catch(error){
    if(request!==collectionReview||!$('scan-dialog').open||selected!==site)return;
    $('plan-summary').textContent='Collection could not be prepared. Choose another collector or correct its connection.';
    $('scan-dialog').querySelector('.form-error').textContent=error.message;
  }
}
$('collection-select').addEventListener('change',updateCollectionPlan);
$('collect-inventory').addEventListener('click',()=>{
  const sources=(state.collectors||[]).filter(c=>c.site===selected&&c.enabled);
  $('collection-select').innerHTML=`<option value="">All enabled collectors (${sources.length})</option>`+sources.map(c=>`<option value="${escapeHTML(c.id)}">${escapeHTML(c.label)}</option>`).join('');
  $('collection-choice').classList.remove('hidden');
  $('plan-heading').textContent='Review direct collection';$('start-scan').textContent='Start collection';
  $('scan-explanation').textContent='Read-only management queries. APIs and SNMP identify devices, hardware and reported relationships automatically. No service is enabled or reconfigured, and power connections are not guessed.';
  openDialog('scan-dialog');updateCollectionPlan();
});
