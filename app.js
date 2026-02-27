/* ─── NOISE CANVAS ───────────────────────────────────────── */
(function initNoise() {
    var canvas = document.getElementById('noiseCanvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    function drawNoise() {
        var w = canvas.width, h = canvas.height;
        var imageData = ctx.createImageData(w, h);
        var data = imageData.data;
        for (var i = 0; i < data.length; i += 4) {
            var v = Math.random() * 255 | 0;
            data[i] = data[i+1] = data[i+2] = v;
            data[i+3] = 255;
        }
        ctx.putImageData(imageData, 0, 0);
    }

    resize();
    drawNoise();
    window.addEventListener('resize', function() { resize(); drawNoise(); });
})();

/* ─── CHECK METADATA ─────────────────────────────────────── */
var CHECK_META = {
    'SQL Injection':                { severity: 'critical', desc: 'Detects SQL injection patterns in URL parameters that could expose database data.' },
    'XSS':                          { severity: 'critical', desc: 'Identifies Cross-Site Scripting payloads capable of hijacking user sessions.' },
    'HTTPS Check':                  { severity: 'high',     desc: 'Verifies the connection uses HTTPS to ensure data is encrypted in transit.' },
    'Directory Traversal':          { severity: 'high',     desc: 'Checks for path traversal sequences that may expose server file system contents.' },
    'Command Injection':            { severity: 'critical', desc: 'Detects shell command injection patterns that could allow remote code execution.' },
    'Open Redirect':                { severity: 'medium',   desc: 'Flags redirect parameters that attackers use to forward victims to malicious sites.' },
    'URL Shortener':                { severity: 'medium',   desc: 'Identifies known URL shortening services which can obscure the true destination.' },
    'IP Address URL':               { severity: 'high',     desc: 'URLs using raw IP addresses instead of domain names are common in phishing attacks.' },
    'Fake Domain':                  { severity: 'critical', desc: 'Matches known brand-name typosquats used to impersonate legitimate services.' },
    'Phishing Keywords':            { severity: 'critical', desc: 'Detects phishing-specific keywords that trick users into entering credentials.' },
    'Suspicious TLD':               { severity: 'high',     desc: 'Flags top-level domains frequently abused for malware and phishing campaigns.' },
    'Data Theft Patterns':          { severity: 'critical', desc: 'Identifies query parameters that transmit sensitive data like passwords and card numbers.' },
    'Excessive URL Length':         { severity: 'medium',   desc: 'URLs over 150 characters are commonly used to obscure malicious payloads.' },
    'High URL Entropy':             { severity: 'high',     desc: 'High entropy in the hostname suggests algorithmically generated or obfuscated domains.' },
    'Excessive Subdomains':         { severity: 'high',     desc: 'Six or more subdomains are unusual and often indicate domain abuse or evasion.' },
    'Special Characters':           { severity: 'medium',   desc: 'Multiple special characters (@, #, ~) in a URL can be used to trick URL parsers.' },
    'Brand Name in Subdomain':      { severity: 'critical', desc: 'Detects brand names in subdomains used to make malicious domains look legitimate.' },
    'Deep URL Path':                { severity: 'medium',   desc: 'Deeply nested URL paths are sometimes used to hide malicious endpoints.' },
    'Number-Letter Substitution':   { severity: 'critical', desc: 'Detects leet-speak substitutions (0→o, 1→l) to impersonate trusted brands.' },
    '@ Symbol Trick':               { severity: 'high',     desc: 'The @ symbol in URLs causes browsers to treat the preceding text as credentials.' },
    'Excessive Dots in Domain':     { severity: 'high',     desc: 'Five or more dots in a hostname is a strong indicator of subdomain abuse.' },
    'Hex Encoded Characters':       { severity: 'high',     desc: 'Multiple percent-encoded characters in paths are used to bypass security filters.' },
    'Suspicious File Extension':    { severity: 'critical', desc: 'Links to executable files (.exe, .bat, .ps1, etc.) are high-risk downloads.' },
    'Free Hosting Platform':        { severity: 'medium',   desc: 'Free hosting services are widely abused to host phishing pages at no cost.' },
    'Urgency Words':                { severity: 'high',     desc: 'Urgency keywords in URLs are a social engineering tactic to force quick action.' },
    'Email Tracking Abuse':         { severity: 'medium',   desc: 'Email service domains used for tracking clicks can mask the true destination URL.' },
    'Numeric Subdomain':            { severity: 'high',     desc: 'Subdomains consisting of long numeric strings suggest auto-generated infrastructure.' },
    'Auto-Generated Domain':        { severity: 'high',     desc: 'Domains with random-looking alphanumeric names are often created by malware.' },
    'Encoded Hidden URL':           { severity: 'high',     desc: 'Double-encoded URL segments are used to evade signature-based detection systems.' },
    'Click Tracking Path':          { severity: 'medium',   desc: 'Paths used by click-tracking systems can mask the final destination of a link.' },
    'SendGrid Redirect Abuse':      { severity: 'high',     desc: 'Combines email-service domain with click-tracking path — a known phishing vector.' },
    'Nested URL in Parameter':      { severity: 'high',     desc: 'A URL embedded within a query parameter is a classic open-redirect payload.' },
    'Long Query String':            { severity: 'medium',   desc: 'Query strings over 200 characters often carry encoded payloads or redirect targets.' },
    'Multiple Redirects':           { severity: 'high',     desc: 'Multiple redirect parameters in one URL indicate a chained redirect attack.' },
    'Suspicious Redirect Parameter':{ severity: 'high',     desc: 'Redirect parameters with long values are used to send victims to attacker-controlled URLs.' }
};

var DEFAULT_META = { severity: 'info', desc: 'No additional description available for this check.' };

/* ─── HELPERS ────────────────────────────────────────────── */
function wait(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
}

function setProgress(pct, label, done, total) {
    var bar   = document.getElementById('progressBar');
    var pctEl = document.getElementById('progressPct');
    var lbl   = document.getElementById('progressLabel');
    var chk   = document.getElementById('progressChecks');

    bar.style.width    = pct + '%';
    pctEl.textContent  = Math.round(pct) + '%';
    lbl.textContent    = label;
    chk.textContent    = done + ' / ' + total + ' checks completed';
}

function getRiskColor(vulnCount, total) {
    var pct = vulnCount / total;
    if (pct === 0)      return 'var(--success)';
    if (pct <= 0.15)    return 'var(--accent)';
    if (pct <= 0.35)    return 'var(--warn)';
    return 'var(--danger)';
}

function getRiskLabel(vulnCount, total) {
    var pct = vulnCount / total;
    if (pct === 0)      return 'CLEAN';
    if (pct <= 0.10)    return 'LOW RISK';
    if (pct <= 0.25)    return 'MODERATE';
    if (pct <= 0.45)    return 'HIGH RISK';
    return 'CRITICAL';
}

/* ─── MAIN SCAN FUNCTION ─────────────────────────────────── */
async function startScan() {
    var url = document.getElementById('urlInput').value.trim();

    if (!url) {
        flashInput();
        return;
    }

    // Normalize: prepend http:// if no protocol so URL() parsing works in all checks
    if (!/^https?:\/\//i.test(url)) {
        url = 'http://' + url;
        document.getElementById('urlInput').value = url;
    }

    var btn = document.getElementById('scanBtn');
    var progressWrap = document.getElementById('progressWrap');
    var resultsSection = document.getElementById('resultsSection');

    // UI: scanning state
    btn.disabled = true;
    btn.classList.add('scanning');
    btn.querySelector('.btn-text').textContent = 'SCANNING';
    progressWrap.classList.add('active');
    resultsSection.classList.remove('active');
    document.getElementById('resultsBody').innerHTML = '';

    // Run all checks with animated progress
    // We re-run each test individually to animate progress
    var tests = getTestList();
    var results = [];
    var total = tests.length;

    for (let i = 0; i < total; i++) {
        const test = tests[i];
        const pct = ((i + 1) / total) * 100;
        setProgress(pct, 'ANALYZING: ' + test.name.toUpperCase(), i, total);

        await wait(40);

        let isVuln = false;
        try { isVuln = test.fn(url); } catch(e) {}

        const meta = CHECK_META[test.name] || DEFAULT_META;
        results.push({
            name:       test.name,
            vulnerable: isVuln,
            severity:   meta.severity,
            desc:       meta.desc
        });
    }

    setProgress(100, 'SCAN COMPLETE', total, total);
    await wait(300);

    // Compute stats
    var vulnCount = results.filter(function(r) { return r.vulnerable; }).length;
    var safeCount = total - vulnCount;

    renderResults(results, vulnCount, safeCount, total);

    // Reset button
    btn.disabled = false;
    btn.classList.remove('scanning');
    btn.querySelector('.btn-text').textContent = 'INITIATE SCAN';

    setTimeout(function() {
        progressWrap.classList.remove('active');
    }, 1200);
}

/* ─── RENDER ─────────────────────────────────────────────── */
function renderResults(results, vulnCount, safeCount, total) {
    var section = document.getElementById('resultsSection');

    // Stats
    document.getElementById('statVuln').textContent  = vulnCount;
    document.getElementById('statSafe').textContent  = safeCount;
    document.getElementById('statTotal').textContent = total;

    // Risk arc
    var pct   = vulnCount / total;
    var deg   = Math.round(pct * 360);
    var color = getRiskColor(vulnCount, total);
    var label = getRiskLabel(vulnCount, total);

    var arc = document.getElementById('riskArc');
    arc.style.background = 'conic-gradient(' + color + ' 0deg, ' + color + ' ' + deg + 'deg, transparent ' + deg + 'deg)';

    var scoreEl = document.getElementById('riskScore');
    scoreEl.textContent = vulnCount;
    scoreEl.style.color = color;

    document.getElementById('riskLabel').textContent = label;

    // Sort: threats first, then by severity
    var sevOrder = { critical: 0, high: 1, medium: 2, info: 3 };
    results.sort(function(a, b) {
        if (a.vulnerable !== b.vulnerable) return a.vulnerable ? -1 : 1;
        return (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3);
    });

    // Rows
    var body = document.getElementById('resultsBody');
    body.innerHTML = results.map(function(r, idx) {
        var rowClass = r.vulnerable ? 'is-threat' : 'is-safe';
        var statusText = r.vulnerable ? 'THREAT' : 'SAFE';
        var sevClass = 'sev-' + (r.severity || 'info');
        var delay = idx * 25;

        return '<div class="result-row ' + rowClass + '" style="animation-delay:' + delay + 'ms">' +
            '<div class="col-status-val"><span class="status-dot"></span>' + statusText + '</div>' +
            '<div class="col-name-val">' + escapeHtml(r.name) + '</div>' +
            '<div><span class="sev-badge ' + sevClass + '">' + (r.severity || 'info').toUpperCase() + '</span></div>' +
            '<div class="col-desc-val">' + escapeHtml(r.desc) + '</div>' +
        '</div>';
    }).join('');

    section.classList.add('active');

    // Scroll to results
    setTimeout(function() {
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function flashInput() {
    var input = document.getElementById('urlInput');
    input.style.borderColor = 'var(--danger)';
    input.style.boxShadow   = '0 0 0 1px rgba(255,58,58,0.3)';
    setTimeout(function() {
        input.style.borderColor = '';
        input.style.boxShadow   = '';
    }, 600);
    input.focus();
}

/* ─── EXTRACT INDIVIDUAL TESTS FROM scanURL ──────────────── */
// We mirror the test list so we can animate them one-by-one.
// Each entry has .name and .fn matching scanner.js logic.
function getTestList() {
    function getDomain(u) {
        try { return new URL(u).hostname; } catch(e) { return u; }
    }
    function calcEntropy(str) {
        var freq = {};
        for (var i = 0; i < str.length; i++) freq[str[i]] = (freq[str[i]] || 0) + 1;
        var entropy = 0;
        Object.keys(freq).forEach(function(k) {
            var p = freq[k] / str.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        });
        return entropy;
    }

    return [
        { name: 'SQL Injection',                fn: function(u) { return ["'",'"','or 1=1','union select'].some(function(x){return u.toLowerCase().indexOf(x)!==-1;}); } },
        { name: 'XSS',                          fn: function(u) { return ['<script','javascript:','onerror=','onload='].some(function(x){return u.toLowerCase().indexOf(x)!==-1;}); } },
        { name: 'HTTPS Check',                  fn: function(u) { return u.indexOf('https://')!==0; } },
        { name: 'Directory Traversal',          fn: function(u) { return ['../','..\\','%2e%2e'].some(function(x){return u.toLowerCase().indexOf(x)!==-1;}); } },
        { name: 'Command Injection',            fn: function(u) { return ['&&','$(','%7C'].some(function(x){return u.indexOf(x)!==-1;}); } },
        { name: 'Open Redirect',                fn: function(u) { return ['redirect=','next=','return=','dest=','goto='].some(function(x){return u.toLowerCase().indexOf(x)!==-1;}); } },
        { name: 'URL Shortener',                fn: function(u) { return ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.io','tiny.cc','rb.gy','is.gd','buff.ly','cutt.ly'].some(function(x){return u.indexOf(x)!==-1;}); } },
        { name: 'IP Address URL',               fn: function(u) { return /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(u); } },
        { name: 'Fake Domain',                  fn: function(u) { return ['paypa1','paypai','arnazon','amazom','g00gle','googie','faceb00k','facebok','micros0ft','microsft','app1e','netfl1x','lnstagram','twltter','linkedln','whatsaap','discrod'].some(function(f){return u.toLowerCase().indexOf(f)!==-1;}); } },
        { name: 'Phishing Keywords',            fn: function(u) { return ['login-verify','account-suspended','verify-now','update-billing','confirm-identity','secure-login','account-locked','unusual-activity','verify-account','password-reset','webscr','ebayisapi','signin-','banking-'].some(function(k){return u.toLowerCase().indexOf(k)!==-1;}); } },
        { name: 'Suspicious TLD',               fn: function(u) { var t=['.xyz','.top','.club','.work','.click','.loan','.gq','.ml','.cf','.tk','.pw']; try{var h=new URL(u).hostname;return t.some(function(x){return h.slice(-x.length)===x;});}catch(e){return false;} } },
        { name: 'Data Theft Patterns',          fn: function(u) { return ['passwd=','password=','creditcard=','ssn=','cvv=','bankaccount=','cardnumber=','pin='].some(function(x){return u.toLowerCase().indexOf(x)!==-1;}); } },
        { name: 'Excessive URL Length',         fn: function(u) { return u.length>150; } },
        { name: 'High URL Entropy',             fn: function(u) { try{return calcEntropy(new URL(u).hostname)>3.8;}catch(e){return false;} } },
        { name: 'Excessive Subdomains',         fn: function(u) { try{return new URL(u).hostname.split('.').length>=6;}catch(e){return false;} } },
        { name: 'Special Characters',           fn: function(u) { return (u.match(/[@#~]/g)||[]).length>=3; } },
        { name: 'Brand Name in Subdomain',      fn: function(u) { var b=['paypal','amazon','facebook','microsoft','apple','netflix','instagram','twitter','linkedin','whatsapp','bank','ebay']; try{var p=new URL(u).hostname.split('.');if(p.length<3)return false;var s=p.slice(0,p.length-2).join('.');return b.some(function(x){return s.indexOf(x)!==-1;});}catch(e){return false;} } },
        { name: 'Deep URL Path',                fn: function(u) { try{return new URL(u).pathname.split('/').length>8;}catch(e){return false;} } },
        { name: 'Number-Letter Substitution',   fn: function(u) { var b=['paypal','amazon','google','facebook','microsoft','apple','netflix','instagram','twitter','linkedin','bank','ebay']; try{var d=new URL(u).hostname.toLowerCase();var n=d.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/4/g,'a').replace(/5/g,'s');return b.some(function(x){return n.indexOf(x)!==-1&&d.indexOf(x)===-1;});}catch(e){return false;} } },
        { name: '@ Symbol Trick',               fn: function(u) { try{return new URL(u).username!=='';}catch(e){return false;} } },
        { name: 'Excessive Dots in Domain',     fn: function(u) { return (getDomain(u).match(/\./g)||[]).length>=5; } },
        { name: 'Hex Encoded Characters',       fn: function(u) { try{var p=new URL(u).pathname+new URL(u).search;return(p.match(/%[0-9a-fA-F]{2}/g)||[]).length>=5;}catch(e){return false;} } },
        { name: 'Suspicious File Extension',    fn: function(u) { return ['.exe','.bat','.cmd','.ps1','.vbs','.scr','.msi','.jar'].some(function(e){return u.toLowerCase().indexOf(e)!==-1;}); } },
        { name: 'Free Hosting Platform',        fn: function(u) { return ['000webhostapp.com','weebly.com','wixsite.com','glitch.me','firebaseapp.com'].some(function(h){return u.toLowerCase().indexOf(h)!==-1;}); } },
        { name: 'Urgency Words',                fn: function(u) { return ['account-suspended','account-locked','action-required','act-now','final-notice','verify-now','confirm-identity'].some(function(w){return u.toLowerCase().indexOf(w)!==-1;}); } },
        { name: 'Email Tracking Abuse',         fn: function(u) { return ['sendgrid.net','ct.sendgrid','mailchimp.com','list-manage.com','mandrillapp.com','emltrk.com'].some(function(s){return u.toLowerCase().indexOf(s)!==-1;}); } },
        { name: 'Numeric Subdomain',            fn: function(u) { try{return new URL(u).hostname.split('.').some(function(p){return /^[a-z]{0,2}\d{5,}$/.test(p);});}catch(e){return false;} } },
        { name: 'Auto-Generated Domain',        fn: function(u) { var d=getDomain(u).split('.')[0]; return /\d{5,}/.test(d)||(/[a-z]\d{3,}/.test(d)&&d.length>8); } },
        { name: 'Encoded Hidden URL',           fn: function(u) { return (u.match(/-2F|-2B|-3D|-2C|-3A/gi)||[]).length>=3; } },
        { name: 'Click Tracking Path',          fn: function(u) { var ps=['/ls/click','/track/click','/wf/click','/lt.php','/click.php']; try{var pn=new URL(u).pathname.toLowerCase();return ps.some(function(p){return pn.indexOf(p)===0;});}catch(e){return false;} } },
        { name: 'SendGrid Redirect Abuse',      fn: function(u) { var t=['sendgrid.net','ct.sendgrid','mailchimp.com','list-manage.com'].some(function(s){return u.toLowerCase().indexOf(s)!==-1;}); var c=false; try{var pn=new URL(u).pathname.toLowerCase();c=['/ls/click','/click','/track/click'].some(function(p){return pn.indexOf(p)===0;});}catch(e){} return t&&c; } },
        { name: 'Nested URL in Parameter',      fn: function(u) { try{var p=new URL(u).search;return /upn=|url=|u=|link=/.test(p)&&p.length>50;}catch(e){return false;} } },
        { name: 'Long Query String',            fn: function(u) { try{return new URL(u).search.length>200;}catch(e){return false;} } },
        { name: 'Multiple Redirects',           fn: function(u) { return ['redirect=','url=','next=','dest=','goto=','link=','target='].filter(function(p){return u.toLowerCase().indexOf(p)!==-1;}).length>=2; } },
        { name: 'Suspicious Redirect Parameter',fn: function(u) { try{var p=new URL(u).search.toLowerCase();return ['upn=','url=','link=','dest=','goto=','target=','redir='].some(function(x){return p.indexOf(x)!==-1;})&&p.length>100;}catch(e){return false;} } }
    ];
}

/* ─── KEYBOARD SUPPORT ───────────────────────────────────── */
document.getElementById('urlInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') startScan();
});

console.log('%c HawkEye Scanner ready ', 'background:#00d4ff;color:#060810;font-weight:bold;font-size:12px;padding:4px 8px;');
