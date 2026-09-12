
let RAW = { assets: null, vulnerabilities: null, controls: null, incidents: null };
let MODE = 'upload';
let DATA = null;     // computed model after analysis

const IMPROVEMENTS = [
    { id: 'mfa', name: 'Multi-factor authentication', effectiveness: 0.50, cost: 300000 },
    { id: 'firewall', name: 'Firewall hardening', effectiveness: 0.60, cost: 1000000 },
    { id: 'backup', name: 'Backup & recovery', effectiveness: 0.65, cost: 800000 },
    { id: 'segment', name: 'Network segmentation', effectiveness: 0.55, cost: 1200000 },
    { id: 'edr', name: 'Endpoint detection (EDR)', effectiveness: 0.70, cost: 1500000 },
    { id: 'patch', name: 'Patch management program', effectiveness: 0.60, cost: 500000 },
];


const TEMPLATES = {
    assets: {
        header: 'asset_id,asset_name,asset_type,department,criticality,business_value,internet_exposed,data_sensitivity',
        sample: 'A001,ERP Server,Server,Finance,5,50000000,Yes,5\nA002,Customer Database,Database,Sales,5,20000000,No,5'
    },
    vulnerabilities: {
        header: 'vulnerability_id,asset_id,vulnerability_name,severity,exploitability,status,discovered_date',
        sample: 'V001,A001,Outdated Software,9.8,0.8,Open,2026-08-01\nV002,A002,Weak Authentication,8.2,0.6,Open,2026-08-05'
    },
    controls: {
        header: 'control_id,control_name,asset_id,effectiveness,implementation_status,annual_cost',
        sample: 'C001,MFA,A001,0.60,Active,300000\nC002,Backup,A002,0.80,Active,800000'
    },
    incidents: {
        header: 'incident_id,asset_id,incident_type,frequency_per_year,average_loss,downtime_hours',
        sample: 'I001,A001,Ransomware,0.30,5000000,24\nI002,A002,Data Breach,0.20,10000000,48'
    }
};

function downloadTemplate(key) {
    const t = TEMPLATES[key];
    const content = t.header + '\n' + t.sample + '\n';
    const blob = new Blob([content], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = key + '_template.csv';
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
}

function parseCSV(text) {
    const lines = text.split(/\r\n|\n|\r/).filter(l => l.trim().length > 0);
    if (lines.length < 2) return [];
    const headers = lines[0].split(',').map(h => h.trim());
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
        const cells = lines[i].split(',').map(c => c.trim());
        const row = {};
        headers.forEach((h, idx) => { row[h] = cells[idx] !== undefined ? cells[idx] : ''; });
        rows.push(row);
    }
    return rows;
}

function num(v, fallback) {
    const n = parseFloat(String(v).replace(/[, ]/g, ''));
    return isNaN(n) ? (fallback !== undefined ? fallback : 0) : n;
}


function setMode(mode) {
    MODE = mode;
    document.getElementById('upload-tab').classList.toggle('active', mode === 'upload');
    document.getElementById('demo-tab').classList.toggle('active', mode === 'demo');
    document.getElementById('upload-panel').style.display = mode === 'upload' ? 'block' : 'none';
    document.getElementById('demo').style.display = mode === 'demo' ? 'block' : 'none';
    refreshAnalyzeState();
}

['assets', 'vulnerabilities', 'controls', 'incidents'].forEach(key => {
    const input = document.getElementById('file-' + key);
    const dz = document.getElementById('dz-' + key);
    input.addEventListener('change', e => handleFile(key, e.target.files[0]));
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
    dz.addEventListener('drop', e => {
        e.preventDefault(); dz.classList.remove('drag');
        if (e.dataTransfer.files[0]) handleFile(key, e.dataTransfer.files[0]);
    });
});

let RAW_FILES = { assets: null, vulnerabilities: null, controls: null, incidents: null };

function handleFile(key, file) {
    if (!file) return;
    RAW_FILES[key] = file;
    const reader = new FileReader();
    reader.onload = () => {
        try {
            const rows = parseCSV(reader.result);
            RAW[key] = rows;
            document.getElementById('status-' + key).textContent = file.name + ' — ' + rows.length + ' rows';
            document.getElementById('status-' + key).classList.add('ok');
            document.getElementById('dz-' + key).classList.add('filled');
        } catch (err) {
            showError('Could not read ' + file.name + '. Make sure it is a plain CSV file.');
        }
        refreshAnalyzeState();
    };
    reader.readAsText(file);
}

function refreshAnalyzeState() {
    const btn = document.getElementById('analyze');
    const note = document.getElementById('analyze-note');
    hideError();
    if (MODE === 'demo') {
        btn.disabled = false;
        note.textContent = 'Sample dataset ready to analyze';
        return;
    }
    const ok = RAW.assets && RAW.assets.length && RAW.vulnerabilities && RAW.vulnerabilities.length;
    btn.disabled = !ok;
    note.textContent = ok ? 'Ready to analyze' : 'Add assets and vulnerabilities to continue';
}

function showError(msg) {
    const box = document.getElementById('error');
    box.textContent = msg; box.classList.add('show');
}
function hideError() { document.getElementById('error').classList.remove('show'); }


function buildDemoData() {
    const assets = [
        { asset_id: 'A001', asset_name: 'ERP Server', asset_type: 'Server', department: 'Finance', criticality: '5', business_value: '50000000', internet_exposed: 'Yes', data_sensitivity: '5' },
        { asset_id: 'A002', asset_name: 'Customer Database', asset_type: 'Database', department: 'Sales', criticality: '5', business_value: '20000000', internet_exposed: 'No', data_sensitivity: '5' },
        { asset_id: 'A003', asset_name: 'Email Server', asset_type: 'Server', department: 'IT', criticality: '4', business_value: '10000000', internet_exposed: 'Yes', data_sensitivity: '4' },
        { asset_id: 'A004', asset_name: 'HR Portal', asset_type: 'Application', department: 'HR', criticality: '3', business_value: '5000000', internet_exposed: 'Yes', data_sensitivity: '3' },
        { asset_id: 'A005', asset_name: 'File Server', asset_type: 'Server', department: 'IT', criticality: '3', business_value: '6000000', internet_exposed: 'No', data_sensitivity: '3' },
        { asset_id: 'A006', asset_name: 'Payment Gateway', asset_type: 'Application', department: 'Finance', criticality: '5', business_value: '35000000', internet_exposed: 'Yes', data_sensitivity: '5' },
        { asset_id: 'A007', asset_name: 'Employee Laptop Fleet', asset_type: 'Endpoint', department: 'IT', criticality: '2', business_value: '3000000', internet_exposed: 'No', data_sensitivity: '2' },
        { asset_id: 'A008', asset_name: 'Cloud Storage Bucket', asset_type: 'Cloud Resource', department: 'Engineering', criticality: '4', business_value: '8000000', internet_exposed: 'Yes', data_sensitivity: '4' },
        { asset_id: 'A009', asset_name: 'VPN Gateway', asset_type: 'Network Device', department: 'IT', criticality: '4', business_value: '4000000', internet_exposed: 'Yes', data_sensitivity: '2' },
        { asset_id: 'A010', asset_name: 'Marketing Website', asset_type: 'Application', department: 'Marketing', criticality: '2', business_value: '1500000', internet_exposed: 'Yes', data_sensitivity: '1' }
    ];
    const vulnerabilities = [
        { vulnerability_id: 'V001', asset_id: 'A001', vulnerability_name: 'Outdated ERP Software', severity: '9.8', exploitability: '0.8', status: 'Open', discovered_date: '2026-08-01' },
        { vulnerability_id: 'V002', asset_id: 'A001', vulnerability_name: 'Weak Authentication', severity: '8.5', exploitability: '0.7', status: 'Open', discovered_date: '2026-08-05' },
        { vulnerability_id: 'V003', asset_id: 'A002', vulnerability_name: 'Database Misconfiguration', severity: '8.2', exploitability: '0.6', status: 'Open', discovered_date: '2026-08-10' },
        { vulnerability_id: 'V004', asset_id: 'A003', vulnerability_name: 'Missing Security Patch', severity: '7.5', exploitability: '0.7', status: 'Open', discovered_date: '2026-08-12' },
        { vulnerability_id: 'V005', asset_id: 'A004', vulnerability_name: 'Weak Password Policy', severity: '6.5', exploitability: '0.5', status: 'Open', discovered_date: '2026-08-15' },
        { vulnerability_id: 'V006', asset_id: 'A006', vulnerability_name: 'Unpatched Payment Library', severity: '9.4', exploitability: '0.75', status: 'Open', discovered_date: '2026-08-18' },
        { vulnerability_id: 'V007', asset_id: 'A006', vulnerability_name: 'Insecure API Endpoint', severity: '8.8', exploitability: '0.65', status: 'Open', discovered_date: '2026-08-19' },
        { vulnerability_id: 'V008', asset_id: 'A005', vulnerability_name: 'Excessive File Permissions', severity: '6.0', exploitability: '0.45', status: 'Open', discovered_date: '2026-08-20' },
        { vulnerability_id: 'V009', asset_id: 'A007', vulnerability_name: 'Unencrypted Local Storage', severity: '5.5', exploitability: '0.4', status: 'Open', discovered_date: '2026-08-21' },
        { vulnerability_id: 'V010', asset_id: 'A008', vulnerability_name: 'Public Bucket Access', severity: '9.0', exploitability: '0.8', status: 'Open', discovered_date: '2026-08-22' },
        { vulnerability_id: 'V011', asset_id: 'A009', vulnerability_name: 'Outdated VPN Firmware', severity: '8.0', exploitability: '0.6', status: 'Open', discovered_date: '2026-08-23' },
        { vulnerability_id: 'V012', asset_id: 'A010', vulnerability_name: 'Outdated CMS Plugin', severity: '6.2', exploitability: '0.5', status: 'Open', discovered_date: '2026-08-24' },
        { vulnerability_id: 'V013', asset_id: 'A002', vulnerability_name: 'Missing Encryption at Rest', severity: '7.0', exploitability: '0.4', status: 'Open', discovered_date: '2026-08-25' },
        { vulnerability_id: 'V014', asset_id: 'A003', vulnerability_name: 'Open Relay Configuration', severity: '5.0', exploitability: '0.35', status: 'Open', discovered_date: '2026-08-26' }
    ];
    const controls = [
        { control_id: 'C001', control_name: 'MFA', asset_id: 'A001', effectiveness: '0.60', implementation_status: 'Active', annual_cost: '300000' },
        { control_id: 'C002', control_name: 'Firewall', asset_id: 'A001', effectiveness: '0.70', implementation_status: 'Active', annual_cost: '1000000' },
        { control_id: 'C003', control_name: 'Backup', asset_id: 'A002', effectiveness: '0.80', implementation_status: 'Active', annual_cost: '800000' },
        { control_id: 'C004', control_name: 'EDR', asset_id: 'A003', effectiveness: '0.50', implementation_status: 'Active', annual_cost: '1200000' },
        { control_id: 'C005', control_name: 'MFA', asset_id: 'A004', effectiveness: '0.40', implementation_status: 'Active', annual_cost: '150000' },
        { control_id: 'C006', control_name: 'WAF', asset_id: 'A006', effectiveness: '0.55', implementation_status: 'Active', annual_cost: '900000' },
        { control_id: 'C007', control_name: 'Access Review', asset_id: 'A005', effectiveness: '0.35', implementation_status: 'Active', annual_cost: '200000' },
        { control_id: 'C008', control_name: 'Disk Encryption', asset_id: 'A007', effectiveness: '0.45', implementation_status: 'Active', annual_cost: '250000' },
        { control_id: 'C009', control_name: 'IAM Policy', asset_id: 'A009', effectiveness: '0.50', implementation_status: 'Active', annual_cost: '400000' }
    ];
    const incidents = [
        { incident_id: 'I001', asset_id: 'A001', incident_type: 'Ransomware', frequency_per_year: '0.30', average_loss: '5000000', downtime_hours: '24' },
        { incident_id: 'I002', asset_id: 'A001', incident_type: 'Server Compromise', frequency_per_year: '0.20', average_loss: '3000000', downtime_hours: '12' },
        { incident_id: 'I003', asset_id: 'A002', incident_type: 'Data Breach', frequency_per_year: '0.20', average_loss: '10000000', downtime_hours: '48' },
        { incident_id: 'I004', asset_id: 'A003', incident_type: 'Credential Theft', frequency_per_year: '0.40', average_loss: '2000000', downtime_hours: '8' },
        { incident_id: 'I005', asset_id: 'A004', incident_type: 'Account Takeover', frequency_per_year: '0.30', average_loss: '1000000', downtime_hours: '6' },
        { incident_id: 'I006', asset_id: 'A006', incident_type: 'Payment Fraud', frequency_per_year: '0.25', average_loss: '8000000', downtime_hours: '18' },
        { incident_id: 'I007', asset_id: 'A008', incident_type: 'Data Breach', frequency_per_year: '0.15', average_loss: '6000000', downtime_hours: '20' },
        { incident_id: 'I008', asset_id: 'A009', incident_type: 'Ransomware', frequency_per_year: '0.10', average_loss: '4000000', downtime_hours: '16' },
        { incident_id: 'I009', asset_id: 'A010', incident_type: 'Defacement', frequency_per_year: '0.35', average_loss: '300000', downtime_hours: '4' }
    ];
    return { assets, vulnerabilities, controls, incidents };
}


function riskLevel(score) {
    if (score >= 76) return 'CRITICAL';
    if (score >= 51) return 'HIGH';
    if (score >= 26) return 'MEDIUM';
    return 'LOW';
}
function levelTagClass(level) {
    return { CRITICAL: 'tag-critical', HIGH: 'tag-high', MEDIUM: 'tag-medium', LOW: 'tag-low' }[level];
}
function levelColor(level) {
    return { CRITICAL: '#a4291f', HIGH: '#a3690f', MEDIUM: '#8a8a24', LOW: '#1f7a4d' }[level];
}

function computeModel(src) {
    const assets = src.assets.map(a => ({
        id: a.asset_id, name: a.asset_name, type: a.asset_type, dept: a.department,
        criticality: num(a.criticality, 1), businessValue: num(a.business_value, 0),
        exposed: (a.internet_exposed || '').toLowerCase() === 'yes', sensitivity: num(a.data_sensitivity, 1)
    }));
    const vulns = (src.vulnerabilities || []).map(v => ({
        id: v.vulnerability_id, assetId: v.asset_id, name: v.vulnerability_name,
        severity: num(v.severity, 0), exploitability: num(v.exploitability, 0), status: v.status || 'Open'
    }));
    const controls = (src.controls || []).map(c => ({
        id: c.control_id, name: c.control_name, assetId: c.asset_id,
        effectiveness: num(c.effectiveness, 0), cost: num(c.annual_cost, 0)
    }));
    const incidents = (src.incidents || []).map(i => ({
        id: i.incident_id, assetId: i.asset_id, type: i.incident_type,
        freq: num(i.frequency_per_year, 0), loss: num(i.average_loss, 0)
    }));

    const perAsset = assets.map(a => {
        const aVulns = vulns.filter(v => v.assetId === a.id);
        const aControls = controls.filter(c => c.assetId === a.id);
        const topVuln = aVulns.reduce((best, v) => (!best || v.severity > best.severity) ? v : best, null);
        const protection = aControls.reduce((m, c) => Math.max(m, c.effectiveness), 0);
        const residual = 1 - protection;
        const severity = topVuln ? topVuln.severity : 0;
        const exploitability = topVuln ? topVuln.exploitability : 0;
        const likelihood = (severity / 10) * exploitability * residual;
        const impactPct = 0.10 + a.criticality * 0.04;
        const potentialLoss = a.businessValue * impactPct;
        const expectedLoss = likelihood * potentialLoss;
        const riskScore = Math.min(100, a.criticality * (severity / 10) * exploitability * 20);
        const level = riskLevel(riskScore);
        return {
            ...a, topVuln, vulnCount: aVulns.length, controls: aControls, protection, residual,
            likelihood, impactPct, potentialLoss, expectedLoss, riskScore, level
        };
    });

    const totalExpectedLoss = perAsset.reduce((s, a) => s + a.expectedLoss, 0);
    const totalBV = perAsset.reduce((s, a) => s + a.businessValue, 0) || 1;
    const overallRiskScore = perAsset.reduce((s, a) => s + a.riskScore * a.businessValue, 0) / totalBV;
    const criticalAssets = perAsset.filter(a => a.level === 'CRITICAL').length;

    const vulnBuckets = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    vulns.forEach(v => {
        if (v.severity >= 9) vulnBuckets.CRITICAL++;
        else if (v.severity >= 7) vulnBuckets.HIGH++;
        else if (v.severity >= 4) vulnBuckets.MEDIUM++;
        else vulnBuckets.LOW++;
    });

    const threatMap = {};
    incidents.forEach(i => {
        if (!threatMap[i.type]) threatMap[i.type] = { type: i.type, exposure: 0, freq: 0, count: 0 };
        threatMap[i.type].exposure += i.freq * i.loss;
        threatMap[i.type].freq += i.freq;
        threatMap[i.type].count++;
    });
    const threats = Object.values(threatMap).sort((a, b) => b.exposure - a.exposure);

    return {
        assets: perAsset, vulns, controls, incidents, totalExpectedLoss, overallRiskScore,
        criticalAssets, vulnBuckets, threats,
        criticalVulnCount: vulnBuckets.CRITICAL
    };
}


function totalLossWithExtraProtection(assets, extraEffectiveness) {
    let total = 0;
    assets.forEach(a => {
        const protection = Math.max(a.protection, extraEffectiveness);
        const residual = 1 - protection;
        const likelihood = (a.topVuln ? a.topVuln.severity / 10 : 0) * (a.topVuln ? a.topVuln.exploitability : 0) * residual;
        total += likelihood * a.potentialLoss;
    });
    return total;
}


function objectsToCSVString(arr, headers) {
    if (!arr) return headers.join(',') + '\n';
    const lines = [headers.join(',')];
    arr.forEach(obj => {
        const row = headers.map(h => {
            let val = obj[h] !== undefined && obj[h] !== null ? String(obj[h]) : '';
            if (val.includes(',') || val.includes('"') || val.includes('\n')) {
                val = '"' + val.replace(/"/g, '""') + '"';
            }
            return val;
        });
        lines.push(row.join(','));
    });
    return lines.join('\n');
}

const CSV_HEADERS = {
    assets: ['asset_id', 'asset_name', 'asset_type', 'department', 'criticality', 'business_value', 'internet_exposed', 'data_sensitivity'],
    vulnerabilities: ['vulnerability_id', 'asset_id', 'vulnerability_name', 'severity', 'exploitability', 'status', 'discovered_date'],
    controls: ['control_id', 'control_name', 'asset_id', 'effectiveness', 'implementation_status', 'annual_cost'],
    incidents: ['incident_id', 'asset_id', 'incident_type', 'frequency_per_year', 'average_loss', 'downtime_hours']
};

async function sendBackendValidation(src) {
    try {
        const formData = new FormData();
        const keys = ['assets', 'vulnerabilities', 'controls', 'incidents'];

        keys.forEach(key => {
            if (MODE === 'upload' && RAW_FILES[key]) {
                formData.append(key, RAW_FILES[key]);
            } else {
                const arr = src[key] || [];
                const csvStr = objectsToCSVString(arr, CSV_HEADERS[key]);
                const blob = new Blob([csvStr], { type: 'text/csv' });
                const file = new File([blob], key + '.csv', { type: 'text/csv' });
                formData.append(key, file);
            }
        });

        const response = await fetch('http://localhost:8000/api/validate', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (response.ok && result.valid) {
            console.log('Backend validation successful:', result);
        } else {
            console.warn('Backend validation errors:', result);
        }
    } catch (err) {
        console.warn('Backend validation call failed (server offline or network error):', err);
    }
}

function _buildFormData(src) {
    const formData = new FormData();
    const keys = ['assets', 'vulnerabilities', 'controls', 'incidents'];
    keys.forEach(key => {
        if (MODE === 'upload' && RAW_FILES[key]) {
            formData.append(key, RAW_FILES[key]);
        } else {
            const arr = src[key] || [];
            const csvStr = objectsToCSVString(arr, CSV_HEADERS[key]);
            const blob = new Blob([csvStr], { type: 'text/csv' });
            const file = new File([blob], key + '.csv', { type: 'text/csv' });
            formData.append(key, file);
        }
    });
    return formData;
}

async function sendBackendProcessing(src) {
    try {
        const formData = _buildFormData(src);
        const response = await fetch('http://localhost:8000/api/process', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (response.ok && result.success) {
            console.log('Backend data processing successful:', result.summary);
            // Log A001 profile as a spot-check
            const a001 = (result.assets || []).find(a => a.asset_id === 'A001');
            if (a001) console.log('A001 profile:', a001);
        } else {
            console.warn('Backend processing failed:', result);
        }
    } catch (err) {
        console.warn('Backend processing call failed (server offline or network error):', err);
    }
}

async function sendBackendAnalyze(src) {
    try {
        const formData = _buildFormData(src);
        const response = await fetch('http://localhost:8000/api/analyze', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (response.ok && result.success) {
            console.log('Backend risk analysis successful:', result);
            console.log('Overall modeled risk:', result.overall_risk);
            console.log('Risk distribution:', result.risk_distribution);
            // Spot check A001
            const a001 = (result.assets || []).find(a => a.asset_id === 'A001');
            if (a001) console.log('A001 modeled risk profile:', a001);
        } else {
            console.warn('Backend analysis failed:', result);
        }
    } catch (err) {
        console.warn('Backend analysis call failed (server offline or network error):', err);
    }
}

function startAnalysis() {
    hideError();
    let src;
    if (MODE === 'demo') {
        src = buildDemoData();
    } else {
        if (!RAW.assets || !RAW.assets.length) { showError('Please add an assets file before analyzing.'); return; }
        if (!RAW.vulnerabilities || !RAW.vulnerabilities.length) { showError('Please add a vulnerabilities file before analyzing.'); return; }
        src = { assets: RAW.assets, vulnerabilities: RAW.vulnerabilities, controls: RAW.controls || [], incidents: RAW.incidents || [] };
    }

    // Trigger backend validation, processing, and risk analysis asynchronously without blocking UI
    sendBackendValidation(src);
    sendBackendProcessing(src);
    sendBackendAnalyze(src);

    const overlay = document.getElementById('process');
    overlay.classList.add('show');
    const steps = document.querySelectorAll('.process-step');
    const bar = document.getElementById('process-bar');
    steps.forEach(s => s.classList.remove('done'));
    bar.style.width = '0%';

    let i = 0;
    const timer = setInterval(() => {
        if (i < steps.length) { steps[i].classList.add('done'); i++; }
        bar.style.width = Math.round((i / steps.length) * 100) + '%';
        if (i >= steps.length) {
            clearInterval(timer);
            setTimeout(() => {
                DATA = computeModel(src);
                overlay.classList.remove('show');
                launchDashboard();
            }, 350);
        }
    }, 380);
}

function resetApp() {
    DATA = null;
    RAW = { assets: null, vulnerabilities: null, controls: null, incidents: null };
    RAW_FILES = { assets: null, vulnerabilities: null, controls: null, incidents: null };
    ['assets', 'vulnerabilities', 'controls', 'incidents'].forEach(k => {
        document.getElementById('status-' + k).textContent = 'No file selected';
        document.getElementById('status-' + k).classList.remove('ok');
        document.getElementById('dz-' + k).classList.remove('filled');
        document.getElementById('file-' + k).value = '';
    });
    document.getElementById('dashboard-page').classList.remove('active');
    document.getElementById('upload-page').classList.add('active');
    refreshAnalyzeState();
}


function fmtINR(n) {
    n = Math.round(n);
    if (Math.abs(n) >= 10000000) return '₹' + (n / 10000000).toFixed(2) + ' Cr';
    if (Math.abs(n) >= 100000) return '₹' + (n / 100000).toFixed(2) + ' L';
    return '₹' + n.toLocaleString('en-IN');
}

function launchDashboard() {
    document.getElementById('upload-page').classList.remove('active');
    document.getElementById('dashboard-page').classList.add('active');
    showSection('overview');
    renderOverview();
    renderAssets();
    renderVulns();
    renderThreats();
    renderFinancial();
    renderWhatIfChecklist();
    renderReport();
    document.getElementById('plan').innerHTML = '<div class="empty">Set a budget and click Optimize.</div>';
}

function showSection(name) {
    document.querySelectorAll('.page').forEach(s => s.classList.remove('active'));
    document.getElementById('sec-' + name).classList.add('active');
    document.querySelectorAll('.nav-link').forEach(b => b.classList.toggle('active', b.dataset.sec === name));
}

function renderOverview() {
    const level = riskLevel(DATA.overallRiskScore);
    const stats = [
        { label: 'Overall risk score', value: DATA.overallRiskScore.toFixed(0) + ' / 100', tag: level },
        { label: 'Expected annual loss', value: fmtINR(DATA.totalExpectedLoss), tag: null },
        { label: 'Assets analyzed', value: DATA.assets.length, tag: null },
        { label: 'Critical vulnerabilities', value: DATA.criticalVulnCount, tag: null }
    ];
    document.getElementById('overview-stats').innerHTML = stats.map(s => `
    <div class="card">
      <div class="label">${s.label}</div>
      <div class="value">${s.value}</div>
      ${s.tag ? `<div class="tag ${levelTagClass(s.tag)}">${s.tag}</div>` : ''}
    </div>`).join('');

    const top = [...DATA.assets].sort((a, b) => b.expectedLoss - a.expectedLoss).slice(0, 6);
    document.getElementById('top-risks').innerHTML = top.map(a => `
    <tr class="click-row" onclick="showSection('assets');openAssetDetail('${a.id}')">
      <td><b>${a.name}</b></td>
      <td>${a.riskScore.toFixed(0)}</td>
      <td class="num">${fmtINR(a.expectedLoss)}</td>
      <td><span class="tag ${levelTagClass(a.level)}">${a.level}</span></td>
    </tr>`).join('');
}

function renderAssets() {
    const rows = [...DATA.assets].sort((a, b) => b.riskScore - a.riskScore);
    document.getElementById('asset-table').innerHTML = rows.map(a => `
    <tr class="click-row" onclick="openAssetDetail('${a.id}')">
      <td><b>${a.name}</b></td>
      <td>${a.type}</td>
      <td>${a.dept}</td>
      <td>${a.criticality}/5</td>
      <td class="num">${a.riskScore.toFixed(0)}</td>
      <td><span class="tag ${levelTagClass(a.level)}">${a.level}</span></td>
    </tr>`).join('');
    closeAssetDetail();
}

function openAssetDetail(id) {
    const a = DATA.assets.find(x => x.id === id);
    if (!a) return;
    document.getElementById('asset-detail').classList.add('show');
    document.getElementById('asset-detail-body').innerHTML = `
    <h3 style="font-size:19px;">${a.name}</h3>
    <div class="pills">
      <span class="pill">${a.type}</span><span class="pill">${a.dept}</span>
      <span class="pill">Criticality ${a.criticality}/5</span>
      <span class="tag ${levelTagClass(a.level)}">${a.level}</span>
    </div>
    <div class="grid grid4" style="margin-top:18px;">
      <div><div class="label">Business value</div><div class="value" style="font-size:19px;">${fmtINR(a.businessValue)}</div></div>
      <div><div class="label">Risk score</div><div class="value" style="font-size:19px;">${a.riskScore.toFixed(0)}/100</div></div>
      <div><div class="label">Expected annual loss</div><div class="value" style="font-size:19px;">${fmtINR(a.expectedLoss)}</div></div>
      <div><div class="label">Existing protection</div><div class="value" style="font-size:19px;">${Math.round(a.protection * 100)}%</div></div>
    </div>
    <div style="margin-top:20px;">
      <div class="title">Top vulnerability</div>
      ${a.topVuln ? `<p style="font-size:13.5px;">${a.topVuln.name} — severity ${a.topVuln.severity}, exploitability ${a.topVuln.exploitability}</p>` : `<p class="empty">None recorded</p>`}
    </div>
    <div style="margin-top:16px;">
      <div class="title">Controls in place</div>
      ${a.controls.length ? a.controls.map(c => `<p style="font-size:13.5px;">${c.name} — ${Math.round(c.effectiveness * 100)}% effective</p>`).join('') : `<p class="empty">No controls recorded for this asset</p>`}
    </div>`;
}
function closeAssetDetail() { document.getElementById('asset-detail').classList.remove('show'); }

function renderVulns() {
    const b = DATA.vulnBuckets;
    const items = [
        { label: 'Critical', value: b.CRITICAL, cls: 'tag-critical' },
        { label: 'High', value: b.HIGH, cls: 'tag-high' },
        { label: 'Medium', value: b.MEDIUM, cls: 'tag-medium' },
        { label: 'Low', value: b.LOW, cls: 'tag-low' }
    ];
    document.getElementById('vuln-counts').innerHTML = items.map(i => `
    <div class="card"><div class="label">${i.label}</div><div class="value">${i.value}</div></div>`).join('');

    const top = [...DATA.vulns].sort((a, b) => b.severity - a.severity).slice(0, 10);
    document.getElementById('vuln-table').innerHTML = top.map(v => {
        const asset = DATA.assets.find(a => a.id === v.assetId);
        return `<tr><td><b>${v.name}</b></td><td>${asset ? asset.name : v.assetId}</td><td class="num">${v.severity}</td><td class="num">${v.exploitability}</td><td>${v.status}</td></tr>`;
    }).join('');
}

function renderThreats() {
    if (!DATA.threats.length) {
        document.getElementById('threats').innerHTML = `<div class="empty">No incident history was provided, so threat modeling is unavailable. Upload an incidents file to see this page.</div>`;
        return;
    }
    const max = Math.max(...DATA.threats.map(t => t.exposure));
    document.getElementById('threats').innerHTML = `
    <div class="title">Modeled exposure by threat type</div>
    <table><thead><tr><th>Threat</th><th>Frequency / yr</th><th>Modeled exposure</th></tr></thead><tbody>
    ${DATA.threats.map(t => `
      <tr><td><b>${t.type}</b></td><td class="num">${t.freq.toFixed(2)}</td>
      <td>
        <div class="bar-cell">
          <div class="bar-track"><div class="bar-fill" style="width:${(t.exposure / max * 100).toFixed(0)}%;background:var(--accent);"></div></div>
          <span class="num" style="width:90px;text-align:right;">${fmtINR(t.exposure)}</span>
        </div>
      </td></tr>`).join('')}
    </tbody></table>`;
}

function renderFinancial() {
    document.getElementById('financial-total').textContent = fmtINR(DATA.totalExpectedLoss);
    const top = [...DATA.assets].sort((a, b) => b.expectedLoss - a.expectedLoss).slice(0, 8);
    const max = Math.max(...top.map(a => a.expectedLoss), 1);
    document.getElementById('financial-bars').innerHTML = top.map(a => `
    <div style="margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:5px;">
        <span style="font-weight:600;">${a.name}</span><span class="num">${fmtINR(a.expectedLoss)}</span>
      </div>
      <div class="bar-track"><div class="bar-fill" style="width:${(a.expectedLoss / max * 100).toFixed(0)}%;background:${levelColor(a.level)};"></div></div>
    </div>`).join('');
}

/* ---------- What-if ---------- */
function renderWhatIfChecklist() {
    document.getElementById('whatif-list').innerHTML = IMPROVEMENTS.map(imp => `
    <div class="check-row">
      <input type="checkbox" id="wi-${imp.id}">
      <label for="wi-${imp.id}">${imp.name}</label>
      <span class="meta">${Math.round(imp.effectiveness * 100)}% · ${fmtINR(imp.cost)}/yr</span>
    </div>`).join('');
    document.getElementById('whatif-before').textContent = fmtINR(DATA.totalExpectedLoss);
    document.getElementById('whatif-after').textContent = fmtINR(DATA.totalExpectedLoss);
    document.getElementById('whatif-reduction').textContent = fmtINR(0);
}
function runWhatIf() {
    const chosen = IMPROVEMENTS.filter(imp => document.getElementById('wi-' + imp.id).checked);
    const extraEff = chosen.reduce((m, i) => Math.max(m, i.effectiveness), 0);
    const before = DATA.totalExpectedLoss;
    const after = totalLossWithExtraProtection(DATA.assets, extraEff);
    document.getElementById('whatif-before').textContent = fmtINR(before);
    document.getElementById('whatif-after').textContent = fmtINR(after);
    document.getElementById('whatif-reduction').textContent = fmtINR(Math.max(0, before - after));
}


function runOptimizer() {
    const budgetRaw = document.getElementById('budget-input').value;
    const budget = num(budgetRaw, 0);
    if (budget <= 0) {
        document.getElementById('plan').innerHTML = `<div class="empty">Enter a budget greater than zero.</div>`;
        return;
    }
    let remaining = budget;
    let selected = [];
    let currentEff = 0;
    let currentLoss = DATA.totalExpectedLoss;
    let pool = IMPROVEMENTS.slice();

    while (true) {
        let best = null, bestRatio = -1, bestNewLoss = currentLoss, bestNewEff = currentEff;
        pool.forEach(item => {
            if (item.cost > remaining) return;
            const candidateEff = Math.max(currentEff, item.effectiveness);
            const newLoss = totalLossWithExtraProtection(DATA.assets, candidateEff);
            const reduction = currentLoss - newLoss;
            const ratio = reduction / item.cost;
            if (reduction > 0.01 && ratio > bestRatio) {
                bestRatio = ratio; best = item; bestNewLoss = newLoss; bestNewEff = candidateEff;
            }
        });
        if (!best) break;
        selected.push({ ...best, reduction: currentLoss - bestNewLoss });
        remaining -= best.cost;
        currentLoss = bestNewLoss;
        currentEff = bestNewEff;
        pool = pool.filter(p => p.id !== best.id);
    }

    if (!selected.length) {
        document.getElementById('plan').innerHTML = `<div class="empty">No protections fit within this budget.</div>`;
        return;
    }

    const totalCost = selected.reduce((s, i) => s + i.cost, 0);
    const totalReduction = DATA.totalExpectedLoss - currentLoss;

    document.getElementById('plan').innerHTML = `
    ${selected.map((item, i) => `
      <div class="option">
        <div class="option-num">${i + 1}</div>
        <div class="option-name">${item.name}</div>
        <div class="option-value">${fmtINR(item.cost)}</div>
        <div class="option-value" style="color:var(--safe);">−${fmtINR(item.reduction)}</div>
      </div>`).join('')}
    <div class="grid grid3" style="margin-top:18px;">
      <div><div class="label">Total investment</div><div class="value" style="font-size:19px;">${fmtINR(totalCost)}</div></div>
      <div><div class="label">Expected risk reduction</div><div class="value" style="font-size:19px;color:var(--safe);">${fmtINR(totalReduction)}</div></div>
      <div><div class="label">Remaining budget</div><div class="value" style="font-size:19px;">${fmtINR(remaining)}</div></div>
    </div>`;
}

function renderRecommendations() {
    const top = [...DATA.assets].sort((a, b) => b.expectedLoss - a.expectedLoss).slice(0, 3);
    const items = top.map((a, i) => ({
        priority: i === 0 ? 'p1' : i === 1 ? 'p2' : 'p3',
        label: i === 0 ? 'HIGH PRIORITY' : i === 1 ? 'MEDIUM PRIORITY' : 'LOWER PRIORITY',
        title: a.topVuln ? `Remediate "${a.topVuln.name}" on ${a.name}` : `Review ${a.name}`,
        body: `${a.name} carries the ${i === 0 ? 'highest' : 'a significant'} modeled exposure in this dataset, driven by ${a.topVuln ? 'a severity ' + a.topVuln.severity + ' vulnerability' : 'its criticality and value'} and ${Math.round(a.protection * 100)}% existing protection.`,
        exposure: a.expectedLoss,
        reduction: a.expectedLoss * 0.6
    }));

    document.getElementById('recommendations').innerHTML = items.map(r => `
    <div class="rec-item">
      <div class="rec-top"><div class="rec-dot ${r.priority}"></div><div class="rec-title">${r.title}</div></div>
      <div class="rec-body">${r.body}</div>
      <div class="rec-meta">
        <div><span>Estimated exposure</span><b>${fmtINR(r.exposure)}</b></div>
        <div><span>Potential reduction</span><b style="color:var(--safe);">${fmtINR(r.reduction)}</b></div>
      </div>
    </div>`).join('');
}

/* ---------- Report ---------- */
function buildReportText() {
    const level = riskLevel(DATA.overallRiskScore);
    const top = [...DATA.assets].sort((a, b) => b.expectedLoss - a.expectedLoss).slice(0, 5);
    let lines = [];
    lines.push('CYBER RISK ASSESSMENT');
    lines.push('='.repeat(40));
    lines.push('');
    lines.push('Overall risk score: ' + DATA.overallRiskScore.toFixed(0) + ' / 100 (' + level + ')');
    lines.push('Expected annual loss: ' + fmtINR(DATA.totalExpectedLoss));
    lines.push('Assets analyzed: ' + DATA.assets.length);
    lines.push('Critical vulnerabilities: ' + DATA.criticalVulnCount);
    lines.push('');
    lines.push('TOP RISKS');
    lines.push('-'.repeat(40));
    top.forEach((a, i) => lines.push((i + 1) + '. ' + a.name + ' — risk ' + a.riskScore.toFixed(0) + '/100, expected loss ' + fmtINR(a.expectedLoss)));
    lines.push('');
    if (DATA.threats.length) {
        lines.push('TOP THREATS');
        lines.push('-'.repeat(40));
        DATA.threats.slice(0, 5).forEach((t, i) => lines.push((i + 1) + '. ' + t.type + ' — modeled exposure ' + fmtINR(t.exposure)));
        lines.push('');
    }
    lines.push('Note: figures are modeled estimates for planning purposes, not guarantees.');
    return lines.join('\n');
}
function renderReport() {
    renderRecommendations();
    document.getElementById('report-text').textContent = buildReportText();
}
function downloadReport() {
    const blob = new Blob([buildReportText()], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'risk_report.txt';
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
}

/* ---------- Backend Health Check ---------- */
async function checkBackendHealth() {
    try {
        const response = await fetch('http://localhost:8000/api/health');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Backend connected:', data);
    } catch (err) {
        console.log('Backend unavailable. Running frontend in local/demo mode.');
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkBackendHealth);
} else {
    checkBackendHealth();
}