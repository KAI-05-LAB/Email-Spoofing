import re
import dns.resolver
from flask import Flask, render_template_string, request, jsonify

# Initialize the Flask application
app = Flask(__name__)

# --- Core DNS and Parsing Functions ---

def parse_headers(headers):
    """
    Parses email headers to find the From domain, DKIM selector, and DKIM domain.
    """
    from_match = re.search(r'^From:\s*.*<(.+?)>', headers, re.MULTILINE | re.IGNORECASE) or \
                 re.search(r'^From:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', headers, re.MULTILINE | re.IGNORECASE)
    
    dkim_match = re.search(r'^DKIM-Signature:.*s=([^;\s]+).*d=([^;\s]+)', headers, re.MULTILINE | re.IGNORECASE)

    from_domain = from_match.group(1).split('@')[-1] if from_match else None
    dkim_selector = dkim_match.group(1).strip() if dkim_match else None
    dkim_domain = dkim_match.group(2).strip() if dkim_match else None
    
    return {
        "from_domain": from_domain,
        "dkim_selector": dkim_selector,
        "dkim_domain": dkim_domain
    }

def check_spf(domain):
    """
    Checks if an SPF record exists for the given domain.
    """
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if 'v=spf1' in record.strings[0].decode('utf-8'):
                return {"status": "pass", "detail": f"An SPF policy was found for {domain}."}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        pass # Fall through to fail
    return {"status": "fail", "detail": f"No SPF policy found for {domain}. This makes spoofing easier."}

def check_dkim(selector, domain):
    """
    Checks if a DKIM public key exists in the DNS.
    """
    if not selector or not domain:
        return {"status": "neutral", "detail": "No DKIM signature was found in the email headers."}
    
    dkim_record_name = f"{selector}._domainkey.{domain}"
    try:
        txt_records = dns.resolver.resolve(dkim_record_name, 'TXT')
        for record in txt_records:
            if 'v=DKIM1' in record.strings[0].decode('utf-8'):
                return {"status": "pass", "detail": "A valid DKIM public key was found. The email signature can be verified."}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        pass # Fall through to fail
    return {"status": "fail", "detail": f"DKIM signature found, but no matching public key in DNS for {domain}."}

def check_dmarc(domain):
    """
    Checks if a DMARC record exists for the given domain.
    """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in txt_records:
            if 'v=DMARC1' in record.strings[0].decode('utf-8'):
                return {"status": "pass", "detail": "A DMARC policy was found, which tells servers how to handle failures."}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        pass # Fall through to neutral
    return {"status": "neutral", "detail": f"No DMARC policy found for {domain}."}


# --- Flask Routes ---

@app.route('/')
def index():
    """
    Renders the main HTML page.
    The HTML is embedded as a string for simplicity.
    """
    # The HTML content from the previous immersive artifact is placed here
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Spoofing Checker - Python/Flask</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', sans-serif; background-color: #f8fafc; }
            .loader { border: 4px solid #e5e7eb; border-top: 4px solid #3b82f6; border-radius: 50%; width: 24px; height: 24px; animation: spin 1s linear infinite; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            .result-card { transition: all 0.3s ease-in-out; transform: translateY(20px); opacity: 0; animation: fadeInUp 0.5s ease forwards; }
            @keyframes fadeInUp { to { opacity: 1; transform: translateY(0); } }
            .result-card:nth-child(1) { animation-delay: 0.1s; }
            .result-card:nth-child(2) { animation-delay: 0.2s; }
            .result-card:nth-child(3) { animation-delay: 0.3s; }
        </style>
    </head>
    <body class="text-slate-800">
        <div class="container mx-auto p-4 sm:p-6 md:p-8 max-w-5xl">
            <header class="text-center mb-8">
                <h1 class="text-3xl sm:text-4xl font-bold text-slate-900">Email Spoofing Detection System</h1>
                <p class="mt-2 text-md sm:text-lg text-slate-600">Powered by Python & Flask</p>
            </header>
            <main>
                <div class="bg-white p-6 rounded-2xl shadow-lg border border-slate-200">
                    <h2 class="text-xl font-semibold mb-4 text-slate-800">1. Paste Raw Email Headers</h2>
                    <textarea id="emailHeaders" class="w-full h-64 p-4 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 bg-slate-50" placeholder="Paste the full raw email headers here..."></textarea>
                    <div class="mt-5 flex flex-col sm:flex-row gap-4 items-center">
                        <button id="checkButton" class="w-full sm:w-auto bg-blue-600 text-white font-bold py-3 px-8 rounded-lg hover:bg-blue-700 active:bg-blue-800 transition-all duration-300 flex items-center justify-center gap-2 shadow-md hover:shadow-lg">
                            <span class="text-lg">Analyze Email</span>
                        </button>
                        <div id="errorMessage" class="text-red-600 font-medium"></div>
                    </div>
                </div>
                <div id="resultsSection" class="mt-10" style="display: none;">
                    <h2 class="text-2xl font-bold mb-5 text-slate-800 text-center">2. Analysis Report</h2>
                    <div id="verdictCard" class="bg-white p-6 rounded-2xl shadow-lg border mb-6 text-center transition-all duration-500">
                        <h3 class="text-xl font-semibold mb-2" id="verdictTitle">Overall Verdict</h3>
                        <div id="verdictResult" class="text-2xl md:text-3xl font-bold"></div>
                        <p id="verdictDescription" class="text-slate-600 mt-2 max-w-2xl mx-auto"></p>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div id="spfCard" class="result-card bg-white p-6 rounded-2xl shadow-lg border">
                            <h3 class="text-lg font-semibold mb-3 flex items-center gap-2 text-slate-700">SPF Check</h3>
                            <div id="spfResult" class="flex items-center gap-3 text-lg"></div>
                            <p id="spfDetail" class="text-sm text-slate-500 mt-2 h-16"></p>
                        </div>
                        <div id="dkimCard" class="result-card bg-white p-6 rounded-2xl shadow-lg border">
                            <h3 class="text-lg font-semibold mb-3 flex items-center gap-2 text-slate-700">DKIM Check</h3>
                            <div id="dkimResult" class="flex items-center gap-3 text-lg"></div>
                            <p id="dkimDetail" class="text-sm text-slate-500 mt-2 h-16"></p>
                        </div>
                        <div id="dmarcCard" class="result-card bg-white p-6 rounded-2xl shadow-lg border">
                            <h3 class="text-lg font-semibold mb-3 flex items-center gap-2 text-slate-700">DMARC Check</h3>
                            <div id="dmarcResult" class="flex items-center gap-3 text-lg"></div>
                            <p id="dmarcDetail" class="text-sm text-slate-500 mt-2 h-16"></p>
                        </div>
                    </div>
                </div>
            </main>
            <footer class="text-center mt-12 py-6 border-t border-slate-200">
                <p class="text-slate-500">Project by Team 8 (2025) | Interactive version created for demonstration.</p>
            </footer>
        </div>
        <script>
            const checkButton = document.getElementById('checkButton');
            const emailHeadersInput = document.getElementById('emailHeaders');
            const resultsSection = document.getElementById('resultsSection');
            const errorMessage = document.getElementById('errorMessage');
            const spfResultEl = document.getElementById('spfResult');
            const spfDetailEl = document.getElementById('spfDetail');
            const dkimResultEl = document.getElementById('dkimResult');
            const dkimDetailEl = document.getElementById('dkimDetail');
            const dmarcResultEl = document.getElementById('dmarcResult');
            const dmarcDetailEl = document.getElementById('dmarcDetail');
            const verdictCardEl = document.getElementById('verdictCard');
            const verdictResultEl = document.getElementById('verdictResult');
            const verdictDescriptionEl = document.getElementById('verdictDescription');

            const ICONS = {
                pass: `<span class="w-6 h-6 rounded-full bg-green-100 flex items-center justify-center"><svg class="w-4 h-4 text-green-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg></span>`,
                fail: `<span class="w-6 h-6 rounded-full bg-red-100 flex items-center justify-center"><svg class="w-4 h-4 text-red-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg></span>`,
                neutral: `<span class="w-6 h-6 rounded-full bg-slate-100 flex items-center justify-center"><svg class="w-4 h-4 text-slate-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9 9a1 1 0 000 2h2a1 1 0 100-2H9z" clip-rule="evenodd"></path></svg></span>`,
                loader: `<div class="loader"></div>`
            };

            function setResult(element, status, text) {
                element.innerHTML = `${ICONS[status]} <span class="font-semibold">${text}</span>`;
            }

            function resetUI() {
                resultsSection.style.display = 'none';
                errorMessage.textContent = '';
                setResult(spfResultEl, 'loader', 'Awaiting Analysis...');
                spfDetailEl.textContent = '';
                setResult(dkimResultEl, 'loader', 'Awaiting Analysis...');
                dkimDetailEl.textContent = '';
                setResult(dmarcResultEl, 'loader', 'Awaiting Analysis...');
                dmarcDetailEl.textContent = '';
            }

            function calculateVerdict(spf, dkim, dmarc) {
                verdictCardEl.className = 'bg-white p-6 rounded-2xl shadow-lg border mb-6 text-center transition-all duration-500';
                if (dmarc === 'pass' && (spf === 'pass' || dkim === 'pass')) {
                    verdictResultEl.textContent = 'Likely Legitimate';
                    verdictDescriptionEl.textContent = 'The email passes key authentication checks (DMARC alignment with SPF or DKIM). It is very likely from a legitimate source.';
                    verdictCardEl.className += ' bg-green-50 border-green-200';
                    verdictResultEl.className = 'text-green-700';
                } else if (spf === 'pass' && dkim === 'pass') {
                    verdictResultEl.textContent = 'Potentially Legitimate';
                    verdictDescriptionEl.textContent = 'The email passes both SPF and DKIM, but lacks a DMARC policy for enforcement. It is probably legitimate.';
                    verdictCardEl.className += ' bg-green-50 border-green-200';
                    verdictResultEl.className = 'text-green-700';
                } else if (spf === 'fail' && dkim !== 'pass') {
                    verdictResultEl.textContent = 'High Risk of Spoofing';
                    verdictDescriptionEl.textContent = 'The email fails SPF and does not have a valid DKIM signature. There is a high probability that this is a spoofed email.';
                    verdictCardEl.className += ' bg-red-50 border-red-200';
                    verdictResultEl.className = 'text-red-700';
                } else {
                    verdictResultEl.textContent = 'Suspicious';
                    verdictDescriptionEl.textContent = 'The email fails one or more key authentication checks. Proceed with caution as this could be a spoofing attempt.';
                    verdictCardEl.className += ' bg-yellow-50 border-yellow-200';
                    verdictResultEl.className = 'text-yellow-700';
                }
            }

            async function handleCheck() {
                const headers = emailHeadersInput.value.trim();
                if (!headers) {
                    errorMessage.textContent = 'Please paste email headers to begin analysis.';
                    return;
                }
                resetUI();
                resultsSection.style.display = 'block';

                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ headers: headers })
                    });
                    if (!response.ok) {
                        throw new Error('Server error during analysis.');
                    }
                    const data = await response.json();

                    if(data.error) {
                        errorMessage.textContent = data.error;
                        resultsSection.style.display = 'none';
                        return;
                    }

                    setResult(spfResultEl, data.spf.status, data.spf.status.charAt(0).toUpperCase() + data.spf.status.slice(1));
                    spfDetailEl.textContent = data.spf.detail;

                    setResult(dkimResultEl, data.dkim.status, data.dkim.status.charAt(0).toUpperCase() + data.dkim.status.slice(1));
                    dkimDetailEl.textContent = data.dkim.detail;

                    setResult(dmarcResultEl, data.dmarc.status, data.dmarc.status.charAt(0).toUpperCase() + data.dmarc.status.slice(1));
                    dmarcDetailEl.textContent = data.dmarc.detail;
                    
                    calculateVerdict(data.spf.status, data.dkim.status, data.dmarc.status);

                } catch (error) {
                    errorMessage.textContent = 'Failed to connect to the server. Please try again.';
                    resultsSection.style.display = 'none';
                }
            }
            checkButton.addEventListener('click', handleCheck);
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Receives email headers, performs checks, and returns a JSON response.
    """
    data = request.get_json()
    headers = data.get('headers', '')

    if not headers:
        return jsonify({"error": "Headers are empty."}), 400

    parsed = parse_headers(headers)
    from_domain = parsed.get("from_domain")

    if not from_domain:
        return jsonify({"error": "Could not find a valid 'From' address in the headers."}), 400

    spf_result = check_spf(from_domain)
    dkim_result = check_dkim(parsed.get("dkim_selector"), parsed.get("dkim_domain") or from_domain)
    dmarc_result = check_dmarc(from_domain)

    return jsonify({
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result
    })

if __name__ == '__main__':
    # Runs the Flask application
    # In a production environment, use a proper WSGI server like Gunicorn or uWSGI
    app.run(debug=True, port=5001)

