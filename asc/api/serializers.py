"""
Data serializers for multiple output formats.

Provides serialization to JSON-LD (schema.org) and HTML+RDFa formats
for exploit data.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import Request

from ..models.exploit import Exploit
from ..config import get_settings

settings = get_settings()


def exploit_to_jsonld(exploit: Exploit) -> Dict[str, Any]:
    """
    Convert exploit to JSON-LD format using schema.org vocabulary.
    
    Uses SoftwareApplication and SoftwareSourceCode schemas.
    """
    jsonld = {
        "@context": {
            "@vocab": "https://schema.org/",
            "asc": settings.asc_namespace,
            "cve": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
            "cwe": "https://cwe.mitre.org/data/definitions/",
        },
        "@type": ["SoftwareApplication", "asc:WebExploit"],
        "@id": f"{settings.asc_data_namespace}exploit/{exploit.id}",
        "name": exploit.title,
        "description": exploit.description,
    }
    
    # Software information
    if exploit.software_name:
        jsonld["softwareRequirements"] = exploit.software_name
    
    if exploit.software_version:
        jsonld["softwareVersion"] = exploit.software_version
    
    if exploit.platform:
        jsonld["operatingSystem"] = exploit.platform
    
    # Author
    if exploit.author:
        jsonld["author"] = {
            "@type": "Person",
            "name": exploit.author,
        }
    
    # Vendor/Provider
    if exploit.vendor:
        jsonld["provider"] = {
            "@type": "Organization",
            "name": exploit.vendor,
        }
    
    # Dates
    if exploit.published_date:
        jsonld["datePublished"] = exploit.published_date.isoformat()
    
    if exploit.created_at:
        jsonld["dateCreated"] = exploit.created_at.isoformat()
    
    # URLs
    if exploit.source_url:
        jsonld["url"] = exploit.source_url
    
    # Security-specific information (using asc namespace)
    jsonld["asc:severity"] = exploit.severity
    jsonld["asc:exploitType"] = exploit.exploit_type
    jsonld["asc:softwareType"] = exploit.software_type
    jsonld["asc:platform"] = exploit.platform
    
    # CVE reference
    if exploit.cve_id:
        jsonld["asc:cveId"] = {
            "@id": f"cve:{exploit.cve_id}",
            "@type": "asc:Vulnerability",
            "name": exploit.cve_id,
        }
    
    # CVSS Score
    if exploit.cvss_score:
        jsonld["asc:cvssScore"] = exploit.cvss_score
    
    # Solutions and mitigations
    if exploit.solution or exploit.mitigation:
        jsonld["asc:securityAdvisory"] = {
            "@type": "asc:SecurityAdvisory",
        }
        if exploit.solution:
            jsonld["asc:securityAdvisory"]["asc:solution"] = exploit.solution
        if exploit.mitigation:
            jsonld["asc:securityAdvisory"]["asc:mitigation"] = exploit.mitigation
    
    # Proof of concept as SoftwareSourceCode
    if exploit.exploit_code or exploit.proof_of_concept:
        poc_code = exploit.proof_of_concept or exploit.exploit_code
        jsonld["asc:proofOfConcept"] = {
            "@type": "SoftwareSourceCode",
            "codeRepository": exploit.source_url,
            "programmingLanguage": _detect_language(poc_code),
            "text": poc_code[:5000] if poc_code else None,  # Limit size
        }
    
    return jsonld


def exploits_list_to_jsonld(
    exploits: List[Exploit],
    page: int,
    page_size: int,
    total: int,
) -> Dict[str, Any]:
    """Convert list of exploits to JSON-LD format."""
    return {
        "@context": {
            "@vocab": "https://schema.org/",
            "asc": settings.asc_namespace,
            "hydra": "http://www.w3.org/ns/hydra/core#",
        },
        "@type": "ItemList",
        "hydra:totalItems": total,
        "hydra:pageIndex": page,
        "hydra:itemsPerPage": page_size,
        "numberOfItems": len(exploits),
        "itemListElement": [
            {
                "@type": "ListItem",
                "position": i + 1 + (page - 1) * page_size,
                "item": exploit_to_jsonld(exploit),
            }
            for i, exploit in enumerate(exploits)
        ],
    }


def exploit_to_rdfa_html(exploit: Exploit, request: Request) -> str:
    """
    Convert exploit to HTML with RDFa semantic markup.
    """
    base_url = str(request.base_url).rstrip("/")
    exploit_url = f"{base_url}/api/exploits/{exploit.id}"
    
    # Build CVE link if available
    cve_html = ""
    if exploit.cve_id:
        cve_html = f'''
        <div class="info-item" property="asc:cveId" resource="https://cve.mitre.org/cgi-bin/cvename.cgi?name={exploit.cve_id}">
            <span class="label">CVE ID:</span>
            <a href="https://nvd.nist.gov/vuln/detail/{exploit.cve_id}" target="_blank">{exploit.cve_id}</a>
        </div>
        '''
    
    # Build solution section if available
    solution_html = ""
    if exploit.solution or exploit.mitigation:
        solution_html = f'''
        <section class="section" typeof="asc:SecurityAdvisory">
            <h2>🛠️ Remediation</h2>
            {"<div class='solution-item'><h3>Solution</h3><p property='asc:solution'>" + exploit.solution + "</p></div>" if exploit.solution else ""}
            {"<div class='solution-item'><h3>Mitigation</h3><p property='asc:mitigation'>" + exploit.mitigation + "</p></div>" if exploit.mitigation else ""}
        </section>
        '''
    
    # Build PoC section if available
    poc_html = ""
    if exploit.exploit_code or exploit.proof_of_concept:
        poc_code = exploit.proof_of_concept or exploit.exploit_code
        poc_html = f'''
        <section class="section" typeof="SoftwareSourceCode" property="asc:proofOfConcept">
            <h2>💻 Proof of Concept</h2>
            <pre property="text"><code>{_escape_html(poc_code[:3000])}</code></pre>
        </section>
        '''
    
    # Determine severity class
    severity_class = f"severity-{exploit.severity or 'unknown'}"
    
    return f'''<!DOCTYPE html>
<html lang="en" prefix="schema: https://schema.org/ asc: {settings.asc_namespace} dcterms: http://purl.org/dc/terms/">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{_escape_html(exploit.title)} - ASC Security Alert</title>
    <meta name="description" content="{_escape_html((exploit.description or '')[:160])}">
    
    <!-- Linked Data -->
    <link rel="alternate" type="application/ld+json" href="{exploit_url}?format=jsonld">
    <link rel="alternate" type="text/turtle" href="{exploit_url}?format=turtle">
    <link rel="alternate" type="application/rdf+xml" href="{exploit_url}?format=rdf">
    
    <!-- WebSub Discovery -->
    <link rel="hub" href="{base_url}/websub/hub">
    <link rel="self" href="{exploit_url}">
    
    <style>
        :root {{
            --bg: #0c0c12;
            --surface: #14141e;
            --surface-2: #1a1a26;
            --border: #252534;
            --text: #e8e8ec;
            --muted: #8888a0;
            --accent: #f43f5e;
            --accent-2: #a855f7;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #3b82f6;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.7;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }}
        
        .breadcrumb {{
            color: var(--muted);
            font-size: 0.85rem;
            margin-bottom: 2rem;
        }}
        
        .breadcrumb a {{
            color: var(--accent);
            text-decoration: none;
        }}
        
        header {{
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }}
        
        h1 {{
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            line-height: 1.3;
        }}
        
        .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
        }}
        
        .tag {{
            font-size: 0.8rem;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            background: var(--surface-2);
            font-weight: 500;
        }}
        
        .severity-critical {{ background: var(--critical); color: white; }}
        .severity-high {{ background: var(--high); color: black; }}
        .severity-medium {{ background: var(--medium); color: black; }}
        .severity-low {{ background: var(--low); color: black; }}
        
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.75rem;
            margin-bottom: 1.5rem;
        }}
        
        .section h2 {{
            font-size: 1.1rem;
            margin-bottom: 1.25rem;
            color: var(--accent);
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .info-item {{
            padding: 1rem;
            background: var(--surface-2);
            border-radius: 8px;
        }}
        
        .info-item .label {{
            display: block;
            font-size: 0.75rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        
        .info-item a {{
            color: var(--accent);
            text-decoration: none;
        }}
        
        .description {{
            color: var(--text);
            font-size: 1rem;
        }}
        
        .solution-item {{
            padding: 1.25rem;
            background: var(--surface-2);
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 3px solid var(--low);
        }}
        
        .solution-item:last-child {{ margin-bottom: 0; }}
        
        .solution-item h3 {{
            font-size: 0.9rem;
            margin-bottom: 0.75rem;
            color: var(--low);
        }}
        
        pre {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            overflow-x: auto;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
        }}
        
        code {{
            color: #e879f9;
        }}
        
        .formats {{
            display: flex;
            gap: 0.75rem;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }}
        
        .formats a {{
            font-size: 0.8rem;
            color: var(--muted);
            text-decoration: none;
            padding: 0.4rem 0.8rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            transition: all 0.2s;
        }}
        
        .formats a:hover {{
            border-color: var(--accent);
            color: var(--accent);
        }}
    </style>
</head>
<body>
    <div class="container" vocab="https://schema.org/" typeof="SoftwareApplication" resource="{exploit_url}">
        <nav class="breadcrumb">
            <a href="{base_url}/">Home</a> / 
            <a href="{base_url}/api/exploits?format=html">Exploits</a> / 
            {exploit.id}
        </nav>
        
        <header>
            <h1 property="name">{_escape_html(exploit.title)}</h1>
            <div class="meta">
                <span class="tag {severity_class}" property="asc:severity">{exploit.severity or 'Unknown'} Severity</span>
                <span class="tag" property="asc:platform">{exploit.platform or 'Unknown'}</span>
                <span class="tag" property="asc:exploitType">{exploit.exploit_type or 'Unknown'}</span>
                <span class="tag" property="asc:softwareType">{exploit.software_type or 'Unknown'}</span>
            </div>
        </header>
        
        <main>
            <section class="section">
                <h2>📋 Overview</h2>
                <p class="description" property="description">{_escape_html(exploit.description or 'No description available.')}</p>
            </section>
            
            <section class="section">
                <h2>🎯 Affected Software</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="label">Software</span>
                        <span property="softwareRequirements">{_escape_html(exploit.software_name or 'Unknown')}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Version</span>
                        <span property="softwareVersion">{_escape_html(exploit.software_version or 'Unknown')}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Vendor</span>
                        <span property="provider" typeof="Organization">
                            <span property="name">{_escape_html(exploit.vendor or 'Unknown')}</span>
                        </span>
                    </div>
                    {cve_html}
                    {"<div class='info-item'><span class='label'>CVSS Score</span><span property='asc:cvssScore'>" + exploit.cvss_score + "</span></div>" if exploit.cvss_score else ""}
                </div>
            </section>
            
            {solution_html}
            {poc_html}
            
            <div class="formats">
                <span style="color: var(--muted); font-size: 0.8rem;">Export:</span>
                <a href="{exploit_url}?format=jsonld">JSON-LD</a>
                <a href="{exploit_url}?format=turtle">Turtle</a>
                <a href="{exploit_url}?format=rdf">RDF/XML</a>
                <a href="{exploit_url}">JSON</a>
            </div>
        </main>
    </div>
</body>
</html>'''


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _detect_language(code: str) -> str:
    """Detect programming language from code."""
    if not code:
        return "text"
    
    code_lower = code.lower()
    
    if "<?php" in code_lower or "<?=" in code_lower:
        return "PHP"
    if "import " in code and "def " in code:
        return "Python"
    if "function " in code and "{" in code:
        if "<%@" in code:
            return "ASP"
        return "JavaScript"
    if "<script" in code_lower:
        return "HTML"
    if "SELECT " in code.upper() or "INSERT " in code.upper():
        return "SQL"
    if "curl " in code_lower or "wget " in code_lower:
        return "Bash"
    
    return "text"
