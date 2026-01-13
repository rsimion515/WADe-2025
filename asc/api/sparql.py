"""
SPARQL endpoint API routes.

Provides a SPARQL endpoint for querying security vulnerability data
with support for multiple RDF serialization formats.
"""

from typing import Optional
import html
from fastapi import APIRouter, Query, HTTPException, Response
from fastapi.responses import JSONResponse, HTMLResponse

from ..services.sparql_service import get_sparql_service, EXAMPLE_QUERIES
from ..config import get_settings
from urllib.parse import quote

router = APIRouter(prefix="/sparql", tags=["sparql"])
settings = get_settings()


@router.get("")
@router.post("")
async def execute_sparql(
    query: Optional[str] = Query(None, description="SPARQL query to execute"),
    format: str = Query("json", regex="^(json|xml|turtle|csv|html)$"),
):
    """
    Execute a SPARQL query against the security vulnerability RDF store.
    
    Supports:
    - SELECT queries: Returns variable bindings
    - ASK queries: Returns boolean result
    - CONSTRUCT queries: Returns RDF graph
    
    Output formats:
    - json: SPARQL JSON results
    - xml: SPARQL XML results
    - turtle: RDF Turtle (for CONSTRUCT)
    - csv: CSV format
    - html: HTML table view
    """
    # If no query, return documentation
    if not query:
        return HTMLResponse(content=get_sparql_documentation())
    
    sparql = get_sparql_service()
    
    try:
        results = sparql.execute_query(query)
        
        if format == "html":
            return HTMLResponse(content=results_to_html(results, query))
        
        if format == "csv":
            csv_content = results_to_csv(results)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=results.csv"}
            )
        
        if format == "xml":
            xml_content = results_to_xml(results)
            return Response(content=xml_content, media_type="application/sparql-results+xml")
        
        if format == "turtle":
            # For CONSTRUCT queries that return a graph
            if results and "graph" in results[0]:
                return Response(
                    content=results[0]["graph"],
                    media_type="text/turtle"
                )
            # Otherwise return JSON
            return JSONResponse(content={"results": results})
        
        # Default JSON
        return JSONResponse(content={
            "head": {"vars": list(results[0].keys()) if results else []},
            "results": {
                "bindings": [
                    {k: {"type": "literal", "value": v} for k, v in r.items() if v}
                    for r in results
                ]
            }
        })
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query execution failed: {e}")


@router.get("/examples")
async def get_example_queries():
    """Get example SPARQL queries."""
    return {
        "examples": [
            {"name": name, "query": query.strip()}
            for name, query in EXAMPLE_QUERIES.items()
        ]
    }


@router.get("/stats")
async def get_graph_statistics():
    """Get statistics about the RDF graph."""
    sparql = get_sparql_service()
    return sparql.get_statistics()


@router.get("/ontology")
async def get_ontology(format: str = Query("turtle", regex="^(turtle|xml|jsonld)$")):
    """Get the ASC ontology definition."""
    sparql = get_sparql_service()
    
    content = sparql.serialize(format=format if format != "jsonld" else "json-ld")
    
    media_types = {
        "turtle": "text/turtle",
        "xml": "application/rdf+xml",
        "jsonld": "application/ld+json",
    }
    
    return Response(content=content, media_type=media_types[format])


def results_to_html(results: list, query: str) -> str:
    """Convert SPARQL results to HTML table."""
    if not results:
        return get_empty_results_html(query)
    
    # Check for graph result (CONSTRUCT query)
    if "graph" in results[0]:
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>SPARQL CONSTRUCT Result</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #eee; padding: 2rem; }}
        pre {{ background: #0f0f1a; padding: 1.5rem; border-radius: 8px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>CONSTRUCT Query Result</h1>
    <pre>{results[0]["graph"]}</pre>
</body>
</html>'''
    
    # Build table headers
    headers = list(results[0].keys())
    header_html = "".join(f"<th>{h}</th>" for h in headers)
    
    # Build table rows
    rows_html = ""
    for row in results:
        cells = "".join(f"<td>{row.get(h, '')}</td>" for h in headers)
        rows_html += f"<tr>{cells}</tr>"
    
    return f'''<!DOCTYPE html>
<html>
<head>
    <title>SPARQL Query Results</title>
    <style>
        :root {{ --bg: #0f0f1a; --surface: #1a1a2e; --border: #2a2a4e; --text: #eee; --accent: #f43f5e; }}
        body {{ font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); padding: 2rem; margin: 0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: var(--accent); margin-bottom: 1rem; }}
        .query-box {{ background: var(--surface); padding: 1rem; border-radius: 8px; margin-bottom: 2rem; font-family: monospace; white-space: pre-wrap; font-size: 0.9rem; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }}
        th {{ background: var(--border); padding: 1rem; text-align: left; font-weight: 600; }}
        td {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); word-break: break-word; }}
        tr:hover td {{ background: rgba(244, 63, 94, 0.1); }}
        .count {{ color: #888; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SPARQL Query Results</h1>
        <div class="query-box">{html.escape(query)}</div>
        <p class="count">{len(results)} results</p>
        <table>
            <thead><tr>{header_html}</tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
</body>
</html>'''


def get_empty_results_html(query: str) -> str:
    """HTML for empty results."""
    return f'''<!DOCTYPE html>
<html>
<head>
    <title>SPARQL Query - No Results</title>
    <style>
        body {{ font-family: 'Inter', sans-serif; background: #0f0f1a; color: #eee; padding: 2rem; }}
        .container {{ max-width: 800px; margin: 0 auto; text-align: center; padding: 4rem 2rem; }}
        h1 {{ color: #f43f5e; }}
        .query {{ background: #1a1a2e; padding: 1rem; border-radius: 8px; font-family: monospace; text-align: left; margin: 2rem 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>No Results Found</h1>
        <p>Your query returned no results.</p>
        <div class="query">{html.escape(query)}</div>
        <p><a href="/sparql" style="color: #f43f5e;">Try another query</a></p>
    </div>
</body>
</html>'''


def results_to_csv(results: list) -> str:
    """Convert results to CSV format."""
    if not results:
        return ""
    
    headers = list(results[0].keys())
    lines = [",".join(headers)]
    
    for row in results:
        values = [f'"{row.get(h, "")}"' for h in headers]
        lines.append(",".join(values))
    
    return "\n".join(lines)


def results_to_xml(results: list) -> str:
    """Convert results to SPARQL XML format."""
    if not results:
        return '''<?xml version="1.0"?>
<sparql xmlns="http://www.w3.org/2005/sparql-results#">
  <head></head>
  <results></results>
</sparql>'''
    
    headers = list(results[0].keys())
    vars_xml = "".join(f'<variable name="{h}"/>' for h in headers)
    
    results_xml = ""
    for row in results:
        bindings = ""
        for h in headers:
            if row.get(h):
                bindings += f'<binding name="{h}"><literal>{row[h]}</literal></binding>'
        results_xml += f"<result>{bindings}</result>"
    
    return f'''<?xml version="1.0"?>
<sparql xmlns="http://www.w3.org/2005/sparql-results#">
  <head>{vars_xml}</head>
  <results>{results_xml}</results>
</sparql>'''


def get_sparql_documentation() -> str:
    """Return SPARQL endpoint documentation."""
    example_queries_html = ""
    for name, query in EXAMPLE_QUERIES.items():
        example_queries_html += f'''
        <div class="example">
            <h3>{name.replace("_", " ").title()}</h3>
            <pre>{html.escape(query.strip())}</pre>
            <a href="/sparql?query={quote(query.strip())}&format=html" 
               class="run-btn">Run Query</a>
        </div>
        '''
    
    return f'''<!DOCTYPE html>
<html>
<head>
    <title>ASC SPARQL Endpoint</title>
    <style>
        :root {{
            --bg: #0a0a10;
            --surface: #12121c;
            --surface-2: #1a1a28;
            --border: #252538;
            --text: #e8e8f0;
            --muted: #8080a0;
            --accent: #f43f5e;
            --accent-2: #a855f7;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 3rem 2rem; }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{ color: var(--muted); margin-bottom: 3rem; }}
        .section {{ 
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        .section h2 {{
            color: var(--accent);
            font-size: 1.2rem;
            margin-bottom: 1.5rem;
        }}
        form {{ display: flex; flex-direction: column; gap: 1rem; }}
        textarea {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            padding: 1rem;
            resize: vertical;
            min-height: 150px;
        }}
        textarea:focus {{ outline: none; border-color: var(--accent); }}
        .form-row {{ display: flex; gap: 1rem; align-items: center; }}
        select, button {{
            background: var(--surface-2);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            padding: 0.75rem 1rem;
            font-size: 0.9rem;
            cursor: pointer;
        }}
        button {{
            background: var(--accent);
            border-color: var(--accent);
            font-weight: 600;
        }}
        button:hover {{ opacity: 0.9; }}
        .example {{
            background: var(--surface-2);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        .example h3 {{ font-size: 1rem; margin-bottom: 1rem; }}
        .example pre {{
            background: var(--bg);
            padding: 1rem;
            border-radius: 6px;
            font-size: 0.8rem;
            overflow-x: auto;
            margin-bottom: 1rem;
        }}
        .run-btn {{
            color: var(--accent);
            text-decoration: none;
            font-size: 0.85rem;
        }}
        .namespaces {{
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--muted);
        }}
        .namespaces code {{ color: var(--accent-2); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔮 SPARQL Endpoint</h1>
            <p class="subtitle">Query the ASC Security Vulnerability Knowledge Graph</p>
        </header>
        
        <section class="section">
            <h2>Execute Query</h2>
            <form action="/sparql" method="get">
                <textarea name="query" placeholder="Enter your SPARQL query here...">PREFIX asc: <{settings.asc_namespace}>
PREFIX schema: <https://schema.org/>

SELECT ?exploit ?title ?severity
WHERE {{
    ?exploit a asc:WebExploit ;
             schema:name ?title ;
             asc:severity ?severity .
}}
LIMIT 10</textarea>
                <div class="form-row">
                    <select name="format">
                        <option value="html">HTML Table</option>
                        <option value="json">JSON</option>
                        <option value="xml">XML</option>
                        <option value="csv">CSV</option>
                        <option value="turtle">Turtle</option>
                    </select>
                    <button type="submit">Execute Query</button>
                </div>
            </form>
        </section>
        
        <section class="section">
            <h2>Available Namespaces</h2>
            <div class="namespaces">
                <p><code>asc:</code> {settings.asc_namespace}</p>
                <p><code>schema:</code> https://schema.org/</p>
                <p><code>data:</code> {settings.asc_data_namespace}</p>
                <p><code>cve:</code> https://cve.mitre.org/cgi-bin/cvename.cgi?name=</p>
                <p><code>cwe:</code> https://cwe.mitre.org/data/definitions/</p>
            </div>
        </section>
        
        <section class="section">
            <h2>Example Queries</h2>
            {example_queries_html}
        </section>
    </div>
</body>
</html>'''
