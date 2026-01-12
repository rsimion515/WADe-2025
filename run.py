#!/usr/bin/env python3
"""
ASC - Web Application Security Control

Quick start script for running the application.
"""

import uvicorn
from asc.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🛡️  ASC - Web Application Security Control                  ║
    ║                                                               ║
    ║   Real-time security vulnerability intelligence               ║
    ║   with semantic web technologies                              ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"   Starting server at http://{settings.host}:{settings.port}")
    print(f"   API Docs: http://{settings.host}:{settings.port}/api/docs")
    print(f"   SPARQL: http://{settings.host}:{settings.port}/sparql")
    print(f"   WebSub: http://{settings.host}:{settings.port}/websub")
    print()
    
    uvicorn.run(
        "asc.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info",
    )
