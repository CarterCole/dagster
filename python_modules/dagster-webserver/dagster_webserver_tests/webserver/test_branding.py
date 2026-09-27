import mock
from dagster._core.instance import DagsterInstance
from dagster_webserver.webserver import DagsterWebserver
from starlette.testclient import TestClient

def test_branding_injection():
    instance = DagsterInstance.ephemeral()
    # Mock settings to include branding
    instance._settings["webserver"] = {
        "branding": {
            "css_override": "/tmp/test.css",
            "logo_url": "http://example.com/logo.png"
        }
    }
    
    process_context = mock.MagicMock()
    process_context.instance = instance
    process_context.create_request_context.return_value = mock.MagicMock()
    
    webserver = DagsterWebserver(process_context)
    # We need a proper app. DagsterWebserver creates routes.
    from starlette.applications import Starlette
    app = Starlette(routes=webserver.build_routes())
    client = TestClient(app)
    
    response = client.get("/")
    assert response.status_code == 200
    assert '<link rel="stylesheet" type="text/css" href="/api/branding.css" />' in response.text
    assert '"branding": {"logoUrl": "http://example.com/logo.png"}' in response.text

def test_api_branding_css_route():
    instance = DagsterInstance.ephemeral()
    instance._settings["webserver"] = {
        "branding": {
            "css_override": __file__ # Just use this file as a dummy CSS
        }
    }
    process_context = mock.MagicMock()
    process_context.instance = instance
    
    webserver = DagsterWebserver(process_context)
    app = Starlette(routes=webserver.build_routes())
    client = TestClient(app)
    
    response = client.get("/api/branding.css")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/css; charset=utf-8"
