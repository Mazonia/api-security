"""Unit & Integration Tests for MazAPI App Surface."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("api-security-project"))
from app_surface.scanner import AppSurfaceScanner
from app_surface.openapi_generator import OpenAPIGenerator
from app_surface.diff_engine import DiffEngine
from app_surface.parsers.python_parser import PythonRouteParser
from app_surface.parsers.node_parser import NodeRouteParser
from app_surface.parsers.java_parser import JavaRouteParser
from app_surface.parsers.dotnet_parser import DotnetRouteParser
from app_surface.parsers.go_parser import GoRouteParser
from app_surface.parsers.php_parser import PhpRouteParser


class TestAppSurface(unittest.TestCase):
    def test_python_fastapi_and_flask_parser(self):
        code = '''
from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"id": user_id}

@app.post("/admin/system/reset")
async def reset_system():
    return {"status": "ok"}
'''
        parser = PythonRouteParser()
        eps = parser.parse_file("test.py", code)
        self.assertEqual(len(eps), 2)
        get_ep = [e for e in eps if e["method"] == "GET"][0]
        self.assertEqual(get_ep["path"], "/users/{user_id}")
        self.assertTrue(get_ep["is_bola_candidate"])

        admin_ep = [e for e in eps if e["method"] == "POST"][0]
        self.assertEqual(admin_ep["path"], "/admin/system/reset")
        self.assertTrue(admin_ep["is_bfla_candidate"])

    def test_node_express_parser(self):
        code = '''
const express = require('express');
const app = express();

app.get('/api/orders/:orderId', (req, res) => {
    res.json({ id: req.params.orderId });
});

app.delete('/admin/delete-database', (req, res) => {
    res.send("done");
});
'''
        parser = NodeRouteParser()
        eps = parser.parse_file("server.js", code)
        self.assertEqual(len(eps), 2)
        order_ep = [e for e in eps if e["method"] == "GET"][0]
        self.assertEqual(order_ep["path"], "/api/orders/:orderId")
        self.assertTrue(order_ep["is_bola_candidate"])

    def test_java_spring_parser(self):
        code = '''
@RestController
@RequestMapping("/api/v1/customers")
public class CustomerController {
    @GetMapping("/{id}")
    public Customer getCustomer(@PathVariable Long id) { return null; }
    
    @PostMapping("/admin/purge")
    public void purge() {}
}
'''
        parser = JavaRouteParser()
        eps = parser.parse_file("CustomerController.java", code)
        self.assertEqual(len(eps), 2)
        self.assertTrue(any(e["path"] == "/api/v1/customers/{id}" for e in eps))

    def test_dotnet_parser(self):
        code = '''
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase {
    [HttpGet("{id}")]
    public IActionResult GetUser(int id) => Ok();
}
'''
        parser = DotnetRouteParser()
        eps = parser.parse_file("UsersController.cs", code)
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["path"], "/api/controller/{id}")

    def test_go_gin_parser(self):
        code = '''
func SetupRouter() *gin.Engine {
    r := gin.Default()
    r.GET("/api/accounts/:accountId", GetAccount)
    r.POST("/admin/promote", PromoteUser)
    return r
}
'''
        parser = GoRouteParser()
        eps = parser.parse_file("main.go", code)
        self.assertEqual(len(eps), 2)
        self.assertTrue(any(e["path"] == "/api/accounts/:accountId" for e in eps))

    def test_php_laravel_parser(self):
        code = '''
Route::get('/users/{id}', [UserController::class, 'show']);
Route::post('/admin/settings', [AdminController::class, 'save']);
'''
        parser = PhpRouteParser()
        eps = parser.parse_file("routes/web.php", code)
        self.assertEqual(len(eps), 2)
        self.assertTrue(any(e["path"] == "/users/{id}" for e in eps))

    def test_openapi_spec_generation(self):
        endpoints = [
            {"method": "GET", "path": "/users/{id}", "has_auth": True, "framework": "FastAPI"},
            {"method": "POST", "path": "/orders", "has_auth": True, "framework": "FastAPI"}
        ]
        gen = OpenAPIGenerator()
        spec = gen.generate_spec(endpoints)
        self.assertEqual(spec["openapi"], "3.0.3")
        self.assertIn("/users/{id}", spec["paths"])
        self.assertIn("/orders", spec["paths"])
        self.assertIn("get", spec["paths"]["/users/{id}"])
        self.assertIn("post", spec["paths"]["/orders"])

    def test_diff_engine(self):
        base = [{"method": "GET", "path": "/users", "has_auth": True, "risk_level": "LOW"}]
        curr = [
            {"method": "GET", "path": "/users", "has_auth": True, "risk_level": "LOW"},
            {"method": "POST", "path": "/admin/backdoor", "has_auth": False, "risk_level": "HIGH"}
        ]
        diff_eng = DiffEngine()
        diff = diff_eng.compute_diff(curr, base)
        self.assertEqual(diff["added_count"], 1)
        self.assertEqual(diff["added"][0]["path"], "/admin/backdoor")


if __name__ == "__main__":
    unittest.main()
