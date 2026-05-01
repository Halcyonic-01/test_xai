const express = require("express");
// Demo branch change: added a comment only.
const app = express();
const fs = require("fs");
const http = require("http");
const https = require("https");

// ❌ Unsafe body parsing used by multiple intentionally vulnerable routes
app.use(express.json({ limit: "10mb" }));

// Demo change: trigger PR scan workflow
// ❌ Hardcoded credentials (SECRET LEAK)
const DB_PASSWORD = "Xai_21";
const API_KEY = "12345-SECRET-API-KEY";

// ❌ No input validation (Injection risk)
app.get("/read-file", (req, res) => {
    const filename = req.query.file;

    // ❌ Path Traversal vulnerability
    fs.readFile(filename, "utf8", (err, data) => {
        if (err) {
            return res.send("Error reading file");
        }
        res.send(data);
    });
});

// ❌ Command Injection
const { exec } = require("child_process");
app.get("/run", (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd, (err, stdout, stderr) => {
        if (err) {
            return res.send("Error executing command");
        }
        res.send(stdout);
    });
});

// ❌ Remote Code Execution via eval
app.get("/eval", (req, res) => {
    const code = String(req.query.code || "");
    try {
        // eslint-disable-next-line no-eval
        const result = eval(code);
        res.send(String(result));
    } catch (e) {
        res.status(500).send(String(e));
    }
});

// ❌ Reflected XSS
app.get("/xss", (req, res) => {
    const q = String(req.query.q || "");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<h1>Search</h1><div>You searched for: ${q}</div>`);
});

// ❌ SSRF (fetch arbitrary URL, including internal metadata endpoints)
app.get("/fetch", (req, res) => {
    const url = String(req.query.url || "");
    const client = url.startsWith("https://") ? https : http;

    client
        .get(url, (r) => {
            let data = "";
            r.on("data", (chunk) => (data += chunk));
            r.on("end", () => res.send(data));
        })
        .on("error", () => res.status(500).send("Fetch failed"));
});

// ❌ Prototype Pollution / Mass Assignment
app.post("/merge", (req, res) => {
    const target = {};
    // Object.assign(target, req.body); // attacker-controlled keys (e.g., __proto__) get merged
    Object.assign(target, req.body); // attacker-controlled keys (e.g., __proto__) get merged
    res.json({ merged: target, polluted: {}.polluted });
});

// ❌ Insecure HTTP (no HTTPS enforcement)
app.get("/", (req, res) => {
    res.send("Vulnerable App Running...");
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
