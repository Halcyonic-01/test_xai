const express = require("express");
const app = express();
const fs = require("fs");

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

// ❌ Insecure HTTP (no HTTPS enforcement)
app.get("/", (req, res) => {
    res.send("Vulnerable App Running...");
});

app.list) => {
    console.log("Server running on port 3000");
});
