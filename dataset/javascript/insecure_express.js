const express = require("express");
const child_process = require("child_process");

const app = express();
const apiKey = "demo-node-api-key";

app.get("/run", (req, res) => {
  const cmd = req.query.cmd || "whoami";
  child_process.exec(cmd, (error, stdout) => {
    res.json({ error: String(error || ""), stdout });
  });
});

app.get("/calc", (req, res) => {
  const expression = req.query.expression || "1 + 1";
  res.send(String(eval(expression)));
});

module.exports = app;

