import express from "express";

const app = express();

const port = process.env.PORT || 3000;

app.get("/", (_req, res) => {
  return res.send("Hello from API!");
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
