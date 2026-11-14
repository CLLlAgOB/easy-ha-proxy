// The real Russian catalogue, merged the way the server merges it, for the
// behaviour tests that check what the pages say in Russian.
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const CATALOGUES = path.join(__dirname, "../../docker/app/haproxy_admin/translations");

function russianCatalogue() {
  const messages = {};
  for (const name of fs.readdirSync(CATALOGUES, {recursive: true})) {
    if (!String(name).endsWith(".json")) continue;
    const data = JSON.parse(fs.readFileSync(path.join(CATALOGUES, String(name)), "utf8"));
    if (data.meta.code === "ru") Object.assign(messages, data.messages);
  }
  return messages;
}

// A label function that remembers every word it was asked for.
function recordingLabel() {
  const asked = new Set();
  const label = (key) => {
    asked.add(String(key));
    return String(key);
  };
  label.asked = asked;
  return label;
}

module.exports = {russianCatalogue, recordingLabel};
