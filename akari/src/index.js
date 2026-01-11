/* eslint-disable no-console */
"use strict";

require("dotenv").config();

const path = require("node:path");

const { openDatabase } = require("./storage/db");
const { migrate } = require("./storage/migrate");
const { createCryptoContext } = require("./storage/crypto");
const { ConfigStore } = require("./storage/configStore");
const { bootstrapAdminIfNeeded, startAdminServer } = require("./admin/server");
const { startCdnjsServer } = require("./proxies/cdnjs");
const { startGitServer } = require("./proxies/git");
const { startTorcherinoServer } = require("./proxies/torcherino");

async function main() {
  const dbPath =
    (process.env.AKARI_DB_PATH || "").toString().trim() ||
    path.join(process.cwd(), "data", "akari.db");
  const masterKey = (process.env.AKARI_MASTER_KEY || "").toString();

  const db = openDatabase(dbPath);
  migrate(db);

  const cryptoContext = createCryptoContext({ db, masterKey });
  const configStore = new ConfigStore({ db, cryptoContext });
  configStore.initFromEnvironment(process.env);

  bootstrapAdminIfNeeded({ db });
  startAdminServer({ db, configStore });
  startTorcherinoServer({ configStore });
  startCdnjsServer({ configStore });
  startGitServer({ configStore });

  console.log("akari: database ready");
  console.log("akari: config ready");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
