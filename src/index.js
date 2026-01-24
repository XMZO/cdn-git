/* eslint-disable no-console */
/**
 * NOTE: 旧实现（维护模式）。当前部署与使用方式请看仓库根目录 README（部署文件在 `go/` 目录）。
 */
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
    (process.env.HAZUKI_DB_PATH || "").toString().trim() ||
    path.join(process.cwd(), "data", "hazuki.db");
  const masterKey = (process.env.HAZUKI_MASTER_KEY || "").toString();

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

  console.log("hazuki: database ready");
  console.log("hazuki: config ready");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
