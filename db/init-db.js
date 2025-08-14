import sqlite3 from "sqlite3";
import { open } from "sqlite";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dbPath = join(__dirname, "game.db");

(async () => {
  if (fs.existsSync(dbPath)) {
    console.log("db already exists at", dbPath);
  }

  const db = await open({ filename: dbPath, driver: sqlite3.Database });

  await db.exec(`
    DROP TABLE IF EXISTS devices;
    DROP TABLE IF EXISTS prizes;
    DROP TABLE IF EXISTS games;
    DROP TABLE IF EXISTS rounds;

    CREATE TABLE games (id INTEGER PRIMARY KEY, name TEXT);
    CREATE TABLE devices (id INTEGER PRIMARY KEY, game_id INTEGER, device_id TEXT UNIQUE, device_secret TEXT, role TEXT);
    CREATE TABLE prizes (id INTEGER PRIMARY KEY, game_id INTEGER, title TEXT, description TEXT, media TEXT);
    CREATE TABLE rounds (id INTEGER PRIMARY KEY, game_id INTEGER, prize_id INTEGER, started_at TEXT, announced_at TEXT, finished_at TEXT, operator_device TEXT, screen_device TEXT);
  `);

  for (let i = 1; i <= 9; i++) {
    const name = `Game ${i}`;
    const res = await db.run("INSERT INTO games (name) VALUES (?)", name);
    const gameId = res.lastID;
    const operatorDeviceId = `OP-${i}`;
    const screenDeviceId = `SC-${i}`;
    const operatorSecret = crypto.randomBytes(6).toString("hex");
    const screenSecret = crypto.randomBytes(6).toString("hex");
    await db.run(
      "INSERT INTO devices (game_id, device_id, device_secret, role) VALUES (?,?,?,?)",
      gameId,
      operatorDeviceId,
      operatorSecret,
      "operator"
    );
    await db.run(
      "INSERT INTO devices (game_id, device_id, device_secret, role) VALUES (?,?,?,?)",
      gameId,
      screenDeviceId,
      screenSecret,
      "screen"
    );

    const prizes = [
      { title: `Prize A${i}`, desc: "Small toy", media: "/media/sample1.jpg" },
      { title: `Prize B${i}`, desc: "Medium gift", media: "/media/sample2.mp4" },
      { title: `Prize C${i}`, desc: "Grand prize", media: "" },
    ];
    for (const p of prizes) {
      await db.run(
        "INSERT INTO prizes (game_id, title, description, media) VALUES (?,?,?,?)",
        gameId,
        p.title,
        p.desc,
        p.media
      );
    }

    console.log(`Game ${gameId} seeded: operatorDevice=${operatorDeviceId}:${operatorSecret}  screenDevice=${screenDeviceId}:${screenSecret}`);
  }

  console.log("DB initialization complete. DB at:", dbPath);
  process.exit(0);
})();
