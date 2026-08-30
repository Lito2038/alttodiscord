const express = require("express");
const cors = require("cors");
const http = require("http");
const WebSocket = require("ws");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "VoiceRoom-dev-secret-7fK2mQ9xL4pN8zR3";

app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// DATABASE
// ============================================================

const db = new Database(
    path.join(__dirname, "voiceroom.db")
);

db.pragma("journal_mode = WAL");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user TEXT NOT NULL,
        to_user TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,

        UNIQUE(from_user, to_user)
    );

    CREATE TABLE IF NOT EXISTS friendships (
        user_id TEXT NOT NULL,
        friend_id TEXT NOT NULL,

        PRIMARY KEY(user_id, friend_id)
    );
`);

// ============================================================
// AUTHENTICATION
// ============================================================

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username
        },
        JWT_SECRET,
        {
            expiresIn: "30d"
        }
    );
}

function authenticate(req, res, next) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Not logged in"
        });
    }

    const token = header.slice(7);

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({
            error: "Invalid or expired login"
        });
    }
}

// ============================================================
// BASIC ROUTES
// ============================================================

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );
});

app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        usersOnline: onlineUsers.size,
        database: "connected"
    });
});

// ============================================================
// CREATE ACCOUNT
// ============================================================

app.post("/api/register", async (req, res) => {
    try {
        let { username, password } = req.body;

        username = String(username || "")
            .trim()
            .toLowerCase();

        password = String(password || "");

        if (!/^[a-z0-9_]{3,20}$/.test(username)) {
            return res.status(400).json({
                error:
                    "Username must be 3-20 characters and use only letters, numbers, or underscores."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error:
                    "Password must be at least 8 characters."
            });
        }

        const existing = db
            .prepare(
                "SELECT id FROM users WHERE username = ?"
            )
            .get(username);

        if (existing) {
            return res.status(409).json({
                error: "That username is already taken."
            });
        }

        const id = crypto.randomUUID();

        const passwordHash =
            await bcrypt.hash(password, 12);

        db.prepare(`
            INSERT INTO users
            (id, username, password_hash, created_at)
            VALUES (?, ?, ?, ?)
        `).run(
            id,
            username,
            passwordHash,
            Date.now()
        );

        const user = {
            id,
            username
        };

        const token = createToken(user);

        res.json({
            user,
            token
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not create account."
        });
    }
});

// ============================================================
// LOGIN
// ============================================================

app.post("/api/login", async (req, res) => {
    try {
        let { username, password } = req.body;

        username = String(username || "")
            .trim()
            .toLowerCase();

        password = String(password || "");

        const user = db
            .prepare(`
                SELECT
                    id,
                    username,
                    password_hash
                FROM users
                WHERE username = ?
            `)
            .get(username);

        if (!user) {
            return res.status(401).json({
                error: "Incorrect username or password."
            });
        }

        const valid =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if (!valid) {
            return res.status(401).json({
                error: "Incorrect username or password."
            });
        }

        const publicUser = {
            id: user.id,
            username: user.username
        };

        const token =
            createToken(publicUser);

        res.json({
            user: publicUser,
            token
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not log in."
        });
    }
});

// ============================================================
// CURRENT ACCOUNT
// ============================================================

app.get(
    "/api/me",
    authenticate,
    (req, res) => {

        const user = db
            .prepare(`
                SELECT id, username, created_at
                FROM users
                WHERE id = ?
            `)
            .get(req.user.id);

        if (!user) {
            return res.status(404).json({
                error: "Account not found."
            });
        }

        res.json({
            user
        });
    }
);

// ============================================================
// FIND USER BY USERNAME
// ============================================================

app.get(
    "/api/users/:username",
    authenticate,
    (req, res) => {

        const username =
            String(req.params.username)
                .trim()
                .toLowerCase();

        const user = db
            .prepare(`
                SELECT id, username
                FROM users
                WHERE username = ?
            `)
            .get(username);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        res.json({
            user
        });
    }
);

// ============================================================
// SEND FRIEND REQUEST
// ============================================================

app.post(
    "/api/friends/request",
    authenticate,
    (req, res) => {

        const username =
            String(req.body.username || "")
                .trim()
                .toLowerCase();

        const target = db
            .prepare(`
                SELECT id, username
                FROM users
                WHERE username = ?
            `)
            .get(username);

        if (!target) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        if (target.id === req.user.id) {
            return res.status(400).json({
                error: "You cannot add yourself."
            });
        }

        const alreadyFriends =
            db.prepare(`
                SELECT 1
                FROM friendships
                WHERE user_id = ?
                AND friend_id = ?
            `).get(
                req.user.id,
                target.id
            );

        if (alreadyFriends) {
            return res.status(400).json({
                error: "You are already friends."
            });
        }

        const existing =
            db.prepare(`
                SELECT *
                FROM friend_requests
                WHERE
                    (
                        from_user = ?
                        AND to_user = ?
                    )
                    OR
                    (
                        from_user = ?
                        AND to_user = ?
                    )
            `).get(
                req.user.id,
                target.id,
                target.id,
                req.user.id
            );

        if (existing) {
            return res.status(400).json({
                error: "A friend request already exists."
            });
        }

        db.prepare(`
            INSERT INTO friend_requests
            (from_user, to_user, status, created_at)
            VALUES (?, ?, 'pending', ?)
        `).run(
            req.user.id,
            target.id,
            Date.now()
        );

        res.json({
            success: true,
            message:
                `Friend request sent to ${target.username}.`
        });
    }
);

// ============================================================
// GET FRIEND REQUESTS
// ============================================================

app.get(
    "/api/friends/requests",
    authenticate,
    (req, res) => {

        const incoming =
            db.prepare(`
                SELECT
                    friend_requests.id,
                    users.id AS user_id,
                    users.username,
                    friend_requests.created_at
                FROM friend_requests
                JOIN users
                    ON users.id =
                       friend_requests.from_user
                WHERE
                    friend_requests.to_user = ?
                    AND friend_requests.status = 'pending'
                ORDER BY friend_requests.created_at DESC
            `).all(req.user.id);

        res.json({
            requests: incoming
        });
    }
);

// ============================================================
// ACCEPT FRIEND REQUEST
// ============================================================

app.post(
    "/api/friends/accept",
    authenticate,
    (req, res) => {

        const requestId =
            Number(req.body.requestId);

        const request =
            db.prepare(`
                SELECT *
                FROM friend_requests
                WHERE
                    id = ?
                    AND to_user = ?
                    AND status = 'pending'
            `).get(
                requestId,
                req.user.id
            );

        if (!request) {
            return res.status(404).json({
                error: "Friend request not found."
            });
        }

        const addFriend =
            db.prepare(`
                INSERT OR IGNORE INTO friendships
                (user_id, friend_id)
                VALUES (?, ?)
            `);

        const transaction =
            db.transaction(() => {

                addFriend.run(
                    request.from_user,
                    request.to_user
                );

                addFriend.run(
                    request.to_user,
                    request.from_user
                );

                db.prepare(`
                    UPDATE friend_requests
                    SET status = 'accepted'
                    WHERE id = ?
                `).run(requestId);
            });

        transaction();

        res.json({
            success: true
        });
    }
);

// ============================================================
// GET FRIENDS
// ============================================================

app.get(
    "/api/friends",
    authenticate,
    (req, res) => {

        const friends =
            db.prepare(`
                SELECT
                    users.id,
                    users.username
                FROM friendships
                JOIN users
                    ON users.id =
                       friendships.friend_id
                WHERE friendships.user_id = ?
                ORDER BY users.username
            `).all(req.user.id);

        res.json({
            friends
        });
    }
);

// ============================================================
// WEBSOCKET / ONLINE USERS
// ============================================================

const onlineUsers = new Map();

wss.on("connection", (socket) => {

    let userId = null;

    socket.on("message", (raw) => {

        let message;

        try {
            message =
                JSON.parse(raw.toString());
        } catch {
            return;
        }

        if (message.type === "register") {

            if (!message.userId) {
                return;
            }

            userId =
                String(message.userId);

            const oldSocket =
                onlineUsers.get(userId);

            if (
                oldSocket &&
                oldSocket !== socket &&
                oldSocket.readyState ===
                    WebSocket.OPEN
            ) {

                oldSocket.send(
                    JSON.stringify({
                        type: "replaced",
                        message:
                            "This account connected somewhere else."
                    })
                );

                oldSocket.close();
            }

            onlineUsers.set(
                userId,
                socket
            );

            socket.send(
                JSON.stringify({
                    type: "registered",
                    userId
                })
            );

            return;
        }

        if (!userId) {
            return;
        }

        // WebRTC signaling
        if (message.type === "signal") {

            if (
                !message.to ||
                !message.payload
            ) {
                return;
            }

            const target =
                onlineUsers.get(
                    String(message.to)
                );

            if (
                target &&
                target.readyState ===
                    WebSocket.OPEN
            ) {

                target.send(
                    JSON.stringify({
                        type: "signal",
                        from: userId,
                        payload:
                            message.payload
                    })
                );
            }

            return;
        }

        // Chat messages
        if (message.type === "message") {

            if (
                !message.to ||
                !message.payload
            ) {
                return;
            }

            const target =
                onlineUsers.get(
                    String(message.to)
                );

            if (
                target &&
                target.readyState ===
                    WebSocket.OPEN
            ) {

                target.send(
                    JSON.stringify({
                        type: "message",
                        from: userId,
                        payload:
                            message.payload
                    })
                );
            }

            return;
        }
    });

    socket.on("close", () => {

        if (
            userId &&
            onlineUsers.get(userId) ===
                socket
        ) {

            onlineUsers.delete(userId);
        }
    });
});

// ============================================================
// START SERVER
// ============================================================

server.listen(PORT, () => {

    console.log(
        `VoiceRoom backend running on port ${PORT}`
    );

    console.log(
        `Website: http://localhost:${PORT}`
    );
});