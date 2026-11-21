
const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
} = require("discord.js");

const app = express();
let discordBotClient = null;
const PORT = process.env.PORT || 3000;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

if (!DASHBOARD_PASSWORD || !SESSION_SECRET) {
  console.error("Missing DASHBOARD_PASSWORD or SESSION_SECRET.");
  process.exit(1);
}

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    name: "rats_dashboard_session",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 30,
    },
  })
);

function requireDashboardLogin(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  next();
}

function requireDiscordConfig(req, res, next) {
  if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET ||
    !DISCORD_REDIRECT_URI
  ) {
    return res.status(500).json({
      error: "Discord OAuth is not configured on the server.",
    });
  }
  next();
}

const loginPage = (error = "") => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard Login</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #100d1b;
      color: white;
      font-family: Arial, sans-serif;
    }
    .panel {
      width: 85%;
      max-width: 380px;
      padding: 30px;
      border-radius: 18px;
      background: #1a1428;
      border: 1px solid #493965;
    }
    input, button {
      box-sizing: border-box;
      width: 100%;
      padding: 14px;
      margin-top: 12px;
      border-radius: 9px;
      font-size: 16px;
    }
    input {
      background: #100d1b;
      color: white;
      border: 1px solid #493965;
    }
    button {
      background: #8b5cf6;
      color: white;
      border: none;
      font-weight: bold;
      cursor: pointer;
    }
    .error { color: #ff8d9a; }
  </style>
</head>
<body>
  <main class="panel">
    <h1>Dashboard Login</h1>
    <p>Enter the shared dashboard password.</p>
    <form method="POST" action="/login">
      <input
        type="password"
        name="password"
        placeholder="Dashboard password"
        autocomplete="current-password"
        required
      >
      <button type="submit">Log in</button>
    </form>
    <p class="error">${error}</p>
  </main>
</body>
</html>`;

app.get("/login", (req, res) => {
  if (req.session.authenticated) return res.redirect("/");
  res.send(loginPage());
});

app.post("/login", (req, res, next) => {
  const password = req.body.password;

  if (typeof password !== "string" || password.length > 200) {
    return res.status(400).send("Invalid password input.");
  }

  if (password !== DASHBOARD_PASSWORD) {
    return res.status(401).send(
      loginPage("Incorrect password. Please try again.")
    );
  }

  req.session.regenerate((error) => {
    if (error) return next(error);

    req.session.authenticated = true;

    req.session.save((saveError) => {
      if (saveError) return next(saveError);
      res.redirect("/");
    });
  });
});

app.post("/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("rats_dashboard_session");
    res.redirect("/login");
  });
});

// Start Discord OAuth
app.get(
  "/auth/discord",
  requireDashboardLogin,
  requireDiscordConfig,
  (req, res) => {
    const state = crypto.randomBytes(32).toString("hex");
    req.session.discordOAuthState = state;

    const params = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      redirect_uri: DISCORD_REDIRECT_URI,
      response_type: "code",
      scope: "identify guilds",
      state,
    });

    res.redirect(
      `https://discord.com/oauth2/authorize?${params.toString()}`
    );
  }
);

// Discord OAuth callback
app.get(
  "/auth/discord/callback",
  requireDashboardLogin,
  requireDiscordConfig,
  async (req, res) => {
    try {
      const { code, state, error } = req.query;

      if (error) {
        return res.redirect("/?discord_error=cancelled");
      }

      if (
        typeof state !== "string" ||
        !req.session.discordOAuthState ||
        state !== req.session.discordOAuthState
      ) {
        return res.status(400).send("Invalid OAuth state. Please try again.");
      }

      delete req.session.discordOAuthState;

      if (typeof code !== "string") {
        return res.status(400).send("Discord did not return an authorization code.");
      }

      const tokenResponse = await fetch(
        "https://discord.com/api/oauth2/token",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: DISCORD_CLIENT_SECRET,
            grant_type: "authorization_code",
            code,
            redirect_uri: DISCORD_REDIRECT_URI,
          }),
        }
      );

      const tokens = await tokenResponse.json();

      if (!tokenResponse.ok || !tokens.access_token) {
        console.error("Discord token exchange failed:", tokens);
        return res.status(502).send("Could not connect to Discord. Please try again.");
      }

      const userResponse = await fetch(
        "https://discord.com/api/users/@me",
        {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
          },
        }
      );

      const user = await userResponse.json();

      if (!userResponse.ok || !user.id) {
        console.error("Discord user request failed:", user);
        return res.status(502).send("Could not retrieve your Discord account.");
      }

      req.session.discord = {
        id: user.id,
        username: user.username,
        global_name: user.global_name || user.username,
        avatar: user.avatar || null,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token || null,
        expiresAt: Date.now() + (tokens.expires_in || 0) * 1000,
      };

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Could not save Discord session:", saveError);
          return res.status(500).send("Could not save your Discord connection.");
        }
        res.redirect("/?discord_connected=1");
      });
    } catch (error) {
      console.error("Discord OAuth callback error:", error);
      res.status(500).send("Discord connection failed. Please try again.");
    }
  }
);
// Bot status for the dashboard
app.get("/api/discord/bot-status", requireDashboardLogin, (req, res) => {
  const guildId = req.query.guildId;
  const botOnline = Boolean(discordBotClient?.isReady());

  const inSelectedServer = guildId
    ? Boolean(discordBotClient?.guilds.cache.has(guildId))
    : null;

  res.json({
    configured: Boolean(DISCORD_BOT_TOKEN && DISCORD_CLIENT_ID),
    online: botOnline,
    inSelectedServer
  });
});
// Current connected Discord account
app.get("/api/discord/me", requireDashboardLogin, (req, res) => {
  if (!req.session.discord) {
    return res.json({ connected: false });
  }

  const { id, username, global_name, avatar } = req.session.discord;

  res.json({
    connected: true,
    user: { id, username, global_name, avatar },
  });
});

// Load servers available to the connected Discord account
app.get("/api/discord/guilds", requireDashboardLogin, async (req, res) => {
  if (!req.session.discord?.accessToken) {
    return res.status(401).json({ error: "Discord is not connected." });
  }

  try {
    const response = await fetch(
      "https://discord.com/api/users/@me/guilds",
      {
        headers: {
          Authorization: `Bearer ${req.session.discord.accessToken}`,
        },
      }
    );

    const guilds = await response.json();

    if (!response.ok) {
      console.error("Discord guild request failed:", guilds);
      return res.status(response.status).json({
        error: "Could not load Discord servers. Please reconnect Discord.",
      });
    }

        const manageableGuilds = guilds.filter((guild) => {
      const permissions = BigInt(guild.permissions || "0");

      const canManageGuild =
        guild.owner ||
        (permissions & 0x20n) === 0x20n ||
        (permissions & 0x8n) === 0x8n;

      const botIsInGuild = Boolean(
        discordBotClient?.guilds.cache.has(guild.id)
      );

      return canManageGuild && botIsInGuild;
    });
// Load channels from the selected Discord server only
app.get(
  "/api/discord/guilds/:guildId/channels",
  requireDashboardLogin,
  async (req, res) => {
    try {
      if (!discordBotClient?.isReady()) {
        return res.status(503).json({
          error: "The Discord bot is not online.",
        });
      }

      const guild = discordBotClient.guilds.cache.get(req.params.guildId);

      if (!guild) {
        return res.status(404).json({
          error: "The bot is not in this Discord server.",
        });
      }

      const channels = await guild.channels.fetch();

      const availableChannels = channels
        .filter((channel) => {
          return (
            channel &&
            (channel.type === 4 ||
              (channel.isTextBased() && !channel.isThread()))
          );
        })
        .map((channel) => ({
          id: channel.id,
          name: channel.name,
          type: channel.type,
          parentId: channel.parentId,
        }));

      res.json(availableChannels);
    } catch (error) {
      console.error("Discord channel loading error:", error);
      res.status(500).json({
        error: "Could not load channels from this server.",
      });
    }
  }
);
    res.json(
      manageableGuilds.map((guild) => ({
        id: guild.id,
        name: guild.name,
        icon: guild.icon,
      }))
    );
  } catch (error) {
    console.error("Discord guild loading error:", error);
    res.status(500).json({ error: "Could not load Discord servers." });
  }
});

// Disconnect Discord account
app.post("/auth/discord/disconnect", requireDashboardLogin, (req, res) => {
  delete req.session.discord;
  delete req.session.discordOAuthState;
  res.json({ success: true });
});

app.get("/", requireDashboardLogin, (req, res, next) => {
  res.sendFile(path.join(__dirname, "index.html"), (error) => {
    if (error) next(error);
  });
});

// Protect the dashboard's static files
app.use(requireDashboardLogin);
app.use(express.static(__dirname));

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).send("Something went wrong.");
});

app.listen(PORT, () => {
  console.log(`Dashboard running on port ${PORT}`);
});

// Discord bot
async function startDiscordBot() {
  if (!DISCORD_BOT_TOKEN || !DISCORD_CLIENT_ID) {
    console.log("Discord bot credentials are not configured yet.");
    return;
  }

  const client = new Client({
    intents: [GatewayIntentBits.Guilds],
  });
discordBotClient = client;
  client.once("ready", () => {
    console.log(`Bot online as ${client.user.tag}`);
  });

  client.on("interactionCreate", async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.commandName === "ping") {
      await interaction.reply({
        content: `Pong! Latency: ${client.ws.ping}ms`,
        ephemeral: true,
      });
    }
  });

  const commands = [
    new SlashCommandBuilder()
      .setName("ping")
      .setDescription("Check if the bot is online.")
      .toJSON(),
  ];

  const rest = new REST({ version: "10" }).setToken(DISCORD_BOT_TOKEN);

  await rest.put(
    Routes.applicationCommands(DISCORD_CLIENT_ID),
    { body: commands }
  );

  await client.login(DISCORD_BOT_TOKEN);
}

startDiscordBot().catch((error) => {
  console.error("Discord bot failed to start:", error);
});
