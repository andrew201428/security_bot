
import os
import re
import json
import time
import asyncio
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

import discord
from discord import app_commands
from discord.ext import commands, tasks

BOT_NAME = "NOVASTRAP"
BOT_VERSION = "1.0.0"
TOKEN = os.getenv("DISCORD_TOKEN")
DB_PATH = os.getenv("NOVASTRAP_DB", "novastrap.db")
OWNER_ID = int(os.getenv("BOT_OWNER_ID", "0"))  # Your Discord user ID

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
log = logging.getLogger("novastrap")

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing. Add it in Render Environment Variables.")

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True
intents.message_content = True
intents.moderation = True

bot = commands.Bot(command_prefix=",", intents=intents, help_command=None)
tree = bot.tree

# ------------------------------ DATABASE ------------------------------

db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = asyncio.Lock()

def db_exec(sql, params=()):
    cur = db.execute(sql, params)
    db.commit()
    return cur

def db_one(sql, params=()):
    return db.execute(sql, params).fetchone()

def db_all(sql, params=()):
    return db.execute(sql, params).fetchall()

def init_db():
    db.executescript("""
    CREATE TABLE IF NOT EXISTS guild_config (
        guild_id INTEGER PRIMARY KEY,
        log_channel_id INTEGER,
        advanced_logs INTEGER NOT NULL DEFAULT 1,
        antinuke_enabled INTEGER NOT NULL DEFAULT 0,
        antinuke_action TEXT NOT NULL DEFAULT 'timeout',
        antinuke_limit INTEGER NOT NULL DEFAULT 3,
        antinuke_window INTEGER NOT NULL DEFAULT 10,
        antispam_enabled INTEGER NOT NULL DEFAULT 0,
        antispam_action TEXT NOT NULL DEFAULT 'timeout',
        antispam_limit INTEGER NOT NULL DEFAULT 5,
        antispam_window INTEGER NOT NULL DEFAULT 5,
        antilink_enabled INTEGER NOT NULL DEFAULT 0,
        antilink_action TEXT NOT NULL DEFAULT 'delete',
        antimention_enabled INTEGER NOT NULL DEFAULT 0,
        antimention_action TEXT NOT NULL DEFAULT 'timeout',
        antimention_limit INTEGER NOT NULL DEFAULT 5,
        antinsfw_enabled INTEGER NOT NULL DEFAULT 0,
        antinsfw_action TEXT NOT NULL DEFAULT 'delete',
        level_enabled INTEGER NOT NULL DEFAULT 0,
        level_channel_id INTEGER,
        jail_role_id INTEGER,
        jail_channel_id INTEGER,
        premium INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS access_levels (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        level TEXT NOT NULL,
        PRIMARY KEY(guild_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS access_commands (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        command TEXT NOT NULL,
        allowed INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY(guild_id, user_id, command)
    );
    CREATE TABLE IF NOT EXISTS antinuke_whitelist (
        guild_id INTEGER NOT NULL,
        target_id INTEGER NOT NULL,
        target_type TEXT NOT NULL,
        PRIMARY KEY(guild_id, target_id, target_type)
    );
    CREATE TABLE IF NOT EXISTS bypass_members (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY(guild_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS bypass_bots (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY(guild_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS warns (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        moderator_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS levels (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        xp INTEGER NOT NULL DEFAULT 0,
        level INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(guild_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS autoresponders (
        guild_id INTEGER NOT NULL,
        trigger TEXT NOT NULL,
        response TEXT NOT NULL,
        PRIMARY KEY(guild_id, trigger)
    );
    CREATE TABLE IF NOT EXISTS giveaways (
        message_id INTEGER PRIMARY KEY,
        guild_id INTEGER NOT NULL,
        channel_id INTEGER NOT NULL,
        prize TEXT NOT NULL,
        ends_at REAL NOT NULL,
        ended INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS saved_backups (
        guild_id INTEGER PRIMARY KEY,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    db.commit()

init_db()

def ensure_guild(guild_id: int):
    db_exec("INSERT OR IGNORE INTO guild_config(guild_id) VALUES(?)", (guild_id,))

def config(guild_id: int):
    ensure_guild(guild_id)
    return db_one("SELECT * FROM guild_config WHERE guild_id=?", (guild_id,))

# ------------------------------ PERMISSIONS ------------------------------

LEVEL_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
COMMAND_LEVEL = {
    "antinuke": "HIGH", "antispam": "HIGH", "anti_nsfw": "HIGH",
    "anti_link": "HIGH", "anti_mention": "HIGH", "all_logs_channel": "HIGH",
    "advanced_logs": "HIGH", "server_prem": "OWNER", "moderation_access": "HIGH",
    "bypass": "HIGH", "backup": "HIGH", "save": "HIGH", "automod": "HIGH",
    "setup_level": "HIGH", "jail_setup": "HIGH", "lock_setup": "HIGH",
    "kick": "MEDIUM", "ban": "MEDIUM", "timeout": "MEDIUM", "warn": "MEDIUM",
    "purgeuser": "MEDIUM", "purgebot": "MEDIUM", "jail": "MEDIUM",
    "lock": "MEDIUM", "giveaway": "MEDIUM", "role": "HIGH",
    "userinfo": "LOW", "serverinfo": "LOW", "avatar": "LOW", "banner": "LOW",
    "help": "LOW", "poll": "LOW", "vote": "LOW", "leaderboard": "LOW",
}

def is_owner(user_id: int) -> bool:
    return OWNER_ID != 0 and user_id == OWNER_ID

def get_level(guild_id: int, user_id: int) -> str:
    row = db_one("SELECT level FROM access_levels WHERE guild_id=? AND user_id=?",
                 (guild_id, user_id))
    return row["level"] if row else "LOW"

def has_access(interaction: discord.Interaction, command_key: str) -> bool:
    if interaction.guild is None:
        return False
    if is_owner(interaction.user.id):
        return True
    needed = COMMAND_LEVEL.get(command_key, "MEDIUM")
    if needed == "OWNER":
        return False
    # The configured NOVASTRAP bot owner is the only global access administrator.
    # Server ownership alone does not grant HIGH-level bot configuration access.
    level = get_level(interaction.guild.id, interaction.user.id)
    if LEVEL_RANK.get(level, 0) < LEVEL_RANK.get(needed, 99):
        return False
    row = db_one(
        "SELECT allowed FROM access_commands WHERE guild_id=? AND user_id=? AND command=?",
        (interaction.guild.id, interaction.user.id, command_key)
    )
    return row is None or bool(row["allowed"])

async def require_access(interaction: discord.Interaction, command_key: str) -> bool:
    if not has_access(interaction, command_key):
        await interaction.response.send_message(
            "You do not have permission to use this command.", ephemeral=True
        )
        return False
    return True

async def require_guild(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        await interaction.response.send_message(
            "This command can only be used inside a server.", ephemeral=True
        )
        return False
    return True

# ------------------------------ LOGGING ------------------------------

async def send_log(guild: discord.Guild, title: str, description: str,
                   color=discord.Color.blurple()):
    cfg = config(guild.id)
    if not cfg["advanced_logs"] or not cfg["log_channel_id"]:
        return
    channel = guild.get_channel(cfg["log_channel_id"])
    if channel is None:
        return
    embed = discord.Embed(title=title, description=description[:4000],
                          color=color, timestamp=discord.utils.utcnow())
    embed.set_footer(text=f"{BOT_NAME} | {BOT_VERSION}")
    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        log.warning("Missing permission to send logs in guild %s", guild.id)

async def audit_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int):
    try:
        async for entry in guild.audit_logs(limit=8, action=action):
            if getattr(entry.target, "id", None) == target_id:
                if (discord.utils.utcnow() - entry.created_at).total_seconds() < 15:
                    return entry.user
    except (discord.Forbidden, discord.HTTPException):
        pass
    return None

# ------------------------------ MODERATION HELPERS ------------------------------

async def punish_member(member: discord.Member, action: str, reason: str):
    try:
        if action == "timeout":
            await member.timeout(timedelta(minutes=10), reason=reason)
        elif action == "kick":
            await member.kick(reason=reason)
        elif action == "ban":
            await member.ban(reason=reason, delete_message_seconds=0)
        elif action == "delete":
            return
    except discord.Forbidden:
        log.warning("Cannot punish %s due to role hierarchy/permissions", member.id)
    except discord.HTTPException as exc:
        log.warning("Punishment failed: %s", exc)

def is_exempt(member: discord.Member) -> bool:
    if member.guild.owner_id == member.id or is_owner(member.id):
        return True
    if member.guild_permissions.administrator:
        return True
    if db_one("SELECT 1 FROM bypass_members WHERE guild_id=? AND user_id=?",
              (member.guild.id, member.id)):
        return True
    return False

spam_cache = defaultdict(lambda: deque(maxlen=30))
nuke_cache = defaultdict(lambda: deque(maxlen=30))
xp_cooldown = {}

async def security_check(member: discord.Member, reason: str, action: str):
    if is_exempt(member):
        return
    await punish_member(member, action, reason)
    await send_log(member.guild, "Security Alert",
                   f"**Member:** {member.mention} (`{member.id}`)\n"
                   f"**Detection:** {reason}\n**Action:** {action.upper()}",
                   discord.Color.red())

# ------------------------------ BASIC EVENTS ------------------------------

@bot.event
async def on_ready():
    try:
        synced = await tree.sync()
        log.info("Synced %s application commands", len(synced))
    except Exception:
        log.exception("Slash command sync failed")
    log.info("%s online as %s", BOT_NAME, bot.user)
    if not giveaway_worker.is_running():
        giveaway_worker.start()

@bot.event
async def on_guild_join(guild):
    ensure_guild(guild.id)
    await send_log(guild, "Bot Joined", f"Joined **{guild.name}** (`{guild.id}`).")

@bot.event
async def on_member_join(member):
    await send_log(member.guild, "Member Joined",
                   f"{member.mention} (`{member.id}`) joined the server.")

@bot.event
async def on_member_remove(member):
    await send_log(member.guild, "Member Left",
                   f"**{member}** (`{member.id}`) left the server.")

@bot.event
async def on_member_ban(guild, user):
    await send_log(guild, "Member Banned", f"**{user}** (`{user.id}`) was banned.")

@bot.event
async def on_member_unban(guild, user):
    await send_log(guild, "Member Unbanned", f"**{user}** (`{user.id}`) was unbanned.")

@bot.event
async def on_message_delete(message):
    if message.guild and not message.author.bot:
        snipes[message.channel.id] = {"author": str(message.author), "content": message.content or "[No text content]"}
        content = message.content[:1500] if message.content else "[No text content]"
        await send_log(message.guild, "Message Deleted",
                       f"**Author:** {message.author} (`{message.author.id}`)\n"
                       f"**Channel:** {message.channel.mention}\n"
                       f"**Content:** {discord.utils.escape_markdown(content)}")

@bot.event
async def on_message_edit(before, after):
    if before.guild and not before.author.bot and before.content != after.content:
        await send_log(before.guild, "Message Edited",
                       f"**Author:** {before.author} (`{before.author.id}`)\n"
                       f"**Channel:** {before.channel.mention}\n"
                       f"**Before:** {before.content[:900] or '[empty]'}\n"
                       f"**After:** {after.content[:900] or '[empty]'}")

@bot.event
async def on_guild_channel_create(channel):
    actor = await audit_actor(channel.guild, discord.AuditLogAction.channel_create, channel.id)
    await send_log(channel.guild, "Channel Created",
                   f"**Channel:** {channel.mention}\n**Created by:** {actor or 'Unknown'}")
    await nuke_guard(channel.guild, actor, "Created a channel")

@bot.event
async def on_guild_channel_delete(channel):
    actor = await audit_actor(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
    await send_log(channel.guild, "Channel Deleted",
                   f"**Channel:** {channel.name} (`{channel.id}`)\n**Deleted by:** {actor or 'Unknown'}")
    await nuke_guard(channel.guild, actor, "Deleted a channel")

@bot.event
async def on_guild_channel_update(before, after):
    actor = await audit_actor(after.guild, discord.AuditLogAction.channel_update, after.id)
    await send_log(after.guild, "Channel Updated",
                   f"**Channel:** {after.mention}\n**Updated by:** {actor or 'Unknown'}")
    await nuke_guard(after.guild, actor, "Updated a channel")

@bot.event
async def on_guild_role_create(role):
    actor = await audit_actor(role.guild, discord.AuditLogAction.role_create, role.id)
    await send_log(role.guild, "Role Created",
                   f"**Role:** {role.name} (`{role.id}`)\n**Created by:** {actor or 'Unknown'}")
    await nuke_guard(role.guild, actor, "Created a role")

@bot.event
async def on_guild_role_delete(role):
    actor = await audit_actor(role.guild, discord.AuditLogAction.role_delete, role.id)
    await send_log(role.guild, "Role Deleted",
                   f"**Role:** {role.name} (`{role.id}`)\n**Deleted by:** {actor or 'Unknown'}")
    await nuke_guard(role.guild, actor, "Deleted a role")

@bot.event
async def on_guild_role_update(before, after):
    actor = await audit_actor(after.guild, discord.AuditLogAction.role_update, after.id)
    await send_log(after.guild, "Role Updated",
                   f"**Role:** {after.name}\n**Updated by:** {actor or 'Unknown'}")
    await nuke_guard(after.guild, actor, "Updated a role")

async def nuke_guard(guild, actor, reason):
    if actor is None or not isinstance(actor, discord.Member) or is_exempt(actor):
        return
    cfg = config(guild.id)
    if not cfg["antinuke_enabled"]:
        return
    if db_one("SELECT 1 FROM antinuke_whitelist WHERE guild_id=? AND target_id=?",
              (guild.id, actor.id)):
        return
    now = time.time()
    key = (guild.id, actor.id)
    q = nuke_cache[key]
    q.append(now)
    while q and now - q[0] > cfg["antinuke_window"]:
        q.popleft()
    if len(q) >= cfg["antinuke_limit"]:
        await security_check(actor, f"Anti-nuke: {reason} ({len(q)} actions)",
                             cfg["antinuke_action"])
        q.clear()

@bot.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return
    cfg = config(message.guild.id)
    member = message.author
    if not is_exempt(member):
        # Anti-spam
        if cfg["antispam_enabled"]:
            key = (message.guild.id, member.id)
            now = time.time()
            q = spam_cache[key]
            q.append(now)
            while q and now - q[0] > cfg["antispam_window"]:
                q.popleft()
            if len(q) >= cfg["antispam_limit"]:
                try:
                    await message.channel.purge(
                        limit=min(len(q), 30),
                        check=lambda m: m.author.id == member.id
                    )
                except discord.HTTPException:
                    pass
                await security_check(member, "Anti-spam message limit exceeded",
                                     cfg["antispam_action"])
                q.clear()
                return
        # Anti-link
        if cfg["antilink_enabled"] and re.search(r"(https?://|discord\.gg/|www\.)", message.content, re.I):
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            if cfg["antilink_action"] != "delete":
                await security_check(member, "Posted a prohibited link",
                                     cfg["antilink_action"])
            return
        # Anti-mention
        if cfg["antimention_enabled"] and len(message.mentions) >= cfg["antimention_limit"]:
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            await security_check(member, "Mention limit exceeded",
                                 cfg["antimention_action"])
            return
        # Anti-NSFW: conservative text-pattern filter only; not an image classifier.
        if cfg["antinsfw_enabled"] and re.search(
            r"\b(nudes?|porn|xxx|onlyfans)\b", message.content, re.I
        ):
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            if cfg["antinsfw_action"] != "delete":
                await security_check(member, "Prohibited NSFW-related text detected",
                                     cfg["antinsfw_action"])
            return

        # XP system
        if cfg["level_enabled"]:
            now = time.time()
            key = (message.guild.id, member.id)
            if now - xp_cooldown.get(key, 0) >= 60:
                xp_cooldown[key] = now
                row = db_one("SELECT xp, level FROM levels WHERE guild_id=? AND user_id=?",
                             (message.guild.id, member.id))
                xp = (row["xp"] if row else 0) + 15
                level = int((xp / 100) ** 0.5)
                db_exec("""INSERT INTO levels(guild_id,user_id,xp,level) VALUES(?,?,?,?)
                           ON CONFLICT(guild_id,user_id) DO UPDATE SET xp=excluded.xp, level=excluded.level""",
                        (message.guild.id, member.id, xp, level))
                if row and level > row["level"]:
                    await message.channel.send(f"{member.mention} reached level **{level}**!")

        # Autoresponders
        for item in db_all("SELECT trigger,response FROM autoresponders WHERE guild_id=?",
                           (message.guild.id,)):
            if message.content.lower() == item["trigger"].lower():
                await message.channel.send(item["response"])
                break
    await bot.process_commands(message)

# ------------------------------ COMMAND GROUPS ------------------------------

class SecurityGroup(app_commands.Group):
    pass

class ModerationAccessGroup(app_commands.Group):
    pass

class ServerPremiumGroup(app_commands.Group):
    pass

class AntinukeGroup(app_commands.Group):
    pass

class AntispamGroup(app_commands.Group):
    pass

class AntiLinkGroup(app_commands.Group):
    pass

class AntiMentionGroup(app_commands.Group):
    pass

class AntiNsfwGroup(app_commands.Group):
    pass

class BypassGroup(app_commands.Group):
    pass

class GiveawayGroup(app_commands.Group):
    pass

class XPGroup(app_commands.Group):
    pass

class AutoresponderGroup(app_commands.Group):
    pass

# ------------------------------ HELP / INFO ------------------------------

@tree.command(name="help", description="Show NOVASTRAP commands and permission levels")
async def help_cmd(interaction: discord.Interaction):
    embed = discord.Embed(title="NOVASTRAP | Command Center",
        description="Advanced Server Security — One System. Total Control.",
        color=discord.Color.blurple())
    embed.add_field(name="HIGH", value="Security settings, access control, backups, server configuration.", inline=False)
    embed.add_field(name="MEDIUM", value="Kick, ban, timeout, warn, purge, jail and lock management.", inline=False)
    embed.add_field(name="LOW", value="User/server info, avatar, banner, help and basic utilities.", inline=False)
    embed.add_field(name="Prefix", value="`,` (legacy prefix commands are not enabled in this release).", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="userinfo", description="View information about a server member")
@app_commands.describe(member="Member to inspect")
async def userinfo(interaction: discord.Interaction, member: discord.Member = None):
    if not await require_guild(interaction): return
    if not await require_access(interaction, "userinfo"): return
    member = member or interaction.user
    embed = discord.Embed(title=f"User Information — {member}",
                          color=discord.Color.blurple())
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="User ID", value=str(member.id), inline=True)
    embed.add_field(name="Account Created", value=discord.utils.format_dt(member.created_at, "D"), inline=True)
    if member.joined_at:
        embed.add_field(name="Joined Server", value=discord.utils.format_dt(member.joined_at, "D"), inline=True)
    embed.add_field(name="Top Role", value=member.top_role.mention, inline=True)
    embed.add_field(name="Bot", value="Yes" if member.bot else "No", inline=True)
    await interaction.response.send_message(embed=embed)

@tree.command(name="serverinfo", description="View server information")
async def serverinfo(interaction: discord.Interaction):
    if not await require_guild(interaction): return
    if not await require_access(interaction, "serverinfo"): return
    g = interaction.guild
    embed = discord.Embed(title=f"Server Information — {g.name}",
                          color=discord.Color.blurple())
    if g.icon: embed.set_thumbnail(url=g.icon.url)
    embed.add_field(name="Server ID", value=str(g.id), inline=True)
    embed.add_field(name="Owner", value=f"<@{g.owner_id}>", inline=True)
    embed.add_field(name="Members", value=str(g.member_count), inline=True)
    embed.add_field(name="Roles", value=str(len(g.roles)), inline=True)
    embed.add_field(name="Channels", value=str(len(g.channels)), inline=True)
    embed.add_field(name="Created", value=discord.utils.format_dt(g.created_at, "D"), inline=True)
    await interaction.response.send_message(embed=embed)

@tree.command(name="avatar", description="Show a member's avatar")
async def avatar(interaction: discord.Interaction, member: discord.Member = None):
    if not await require_access(interaction, "avatar"): return
    member = member or interaction.user
    embed = discord.Embed(title=f"{member}'s Avatar", color=discord.Color.blurple())
    embed.set_image(url=member.display_avatar.url)
    await interaction.response.send_message(embed=embed)

@tree.command(name="banner", description="Show a member's profile banner")
async def banner(interaction: discord.Interaction, user: discord.User = None):
    if not await require_access(interaction, "banner"): return
    user = user or interaction.user
    user = await bot.fetch_user(user.id)
    if not user.banner:
        await interaction.response.send_message("This user has no public banner.", ephemeral=True)
        return
    embed = discord.Embed(title=f"{user}'s Banner", color=discord.Color.blurple())
    embed.set_image(url=user.banner.url)
    await interaction.response.send_message(embed=embed)

# ------------------------------ MODERATION ------------------------------

@tree.command(name="kick", description="Kick a member from this server")
@app_commands.describe(member="Member to kick", reason="Reason for the kick")
async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await require_access(interaction, "kick"): return
    if member.id == interaction.user.id or member.guild_permissions.administrator:
        await interaction.response.send_message("That member cannot be kicked with this command.", ephemeral=True); return
    if member.top_role >= interaction.user.top_role and interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Your role must be higher than the target's role.", ephemeral=True); return
    await member.kick(reason=f"{reason} | Moderator: {interaction.user}")
    await interaction.response.send_message(f"**{member}** was kicked. Reason: {reason}")
    await send_log(interaction.guild, "Member Kicked", f"**Target:** {member} (`{member.id}`)\n**Moderator:** {interaction.user}\n**Reason:** {reason}")

@tree.command(name="ban", description="Ban a member from this server")
@app_commands.describe(member="Member to ban", reason="Reason for the ban")
async def ban(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await require_access(interaction, "ban"): return
    if member.id == interaction.user.id or member.guild_permissions.administrator:
        await interaction.response.send_message("That member cannot be banned with this command.", ephemeral=True); return
    if member.top_role >= interaction.user.top_role and interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Your role must be higher than the target's role.", ephemeral=True); return
    await member.ban(reason=f"{reason} | Moderator: {interaction.user}", delete_message_seconds=0)
    await interaction.response.send_message(f"**{member}** was banned. Reason: {reason}")
    await send_log(interaction.guild, "Member Banned", f"**Target:** {member} (`{member.id}`)\n**Moderator:** {interaction.user}\n**Reason:** {reason}")

@tree.command(name="timeout", description="Timeout a member for a set number of minutes")
@app_commands.describe(member="Member to timeout", minutes="Duration in minutes", reason="Reason")
async def timeout_cmd(interaction: discord.Interaction, member: discord.Member,
                      minutes: app_commands.Range[int, 1, 40320], reason: str = "No reason provided"):
    if not await require_access(interaction, "timeout"): return
    if member.top_role >= interaction.user.top_role and interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Your role must be higher than the target's role.", ephemeral=True); return
    await member.timeout(timedelta(minutes=minutes), reason=f"{reason} | Moderator: {interaction.user}")
    await interaction.response.send_message(f"**{member}** timed out for {minutes} minutes. Reason: {reason}")
    await send_log(interaction.guild, "Member Timed Out", f"**Target:** {member}\n**Duration:** {minutes} minutes\n**Reason:** {reason}")

@tree.command(name="warn", description="Warn a member and record the reason")
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str):
    if not await require_access(interaction, "warn"): return
    db_exec("INSERT INTO warns VALUES(?,?,?,?,?)",
            (interaction.guild.id, member.id, interaction.user.id, reason, datetime.now(timezone.utc).isoformat()))
    count = db_one("SELECT COUNT(*) AS n FROM warns WHERE guild_id=? AND user_id=?",
                   (interaction.guild.id, member.id))["n"]
    await interaction.response.send_message(f"{member.mention} has been warned. Total recorded warnings: **{count}**.")
    await send_log(interaction.guild, "Member Warned", f"**Target:** {member}\n**Moderator:** {interaction.user}\n**Reason:** {reason}")

@tree.command(name="purgeuser", description="Delete recent messages from one member in this channel")
async def purgeuser(interaction: discord.Interaction, member: discord.Member,
                    amount: app_commands.Range[int, 1, 100]):
    if not await require_access(interaction, "purgeuser"): return
    await interaction.response.defer(ephemeral=True)
    matches = []
    async for message in interaction.channel.history(limit=1000):
        if message.author.id == member.id:
            matches.append(message)
            if len(matches) >= amount:
                break
    if not matches:
        await interaction.followup.send("No matching messages found in the recent channel history.", ephemeral=True)
        return
    cutoff = discord.utils.utcnow() - timedelta(days=14)
    recent = [m for m in matches if m.created_at > cutoff]
    old = [m for m in matches if m.created_at <= cutoff]
    deleted_count = 0
    for start in range(0, len(recent), 100):
        batch = recent[start:start + 100]
        if len(batch) == 1:
            await batch[0].delete()
            deleted_count += 1
        elif batch:
            removed = await interaction.channel.delete_messages(batch)
            deleted_count += len(removed)
    for message in old:
        await message.delete()
        deleted_count += 1
    await interaction.followup.send(f"Deleted {deleted_count} recent messages from {member.mention}.", ephemeral=True)

@tree.command(name="purgebot", description="Delete recent bot messages in this channel")
async def purgebot(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]):
    if not await require_access(interaction, "purgebot"): return
    await interaction.response.defer(ephemeral=True)
    deleted = await interaction.channel.purge(limit=amount, check=lambda m: m.author.bot, bulk=True)
    await interaction.followup.send(f"Deleted {len(deleted)} bot messages.", ephemeral=True)

@tree.command(name="server_ban_list", description="Show the server's current ban list")
async def server_ban_list(interaction: discord.Interaction):
    if not await require_access(interaction, "ban"): return
    bans = [entry async for entry in interaction.guild.bans(limit=100)]
    if not bans:
        await interaction.response.send_message("The server ban list is empty.", ephemeral=True); return
    lines = [f"{i+1}. {entry.user} (`{entry.user.id}`)" for i, entry in enumerate(bans[:50])]
    await interaction.response.send_message("**Server Ban List**\n" + "\n".join(lines), ephemeral=True)

# ------------------------------ SECURITY CONFIGURATION ------------------------------

@tree.command(name="all_logs_channel", description="Set the server's log channel")
async def all_logs_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if not await require_access(interaction, "all_logs_channel"): return
    ensure_guild(interaction.guild.id)
    db_exec("UPDATE guild_config SET log_channel_id=? WHERE guild_id=?",
            (channel.id, interaction.guild.id))
    await interaction.response.send_message(f"All logs will be sent to {channel.mention}.", ephemeral=True)

@tree.command(name="advanced_logs", description="Turn advanced event logging on or off")
@app_commands.choices(state=[
    app_commands.Choice(name="On", value="on"),
    app_commands.Choice(name="Off", value="off")
])
async def advanced_logs(interaction: discord.Interaction, state: app_commands.Choice[str]):
    if not await require_access(interaction, "advanced_logs"): return
    db_exec("UPDATE guild_config SET advanced_logs=? WHERE guild_id=?",
            (1 if state.value == "on" else 0, interaction.guild.id))
    await interaction.response.send_message(f"Advanced logs: **{state.value.upper()}**", ephemeral=True)

@tree.command(name="antinuke", description="Configure anti-nuke protection")
@app_commands.choices(action=[
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def antinuke(interaction: discord.Interaction, enabled: bool,
                   action: app_commands.Choice[str] = None,
                   limit: app_commands.Range[int, 2, 10] = 3,
                   window_seconds: app_commands.Range[int, 5, 60] = 10):
    if not await require_access(interaction, "antinuke"): return
    db_exec("""UPDATE guild_config SET antinuke_enabled=?, antinuke_action=?,
               antinuke_limit=?, antinuke_window=? WHERE guild_id=?""",
            (int(enabled), action.value if action else "timeout", limit, window_seconds, interaction.guild.id))
    await interaction.response.send_message(
        f"Anti-nuke **{'enabled' if enabled else 'disabled'}**. "
        f"Threshold: {limit} actions / {window_seconds}s. "
        f"Punishment: {(action.value if action else 'timeout').upper()}.", ephemeral=True)

@tree.command(name="antinuke_whitelist", description="Add or remove a member or bot from anti-nuke whitelist")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="List", value="list")
])
async def antinuke_whitelist(interaction: discord.Interaction, operation: app_commands.Choice[str],
                             user: discord.User = None):
    if not await require_access(interaction, "antinuke"): return
    gid = interaction.guild.id
    if operation.value == "list":
        rows = db_all("SELECT target_id,target_type FROM antinuke_whitelist WHERE guild_id=?", (gid,))
        text = "\n".join(f"<@{r['target_id']}> — {r['target_type']}" for r in rows) or "Whitelist is empty."
        await interaction.response.send_message(text, ephemeral=True); return
    if user is None:
        await interaction.response.send_message("Select a user or bot.", ephemeral=True); return
    if operation.value == "add":
        db_exec("INSERT OR IGNORE INTO antinuke_whitelist VALUES(?,?,?)",
                (gid, user.id, "bot" if user.bot else "member"))
    else:
        db_exec("DELETE FROM antinuke_whitelist WHERE guild_id=? AND target_id=?", (gid, user.id))
    await interaction.response.send_message(f"Anti-nuke whitelist updated for {user.mention}.", ephemeral=True)

@tree.command(name="antispam", description="Configure anti-spam protection")
@app_commands.choices(action=[
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def antispam(interaction: discord.Interaction, enabled: bool,
                   action: app_commands.Choice[str] = None,
                   limit: app_commands.Range[int, 3, 20] = 5,
                   window_seconds: app_commands.Range[int, 2, 30] = 5):
    if not await require_access(interaction, "antispam"): return
    db_exec("""UPDATE guild_config SET antispam_enabled=?, antispam_action=?,
               antispam_limit=?, antispam_window=? WHERE guild_id=?""",
            (int(enabled), action.value if action else "timeout", limit, window_seconds, interaction.guild.id))
    await interaction.response.send_message("Anti-spam configuration saved.", ephemeral=True)

@tree.command(name="anti_link", description="Configure link filtering")
@app_commands.choices(action=[
    app_commands.Choice(name="Delete only", value="delete"),
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def anti_link(interaction: discord.Interaction, enabled: bool,
                    action: app_commands.Choice[str] = None):
    if not await require_access(interaction, "anti_link"): return
    db_exec("UPDATE guild_config SET antilink_enabled=?, antilink_action=? WHERE guild_id=?",
            (int(enabled), action.value if action else "delete", interaction.guild.id))
    await interaction.response.send_message("Anti-link configuration saved.", ephemeral=True)

@tree.command(name="anti_mention", description="Configure mass-mention protection")
@app_commands.choices(action=[
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def anti_mention(interaction: discord.Interaction, enabled: bool,
                       action: app_commands.Choice[str] = None,
                       limit: app_commands.Range[int, 2, 20] = 5):
    if not await require_access(interaction, "anti_mention"): return
    db_exec("UPDATE guild_config SET antimention_enabled=?, antimention_action=?, antimention_limit=? WHERE guild_id=?",
            (int(enabled), action.value if action else "timeout", limit, interaction.guild.id))
    await interaction.response.send_message("Anti-mention configuration saved.", ephemeral=True)

@tree.command(name="anti_nsfw", description="Configure basic NSFW text filtering")
@app_commands.choices(action=[
    app_commands.Choice(name="Delete only", value="delete"),
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def anti_nsfw(interaction: discord.Interaction, enabled: bool,
                    action: app_commands.Choice[str] = None):
    if not await require_access(interaction, "anti_nsfw"): return
    db_exec("UPDATE guild_config SET antinsfw_enabled=?, antinsfw_action=? WHERE guild_id=?",
            (int(enabled), action.value if action else "delete", interaction.guild.id))
    await interaction.response.send_message(
        "Anti-NSFW text filter configuration saved. Note: this is a basic text-pattern filter, not image/video detection.",
        ephemeral=True)

# ------------------------------ STAFF ACCESS ------------------------------

@tree.command(name="moderation_access", description="Manage a staff member's HIGH/MEDIUM/LOW access")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="List", value="list"),
    app_commands.Choice(name="Edit level", value="edit")
], level=[
    app_commands.Choice(name="LOW", value="LOW"),
    app_commands.Choice(name="MEDIUM", value="MEDIUM"),
    app_commands.Choice(name="HIGH", value="HIGH")
])
async def moderation_access(interaction: discord.Interaction,
                            operation: app_commands.Choice[str],
                            member: discord.Member = None,
                            level: app_commands.Choice[str] = None):
    if not await require_access(interaction, "moderation_access"): return
    gid = interaction.guild.id
    if operation.value == "list":
        rows = db_all("SELECT user_id,level FROM access_levels WHERE guild_id=? ORDER BY level", (gid,))
        body = "\n".join(f"<@{r['user_id']}> — **{r['level']}**" for r in rows) or "No staff entries."
        await interaction.response.send_message(body, ephemeral=True); return
    if member is None:
        await interaction.response.send_message("Select a member.", ephemeral=True); return
    if member.id == interaction.guild.owner_id or is_owner(member.id):
        await interaction.response.send_message("The server/bot owner access cannot be changed here.", ephemeral=True); return
    if operation.value == "remove":
        db_exec("DELETE FROM access_levels WHERE guild_id=? AND user_id=?", (gid, member.id))
        db_exec("DELETE FROM access_commands WHERE guild_id=? AND user_id=?", (gid, member.id))
        await interaction.response.send_message(f"Removed NOVASTRAP access for {member.mention}.", ephemeral=True); return
    if level is None:
        await interaction.response.send_message("Choose a level.", ephemeral=True); return
    # Only the configured bot owner or server owner may assign HIGH.
    if level.value == "HIGH" and not is_owner(interaction.user.id):
        await interaction.response.send_message("Only the configured NOVASTRAP bot owner can assign HIGH.", ephemeral=True); return
    db_exec("""INSERT INTO access_levels(guild_id,user_id,level) VALUES(?,?,?)
               ON CONFLICT(guild_id,user_id) DO UPDATE SET level=excluded.level""",
            (gid, member.id, level.value))
    await interaction.response.send_message(f"{member.mention} now has **{level.value}** access.", ephemeral=True)
    await send_log(interaction.guild, "Staff Access Updated",
                   f"**Member:** {member.mention}\n**Level:** {level.value}\n**Changed by:** {interaction.user}")

# ------------------------------ BYPASS LISTS ------------------------------

@tree.command(name="bypass_member", description="Add or remove a member from security bypass")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="List", value="list")
])
async def bypass_member(interaction: discord.Interaction, operation: app_commands.Choice[str],
                        member: discord.Member = None):
    if not await require_access(interaction, "bypass"): return
    gid = interaction.guild.id
    if operation.value == "list":
        rows = db_all("SELECT user_id FROM bypass_members WHERE guild_id=?", (gid,))
        await interaction.response.send_message("\n".join(f"<@{r['user_id']}>" for r in rows) or "Empty.", ephemeral=True); return
    if member is None:
        await interaction.response.send_message("Select a member.", ephemeral=True); return
    if operation.value == "add":
        db_exec("INSERT OR IGNORE INTO bypass_members VALUES(?,?)", (gid, member.id))
    else:
        db_exec("DELETE FROM bypass_members WHERE guild_id=? AND user_id=?", (gid, member.id))
    await interaction.response.send_message("Bypass list updated.", ephemeral=True)

@tree.command(name="bypass_bot", description="Add or remove a bot from security bypass")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="List", value="list")
])
async def bypass_bot(interaction: discord.Interaction, operation: app_commands.Choice[str],
                     user: discord.User = None):
    if not await require_access(interaction, "bypass"): return
    gid = interaction.guild.id
    if operation.value == "list":
        rows = db_all("SELECT user_id FROM bypass_bots WHERE guild_id=?", (gid,))
        await interaction.response.send_message("\n".join(f"<@{r['user_id']}>" for r in rows) or "Empty.", ephemeral=True); return
    if user is None or not user.bot:
        await interaction.response.send_message("Select a bot account.", ephemeral=True); return
    if operation.value == "add":
        db_exec("INSERT OR IGNORE INTO bypass_bots VALUES(?,?)", (gid, user.id))
    else:
        db_exec("DELETE FROM bypass_bots WHERE guild_id=? AND user_id=?", (gid, user.id))
    await interaction.response.send_message("Bot bypass list updated.", ephemeral=True)

# ------------------------------ PREMIUM (BOT OWNER ONLY) ------------------------------

@tree.command(name="server_prem", description="Bot-owner-only premium server management")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="List", value="list")
])
async def server_prem(interaction: discord.Interaction, operation: app_commands.Choice[str],
                      guild_id: str = None):
    if not is_owner(interaction.user.id):
        await interaction.response.send_message("Only the NOVASTRAP bot owner can manage server premium.", ephemeral=True); return
    if operation.value == "list":
        rows = db_all("SELECT guild_id FROM guild_config WHERE premium=1")
        await interaction.response.send_message("\n".join(str(r["guild_id"]) for r in rows) or "No premium servers.", ephemeral=True); return
    if not guild_id or not guild_id.isdigit():
        await interaction.response.send_message("Provide a valid server ID.", ephemeral=True); return
    gid = int(guild_id)
    db_exec("INSERT OR IGNORE INTO guild_config(guild_id) VALUES(?)", (gid,))
    db_exec("UPDATE guild_config SET premium=? WHERE guild_id=?", (1 if operation.value == "add" else 0, gid))
    await interaction.response.send_message(f"Premium {operation.value} completed for server `{gid}`.", ephemeral=True)

# ------------------------------ LEVELS / XP ------------------------------

@tree.command(name="setup_level", description="Enable or disable the server leveling system")
async def setup_level(interaction: discord.Interaction, enabled: bool,
                      channel: discord.TextChannel = None):
    if not await require_access(interaction, "setup_level"): return
    db_exec("UPDATE guild_config SET level_enabled=?, level_channel_id=? WHERE guild_id=?",
            (int(enabled), channel.id if channel else None, interaction.guild.id))
    await interaction.response.send_message(f"Level system {'enabled' if enabled else 'disabled'}.", ephemeral=True)

@tree.command(name="lb", description="Show the server XP leaderboard")
async def lb(interaction: discord.Interaction):
    if not await require_access(interaction, "leaderboard"): return
    rows = db_all("SELECT user_id,xp,level FROM levels WHERE guild_id=? ORDER BY xp DESC LIMIT 10",
                  (interaction.guild.id,))
    body = "\n".join(f"**{i}.** <@{r['user_id']}> — Level {r['level']} ({r['xp']} XP)"
                     for i, r in enumerate(rows, 1)) or "No XP data yet."
    await interaction.response.send_message(embed=discord.Embed(title="NOVASTRAP Leaderboard",
        description=body, color=discord.Color.blurple()))

@tree.command(name="xp", description="Add, remove, set or reset a member's XP")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="Set", value="set"),
    app_commands.Choice(name="Reset", value="reset")
])
async def xp_cmd(interaction: discord.Interaction, operation: app_commands.Choice[str],
                 member: discord.Member, amount: app_commands.Range[int, 0, 100000] = 0):
    if not await require_access(interaction, "setup_level"): return
    row = db_one("SELECT xp FROM levels WHERE guild_id=? AND user_id=?",
                 (interaction.guild.id, member.id))
    current = row["xp"] if row else 0
    if operation.value == "add": value = current + amount
    elif operation.value == "remove": value = max(0, current - amount)
    elif operation.value == "set": value = amount
    else: value = 0
    level = int((value / 100) ** 0.5)
    db_exec("""INSERT INTO levels(guild_id,user_id,xp,level) VALUES(?,?,?,?)
               ON CONFLICT(guild_id,user_id) DO UPDATE SET xp=excluded.xp, level=excluded.level""",
            (interaction.guild.id, member.id, value, level))
    await interaction.response.send_message(f"{member.mention}: **{value} XP**, Level **{level}**.", ephemeral=True)

# ------------------------------ AUTORESPONDER ------------------------------

@tree.command(name="autoresponder", description="Add, remove, list or edit an exact-match autoresponder")
@app_commands.choices(operation=[
    app_commands.Choice(name="Add", value="add"),
    app_commands.Choice(name="Remove", value="remove"),
    app_commands.Choice(name="List", value="list"),
    app_commands.Choice(name="Edit", value="edit")
])
async def autoresponder(interaction: discord.Interaction, operation: app_commands.Choice[str],
                        trigger: str = None, response_text: str = None):
    if not await require_access(interaction, "automod"): return
    gid = interaction.guild.id
    if operation.value == "list":
        rows = db_all("SELECT trigger,response FROM autoresponders WHERE guild_id=?", (gid,))
        body = "\n".join(f"`{r['trigger']}` → {r['response'][:100]}" for r in rows) or "No autoresponders."
        await interaction.response.send_message(body, ephemeral=True); return
    if not trigger:
        await interaction.response.send_message("Provide a trigger phrase.", ephemeral=True); return
    if operation.value == "remove":
        db_exec("DELETE FROM autoresponders WHERE guild_id=? AND trigger=?", (gid, trigger))
        await interaction.response.send_message("Autoresponder removed.", ephemeral=True); return
    if not response_text:
        await interaction.response.send_message("Provide a response.", ephemeral=True); return
    db_exec("""INSERT INTO autoresponders(guild_id,trigger,response) VALUES(?,?,?)
               ON CONFLICT(guild_id,trigger) DO UPDATE SET response=excluded.response""",
            (gid, trigger, response_text))
    await interaction.response.send_message("Autoresponder saved.", ephemeral=True)

# ------------------------------ POLL ------------------------------

@tree.command(name="poll", description="Create a simple yes/no poll")
async def poll(interaction: discord.Interaction, question: str):
    if not await require_access(interaction, "poll"): return
    embed = discord.Embed(title="Community Poll", description=question, color=discord.Color.blurple())
    await interaction.response.send_message(embed=embed)
    msg = await interaction.original_response()
    await msg.add_reaction("👍")
    await msg.add_reaction("👎")

# ------------------------------ SNIPE / PREFIX SHORTCUTS ------------------------------

snipes = {}

@bot.event
async def on_message_delete_for_snipe(message):
    pass

@tree.command(name="snipe", description="Show the most recently deleted message in this channel")
async def snipe(interaction: discord.Interaction):
    item = snipes.get(interaction.channel_id)
    if not item:
        await interaction.response.send_message("No deleted message is cached.", ephemeral=True); return
    await interaction.response.send_message(
        f"**{item['author']}**: {item['content'][:1500]}", ephemeral=True)

# ------------------------------ BACKUP / SAVE ------------------------------

@tree.command(name="save", description="Save a basic server structure snapshot")
async def save(interaction: discord.Interaction):
    if not await require_access(interaction, "backup"): return
    g = interaction.guild
    payload = {
        "name": g.name,
        "roles": [{"name": r.name, "permissions": r.permissions.value,
                   "color": r.color.value, "hoist": r.hoist, "mentionable": r.mentionable}
                  for r in g.roles if not r.is_default() and not r.managed],
        "categories": [c.name for c in g.categories],
        "channels": [{"name": c.name, "type": str(c.type),
                      "category": c.category.name if c.category else None}
                     for c in g.channels if not isinstance(c, discord.CategoryChannel)]
    }
    db_exec("""INSERT INTO saved_backups(guild_id,payload,created_at) VALUES(?,?,?)
               ON CONFLICT(guild_id) DO UPDATE SET payload=excluded.payload, created_at=excluded.created_at""",
            (g.id, json.dumps(payload), datetime.now(timezone.utc).isoformat()))
    await interaction.response.send_message(
        "Server structure snapshot saved. This is a configuration snapshot, not a full restore or member/message backup.",
        ephemeral=True)

@tree.command(name="backup", description="View the saved server structure snapshot")
async def backup(interaction: discord.Interaction):
    if not await require_access(interaction, "backup"): return
    row = db_one("SELECT payload,created_at FROM saved_backups WHERE guild_id=?", (interaction.guild.id,))
    if not row:
        await interaction.response.send_message("No saved snapshot. Run /save first.", ephemeral=True); return
    data = json.loads(row["payload"])
    await interaction.response.send_message(
        f"Snapshot saved: `{row['created_at']}`\n"
        f"Roles: **{len(data['roles'])}**\nCategories: **{len(data['categories'])}**\n"
        f"Channels: **{len(data['channels'])}**\n\n"
        "This release stores a snapshot for reference; automatic destructive restoration is intentionally not enabled.",
        ephemeral=True)

# ------------------------------ GIVEAWAY ------------------------------

@tree.command(name="giveaway_create", description="Create a timed giveaway")
async def giveaway_create(interaction: discord.Interaction, duration_minutes: app_commands.Range[int, 1, 10080],
                          prize: str):
    if not await require_access(interaction, "giveaway"): return
    ends = time.time() + duration_minutes * 60
    embed = discord.Embed(title="Giveaway", description=f"Prize: **{prize}**\nReact with 🎉 to enter.\nEnds <t:{int(ends)}:R>",
                          color=discord.Color.gold())
    await interaction.response.send_message(embed=embed)
    msg = await interaction.original_response()
    await msg.add_reaction("🎉")
    db_exec("INSERT INTO giveaways(message_id,guild_id,channel_id,prize,ends_at) VALUES(?,?,?,?,?)",
            (msg.id, interaction.guild.id, interaction.channel_id, prize, ends))

@tasks.loop(seconds=30)
async def giveaway_worker():
    rows = db_all("SELECT * FROM giveaways WHERE ended=0 AND ends_at<=?", (time.time(),))
    for row in rows:
        channel = bot.get_channel(row["channel_id"])
        winner_text = "No eligible entries."
        if channel:
            try:
                msg = await channel.fetch_message(row["message_id"])
                reaction = discord.utils.get(msg.reactions, emoji="🎉")
                if reaction:
                    users = [u async for u in reaction.users() if not u.bot]
                    if users:
                        winner_text = f"Winner: {users[0].mention}"
                await channel.send(f"Giveaway ended — **{row['prize']}**\n{winner_text}")
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                pass
        db_exec("UPDATE giveaways SET ended=1 WHERE message_id=?", (row["message_id"],))

@giveaway_worker.before_loop
async def before_giveaway_worker():
    await bot.wait_until_ready()

# ------------------------------ ERROR HANDLING ------------------------------

@tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    log.exception("Application command error", exc_info=error)
    message = "The command failed. Check the bot logs and confirm the bot has the required Discord permissions."
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass

if __name__ == "__main__":
    bot.run(TOKEN)
