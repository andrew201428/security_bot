import os
import time
import random
import sqlite3
import asyncio
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

import discord
from aiohttp import web
from discord import app_commands
from discord.ext import commands

# ============================================================
# EXTERNAL | FULL SECURITY
# Multi-server Discord security and moderation bot
# ============================================================

TOKEN = (os.getenv("DISCORD_TOKEN") or "").strip()

# Global bot owner. Keep your owner ID here.
OWNER_IDS = {1460495693536825479}

DATABASE = "external_security.db"

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True
intents.moderation = True
intents.invites = True

bot = commands.Bot(command_prefix="!", intents=intents)

spam_cache = defaultdict(deque)
invite_cache = {}
giveaway_tasks = {}


# ============================================================
# DATABASE
# ============================================================

def db_connect():
    return sqlite3.connect(DATABASE)


def init_db():
    with db_connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                guild_id INTEGER PRIMARY KEY,
                log_channel_id INTEGER,
                antispam INTEGER NOT NULL DEFAULT 1,
                antinuke INTEGER NOT NULL DEFAULT 1,
                antibot INTEGER NOT NULL DEFAULT 1,
                spam_limit INTEGER NOT NULL DEFAULT 5,
                spam_window INTEGER NOT NULL DEFAULT 5,
                spam_action TEXT NOT NULL DEFAULT 'timeout'
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS authorized_members (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS trusted_bots (
                guild_id INTEGER NOT NULL,
                bot_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, bot_id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS autoresponders (
                guild_id INTEGER NOT NULL,
                trigger TEXT NOT NULL,
                response TEXT NOT NULL,
                PRIMARY KEY (guild_id, trigger)
            )
        """)

        db.commit()


def get_settings(guild_id):
    with db_connect() as db:
        row = db.execute(
            "SELECT log_channel_id, antispam, antinuke, antibot, "
            "spam_limit, spam_window, spam_action "
            "FROM settings WHERE guild_id = ?",
            (guild_id,)
        ).fetchone()

        if row is None:
            db.execute(
                "INSERT OR IGNORE INTO settings (guild_id) VALUES (?)",
                (guild_id,)
            )
            db.commit()
            return {
                "log_channel_id": None,
                "antispam": True,
                "antinuke": True,
                "antibot": True,
                "spam_limit": 5,
                "spam_window": 5,
                "spam_action": "timeout"
            }

    return {
        "log_channel_id": row[0],
        "antispam": bool(row[1]),
        "antinuke": bool(row[2]),
        "antibot": bool(row[3]),
        "spam_limit": row[4],
        "spam_window": row[5],
        "spam_action": row[6]
    }


def set_setting(guild_id, name, value):
    allowed = {
        "log_channel_id", "antispam", "antinuke", "antibot",
        "spam_limit", "spam_window", "spam_action"
    }
    if name not in allowed:
        raise ValueError("Invalid setting")

    get_settings(guild_id)

    with db_connect() as db:
        db.execute(
            f"UPDATE settings SET {name} = ? WHERE guild_id = ?",
            (value, guild_id)
        )
        db.commit()


def is_owner(user_id):
    return user_id in OWNER_IDS


def is_authorized(guild_id, user_id):
    if is_owner(user_id):
        return True

    with db_connect() as db:
        row = db.execute(
            "SELECT 1 FROM authorized_members "
            "WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id)
        ).fetchone()

    return row is not None


def is_trusted_bot(guild_id, bot_id):
    with db_connect() as db:
        row = db.execute(
            "SELECT 1 FROM trusted_bots WHERE guild_id = ? AND bot_id = ?",
            (guild_id, bot_id)
        ).fetchone()

    return row is not None


# ============================================================
# EMBEDS AND CENTRAL LOGGING
# ============================================================

def text_or_unknown(value, limit=900):
    if value is None:
        return "Unknown"
    value = str(value)
    return value[:limit] if value else "(empty)"


def create_embed(title, description, color=None):
    embed = discord.Embed(
        title=title,
        description=description[:4000],
        color=color or discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_footer(text="EXTERNAL | FULL SECURITY")
    return embed


async def send_log(guild, title, description, color=None, jump_url=None):
    if guild is None:
        return

    channel_id = get_settings(guild.id)["log_channel_id"]
    if not channel_id:
        return

    channel = guild.get_channel(channel_id)
    if channel is None:
        try:
            channel = await guild.fetch_channel(channel_id)
        except (discord.HTTPException, discord.Forbidden):
            return

    if not isinstance(channel, discord.TextChannel):
        return

    embed = create_embed(title, description, color)

    if jump_url:
        embed.add_field(
            name="Message link",
            value=f"[Open message]({jump_url})",
            inline=False
        )

    try:
        await channel.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none()
        )
    except discord.HTTPException:
        pass


async def audit_actor(guild, action, target_id=None):
    """Best-effort lookup; Discord may not identify the actor."""
    try:
        async for entry in guild.audit_logs(limit=8, action=action):
            if target_id is not None:
                if getattr(entry.target, "id", None) != target_id:
                    continue

            age = (discord.utils.utcnow() - entry.created_at).total_seconds()
            if 0 <= age <= 15:
                return entry.user, entry.reason
    except (discord.Forbidden, discord.HTTPException):
        pass

    return None, None


# ============================================================
# BOT STARTUP AND INVITES
# ============================================================

async def update_invite_cache(guild):
    try:
        invites = await guild.invites()
        invite_cache[guild.id] = {
            inv.code: {
                "uses": inv.uses or 0,
                "inviter_id": inv.inviter.id if inv.inviter else None,
                "channel_id": inv.channel.id if inv.channel else None
            }
            for inv in invites
        }
    except (discord.Forbidden, discord.HTTPException):
        invite_cache[guild.id] = {}


@bot.event
async def setup_hook():
    init_db()
    try:
        synced = await bot.tree.sync()
        print(f"Registered {len(synced)} slash commands.")
    except discord.HTTPException as exc:
        print(f"Slash command sync failed: {exc}")


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} ({bot.user.id})")
    for guild in bot.guilds:
        await update_invite_cache(guild)


@bot.event
async def on_guild_join(guild):
    await update_invite_cache(guild)


@bot.event
async def on_invite_create(invite):
    await update_invite_cache(invite.guild)
    await send_log(
        invite.guild,
        "Invite Created",
        f"Code: `{invite.code}`\n"
        f"Creator: {invite.inviter or 'Unknown'}\n"
        f"Channel: {invite.channel or 'Unknown'}"
    )


@bot.event
async def on_invite_delete(invite):
    await send_log(
        invite.guild,
        "Invite Deleted",
        f"Code: `{invite.code}`\n"
        f"Channel: {invite.channel or 'Unknown'}"
    )
    await update_invite_cache(invite.guild)


# ============================================================
# MESSAGE EDIT AND DELETE LOGS
# Normal messages are not logged.
# ============================================================

@bot.event
async def on_message_edit(before, after):
    if before.guild is None or before.author.bot:
        return
    if before.content == after.content:
        return

    url = (
        f"https://discord.com/channels/"
        f"{before.guild.id}/{before.channel.id}/{before.id}"
    )

    await send_log(
        before.guild,
        "Message Edited",
        f"Author: {before.author} (`{before.author.id}`)\n"
        f"Channel: {before.channel.mention}\n\n"
        f"Before:\n{text_or_unknown(before.content)}\n\n"
        f"After:\n{text_or_unknown(after.content)}",
        jump_url=url
    )


@bot.event
async def on_message_delete(message):
    if message.guild is None or message.author.bot:
        return

    actor, reason = await audit_actor(
        message.guild,
        discord.AuditLogAction.message_delete,
        message.author.id
    )

    url = (
        f"https://discord.com/channels/"
        f"{message.guild.id}/{message.channel.id}/{message.id}"
    )

    await send_log(
        message.guild,
        "Message Deleted",
        f"Original author: {message.author} (`{message.author.id}`)\n"
        f"Channel: {message.channel.mention}\n"
        f"Deleted by: {actor or 'Unknown'}\n"
        f"Reason: {text_or_unknown(reason)}\n\n"
        f"Cached content:\n{text_or_unknown(message.content)}",
        discord.Color.red(),
        jump_url=url
    )


# ============================================================
# MEMBER, ROLE, AND BOT LOGS
# ============================================================

@bot.event
async def on_member_join(member):
    await send_log(
        member.guild,
        "Member Joined",
        f"Member: {member} (`{member.id}`)\n"
        f"Account created: {member.created_at.strftime('%Y-%m-%d %H:%M UTC')}"
    )

    if not member.bot:
        return

    actor, reason = await audit_actor(
        member.guild, discord.AuditLogAction.bot_add, member.id
    )

    old = invite_cache.get(member.guild.id, {})
    await update_invite_cache(member.guild)
    new = invite_cache.get(member.guild.id, {})

    used = None
    for code, data in new.items():
        previous_uses = old.get(code, {}).get("uses", 0)
        if data["uses"] > previous_uses:
            used = data
            break

    inviter = str(actor) if actor else "Unknown"
    invite_channel = "Unknown"

    if used:
        if used["inviter_id"]:
            inviter = f"<@{used['inviter_id']}>"
        if used["channel_id"]:
            ch = member.guild.get_channel(used["channel_id"])
            if ch:
                invite_channel = ch.mention

    await send_log(
        member.guild,
        "Bot Joined",
        f"Bot: {member} (`{member.id}`)\n"
        f"Inviter: {inviter}\n"
        f"Invite channel: {invite_channel}\n"
        f"Audit reason: {text_or_unknown(reason)}"
    )

    settings = get_settings(member.guild.id)
    if settings["antibot"] and not is_trusted_bot(member.guild.id, member.id):
        await send_log(
            member.guild,
            "Untrusted Bot Alert",
            f"Bot: {member} (`{member.id}`)\n"
            f"Inviter: {inviter}\n"
            "This bot is not on the trusted-bot list.",
            discord.Color.orange()
        )


@bot.event
async def on_member_remove(member):
    actor, reason = await audit_actor(
        member.guild, discord.AuditLogAction.kick, member.id
    )
    await send_log(
        member.guild,
        "Member Left or Was Removed",
        f"Member: {member} (`{member.id}`)\n"
        f"Possible kick executor: {actor or 'Unknown'}\n"
        f"Reason: {text_or_unknown(reason)}"
    )


@bot.event
async def on_member_update(before, after):
    old_roles = {r.id: r for r in before.roles}
    new_roles = {r.id: r for r in after.roles}

    added = [r for rid, r in new_roles.items() if rid not in old_roles]
    removed = [r for rid, r in old_roles.items() if rid not in new_roles]

    if added or removed:
        actor, reason = await audit_actor(
            after.guild,
            discord.AuditLogAction.member_role_update,
            after.id
        )

        if added:
            await send_log(
                after.guild,
                "Member Role Added",
                f"Member: {after} (`{after.id}`)\n"
                f"Roles: {', '.join(r.name for r in added)}\n"
                f"Changed by: {actor or 'Unknown'}\n"
                f"Reason: {text_or_unknown(reason)}"
            )

        if removed:
            await send_log(
                after.guild,
                "Member Role Removed",
                f"Member: {after} (`{after.id}`)\n"
                f"Roles: {', '.join(r.name for r in removed)}\n"
                f"Changed by: {actor or 'Unknown'}\n"
                f"Reason: {text_or_unknown(reason)}"
            )

    if before.nick != after.nick:
        await send_log(
            after.guild,
            "Nickname Changed",
            f"Member: {after} (`{after.id}`)\n"
            f"Before: {text_or_unknown(before.nick)}\n"
            f"After: {text_or_unknown(after.nick)}"
        )

    if before.timed_out_until != after.timed_out_until:
        await send_log(
            after.guild,
            "Timeout Updated",
            f"Member: {after} (`{after.id}`)\n"
            f"Before: {text_or_unknown(before.timed_out_until)}\n"
            f"After: {text_or_unknown(after.timed_out_until)}"
        )


# ============================================================
# ROLE AND CHANNEL LOGS
# ============================================================

@bot.event
async def on_guild_role_create(role):
    actor, reason = await audit_actor(
        role.guild, discord.AuditLogAction.role_create, role.id
    )
    await send_log(
        role.guild, "Role Created",
        f"Role: {role.name} (`{role.id}`)\n"
        f"By: {actor or 'Unknown'}\nReason: {text_or_unknown(reason)}"
    )


@bot.event
async def on_guild_role_delete(role):
    actor, reason = await audit_actor(
        role.guild, discord.AuditLogAction.role_delete, role.id
    )
    await send_log(
        role.guild, "Role Deleted",
        f"Role: {role.name} (`{role.id}`)\n"
        f"By: {actor or 'Unknown'}\nReason: {text_or_unknown(reason)}",
        discord.Color.red()
    )


@bot.event
async def on_guild_role_update(before, after):
    changes = []
    for label, old, new in [
        ("Name", before.name, after.name),
        ("Colour", str(before.colour), str(after.colour)),
        ("Hoist", before.hoist, after.hoist),
        ("Mentionable", before.mentionable, after.mentionable),
        ("Permissions", before.permissions.value, after.permissions.value)
    ]:
        if old != new:
            changes.append(f"{label}: `{old}` -> `{new}`")

    if not changes:
        return

    actor, reason = await audit_actor(
        after.guild, discord.AuditLogAction.role_update, after.id
    )
    await send_log(
        after.guild, "Role Updated",
        f"Role: {after.name} (`{after.id}`)\n"
        f"By: {actor or 'Unknown'}\n"
        + "\n".join(changes)
        + f"\nReason: {text_or_unknown(reason)}"
    )


@bot.event
async def on_guild_channel_create(channel):
    actor, reason = await audit_actor(
        channel.guild, discord.AuditLogAction.channel_create, channel.id
    )
    await send_log(
        channel.guild, "Channel Created",
        f"Channel: {channel.name} (`{channel.id}`)\n"
        f"By: {actor or 'Unknown'}\nReason: {text_or_unknown(reason)}"
    )


@bot.event
async def on_guild_channel_delete(channel):
    actor, reason = await audit_actor(
        channel.guild, discord.AuditLogAction.channel_delete, channel.id
    )
    await send_log(
        channel.guild, "Channel Deleted",
        f"Channel: {channel.name} (`{channel.id}`)\n"
        f"By: {actor or 'Unknown'}\nReason: {text_or_unknown(reason)}",
        discord.Color.red()
    )


@bot.event
async def on_guild_channel_update(before, after):
    changes = []
    for label, old, new in [
        ("Name", before.name, after.name),
        ("Category", getattr(before.category, "name", None),
         getattr(after.category, "name", None)),
        ("Position", before.position, after.position),
        ("Topic", getattr(before, "topic", None),
         getattr(after, "topic", None)),
        ("NSFW", getattr(before, "nsfw", None),
         getattr(after, "nsfw", None))
    ]:
        if old != new:
            changes.append(
                f"{label}: `{text_or_unknown(old, 250)}` -> "
                f"`{text_or_unknown(new, 250)}`"
            )

    if not changes:
        return

    actor, reason = await audit_actor(
        after.guild, discord.AuditLogAction.channel_update, after.id
    )
    await send_log(
        after.guild, "Channel Updated",
        f"Channel: {after.name} (`{after.id}`)\n"
        f"By: {actor or 'Unknown'}\n"
        + "\n".join(changes)
        + f"\nReason: {text_or_unknown(reason)}"
    )
