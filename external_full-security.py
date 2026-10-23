import os
import time
import random
import sqlite3
import asyncio
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

import discord
from discord import app_commands
from discord.ext import commands

# ============================================================
# EXTERNAL | FULL SECURITY
# Multi-server Discord security and moderation bot
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN").strip()

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


# ============================================================
# SERVER SETTINGS / BASIC ANTI-NUKE MONITORING
# ============================================================

@bot.event
async def on_guild_update(before, after):
    changes = []
    for label, old, new in [
        ("Server name", before.name, after.name),
        ("Verification level", str(before.verification_level),
         str(after.verification_level)),
        ("Default notifications", str(before.default_notifications),
         str(after.default_notifications))
    ]:
        if old != new:
            changes.append(f"{label}: `{old}` -> `{new}`")

    if not changes:
        return

    actor, reason = await audit_actor(
        after, discord.AuditLogAction.guild_update
    )
    settings = get_settings(after.id)

    await send_log(
        after, "Server Settings Updated",
        f"Changed by: {actor or 'Unknown'}\n"
        + "\n".join(changes)
        + f"\nReason: {text_or_unknown(reason)}",
        discord.Color.orange() if settings["antinuke"] else discord.Color.blurple()
    )


# ============================================================
# ANTI-SPAM AND AUTORESPONDER
# ============================================================

@bot.event
async def on_message(message):
    if message.guild is None or message.author.bot:
        return

    settings = get_settings(message.guild.id)

    if settings["antispam"] and not is_authorized(
        message.guild.id, message.author.id
    ):
        key = (message.guild.id, message.author.id)
        now = time.monotonic()
        queue = spam_cache[key]
        queue.append(now)

        while queue and now - queue[0] > settings["spam_window"]:
            queue.popleft()

        if len(queue) >= settings["spam_limit"]:
            queue.clear()

            try:
                await message.channel.purge(
                    limit=settings["spam_limit"],
                    check=lambda m: m.author.id == message.author.id
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

            try:
                action = settings["spam_action"]
                if action == "kick":
                    await message.author.kick(reason="Automatic anti-spam")
                elif action == "ban":
                    await message.author.ban(reason="Automatic anti-spam")
                else:
                    await message.author.timeout(
                        timedelta(minutes=1),
                        reason="Automatic anti-spam"
                    )
            except (discord.Forbidden, discord.HTTPException):
                pass

            await send_log(
                message.guild, "Anti-Spam Triggered",
                f"Member: {message.author} (`{message.author.id}`)\n"
                f"Channel: {message.channel.mention}\n"
                f"Configured action: {settings['spam_action']}"
            )

    with db_connect() as db:
        responders = db.execute(
            "SELECT trigger, response FROM autoresponders WHERE guild_id = ?",
            (message.guild.id,)
        ).fetchall()

    content = message.content.casefold()
    for trigger, response in responders:
        if trigger in content:
            await message.channel.send(
                response,
                allowed_mentions=discord.AllowedMentions.none()
            )
            break

    await bot.process_commands(message)


# ============================================================
# COMMAND PERMISSION HELPER
# ============================================================

def manage_guild_only():
    return app_commands.checks.has_permissions(manage_guild=True)


# ============================================================
# LOG CHANNEL AND HELP
# ============================================================

@bot.tree.command(
    name="all-logs-channel",
    description="Set the central channel for server logs."
)
@app_commands.describe(channel="The channel where activity logs will be sent.")
@manage_guild_only()
async def all_logs_channel(
    interaction: discord.Interaction,
    channel: discord.TextChannel
):
    set_setting(interaction.guild_id, "log_channel_id", channel.id)
    await interaction.response.send_message(
        f"Central logging channel set to {channel.mention}.",
        ephemeral=True
    )
    await send_log(
        interaction.guild, "Logging Configured",
        f"Set by: {interaction.user}\nChannel: {channel.mention}"
    )


@bot.tree.command(name="help", description="Show available bot commands.")
async def help_command(interaction: discord.Interaction):
    await interaction.response.send_message(
        "**Logging**\n"
        "`/all-logs-channel channel:` Set central log channel.\n\n"
        "**Moderation**\n"
        "`/kick member reason:` Kick a member.\n"
        "`/ban member reason:` Ban a member.\n"
        "`/addmembersrole member role:` Add a role.\n\n"
        "**Security**\n"
        "`/antinuke enabled:` Toggle server-change monitoring.\n"
        "`/antispam enabled:` Toggle anti-spam.\n"
        "`/antibot enabled:` Toggle untrusted-bot alerts.\n"
        "`/spam-action action:` Set spam punishment.\n"
        "`/authorize-member member:` Allow spam bypass.\n"
        "`/trust-bot bot_member:` Trust a bot.\n"
        "`/security-settings:` View settings.\n\n"
        "**Other**\n"
        "`/announcement channel message:` Send an announcement.\n"
        "`/autoresponder-add trigger response:` Add a responder.\n"
        "`/autoresponder-remove trigger:` Remove a responder.\n"
        "`/giveaway channel minutes prize:` Start a giveaway.",
        ephemeral=True
    )


# ============================================================
# MODERATION COMMANDS
# ============================================================

@bot.tree.command(name="kick", description="Kick a server member.")
@app_commands.checks.has_permissions(kick_members=True)
async def kick(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if member.id == interaction.user.id:
        await interaction.response.send_message(
            "You cannot kick yourself.", ephemeral=True
        )
        return

    if member.top_role >= interaction.user.top_role and not is_owner(interaction.user.id):
        await interaction.response.send_message(
            "The target has an equal or higher role.", ephemeral=True
        )
        return

    await member.kick(reason=reason)
    await interaction.response.send_message(
        f"Kicked {member}.", ephemeral=True
    )
    await send_log(
        interaction.guild, "Member Kicked",
        f"Member: {member} (`{member.id}`)\n"
        f"By: {interaction.user}\nReason: {reason}"
    )


@bot.tree.command(name="ban", description="Ban a server member.")
@app_commands.checks.has_permissions(ban_members=True)
async def ban(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if member.id == interaction.user.id:
        await interaction.response.send_message(
            "You cannot ban yourself.", ephemeral=True
        )
        return

    if member.top_role >= interaction.user.top_role and not is_owner(interaction.user.id):
        await interaction.response.send_message(
            "The target has an equal or higher role.", ephemeral=True
        )
        return

    await member.ban(reason=reason)
    await interaction.response.send_message(
        f"Banned {member}.", ephemeral=True
    )
    await send_log(
        interaction.guild, "Member Banned",
        f"Member: {member} (`{member.id}`)\n"
        f"By: {interaction.user}\nReason: {reason}",
        discord.Color.red()
    )


@bot.tree.command(
    name="addmembersrole",
    description="Add a role to a member."
)
@app_commands.checks.has_permissions(manage_roles=True)
async def addmembersrole(
    interaction: discord.Interaction,
    member: discord.Member,
    role: discord.Role
):
    bot_member = interaction.guild.me

    if role >= bot_member.top_role:
        await interaction.response.send_message(
            "That role is above or equal to the bot's highest role.",
            ephemeral=True
        )
        return

    if role >= interaction.user.top_role and not is_owner(interaction.user.id):
        await interaction.response.send_message(
            "That role is above or equal to your highest role.",
            ephemeral=True
        )
        return

    await member.add_roles(role, reason=f"Requested by {interaction.user}")
    await interaction.response.send_message(
        f"Added {role.name} to {member}.", ephemeral=True
    )
    await send_log(
        interaction.guild, "Role Added by Command",
        f"Member: {member}\nRole: {role.name}\nBy: {interaction.user}"
    )


# ============================================================
# SECURITY TOGGLES
# ============================================================

async def toggle_setting(interaction, name, enabled):
    set_setting(interaction.guild_id, name, int(enabled))
    await interaction.response.send_message(
        f"{name.title()} is now {'enabled' if enabled else 'disabled'}.",
        ephemeral=True
    )


@bot.tree.command(name="antinuke", description="Toggle basic anti-nuke monitoring.")
@manage_guild_only()
async def antinuke(interaction: discord.Interaction, enabled: bool):
    await toggle_setting(interaction, "antinuke", enabled)


@bot.tree.command(name="antispam", description="Toggle anti-spam protection.")
@manage_guild_only()
async def antispam(interaction: discord.Interaction, enabled: bool):
    await toggle_setting(interaction, "antispam", enabled)


@bot.tree.command(name="antibot", description="Toggle untrusted-bot alerts.")
@manage_guild_only()
async def antibot(interaction: discord.Interaction, enabled: bool):
    await toggle_setting(interaction, "antibot", enabled)


@bot.tree.command(name="spam-action", description="Choose the anti-spam punishment.")
@manage_guild_only()
@app_commands.choices(action=[
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def spam_action(
    interaction: discord.Interaction,
    action: app_commands.Choice[str]
):
    set_setting(interaction.guild_id, "spam_action", action.value)
    await interaction.response.send_message(
        f"Anti-spam action set to {action.name}.", ephemeral=True
    )


@bot.tree.command(
    name="security-settings",
    description="Show this server's security settings."
)
@manage_guild_only()
async def security_settings(interaction: discord.Interaction):
    s = get_settings(interaction.guild_id)
    channel = (
        f"<#{s['log_channel_id']}>"
        if s["log_channel_id"] else "Not configured"
    )

    await interaction.response.send_message(
        f"Log channel: {channel}\n"
        f"Anti-spam: {'ON' if s['antispam'] else 'OFF'}\n"
        f"Anti-nuke monitoring: {'ON' if s['antinuke'] else 'OFF'}\n"
        f"Anti-bot alerts: {'ON' if s['antibot'] else 'OFF'}\n"
        f"Spam limit: {s['spam_limit']} messages in {s['spam_window']} seconds\n"
        f"Spam action: {s['spam_action']}",
        ephemeral=True
    )


@bot.tree.command(
    name="authorize-member",
    description="Allow a member to bypass anti-spam."
)
@manage_guild_only()
async def authorize_member(
    interaction: discord.Interaction,
    member: discord.Member
):
    with db_connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO authorized_members VALUES (?, ?)",
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{member} is now authorized.", ephemeral=True
    )


@bot.tree.command(name="trust-bot", description="Add a bot to the trusted list.")
@manage_guild_only()
async def trust_bot(
    interaction: discord.Interaction,
    bot_member: discord.Member
):
    if not bot_member.bot:
        await interaction.response.send_message(
            "Select a bot account.", ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO trusted_bots VALUES (?, ?)",
            (interaction.guild_id, bot_member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{bot_member} added to the trusted-bot list.",
        ephemeral=True
    )


# ============================================================
# ANNOUNCEMENTS
# ============================================================

@bot.tree.command(name="announcement", description="Send a server announcement.")
@manage_guild_only()
async def announcement(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    message: str
):
    embed = create_embed("Announcement", message)
    await channel.send(
        embed=embed,
        allowed_mentions=discord.AllowedMentions.none()
    )
    await interaction.response.send_message(
        f"Announcement sent to {channel.mention}.", ephemeral=True
    )
    await send_log(
        interaction.guild, "Announcement Sent",
        f"By: {interaction.user}\nChannel: {channel.mention}"
    )


# ============================================================
# AUTORESPONDER
# ============================================================

@bot.tree.command(
    name="autoresponder-add",
    description="Add a keyword response."
)
@manage_guild_only()
async def autoresponder_add(
    interaction: discord.Interaction,
    trigger: str,
    response: str
):
    if len(trigger) > 100 or len(response) > 1500:
        await interaction.response.send_message(
            "Trigger limit is 100 characters; response limit is 1500.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO autoresponders VALUES (?, ?, ?)",
            (interaction.guild_id, trigger.casefold(), response)
        )
        db.commit()

    await interaction.response.send_message(
        f"Autoresponder added for `{trigger}`.", ephemeral=True
    )


@bot.tree.command(
    name="autoresponder-remove",
    description="Remove a keyword response."
)
@manage_guild_only()
async def autoresponder_remove(
    interaction: discord.Interaction,
    trigger: str
):
    with db_connect() as db:
        cursor = db.execute(
            "DELETE FROM autoresponders WHERE guild_id = ? AND trigger = ?",
            (interaction.guild_id, trigger.casefold())
        )
        db.commit()

    await interaction.response.send_message(
        "Autoresponder removed." if cursor.rowcount else "Trigger not found.",
        ephemeral=True
    )


# ============================================================
# GIVEAWAY
# ============================================================

async def finish_giveaway(channel_id, message_id, guild_id, prize):
    try:
        await asyncio.sleep(60)  # replaced by the command's duration below
    except asyncio.CancelledError:
        return


@bot.tree.command(name="giveaway", description="Start a timed giveaway.")
@manage_guild_only()
async def giveaway(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    minutes: app_commands.Range[int, 1, 10080],
    prize: str
):
    if len(prize) > 200:
        await interaction.response.send_message(
            "Prize description must be 200 characters or fewer.",
            ephemeral=True
        )
        return

    end_timestamp = int(time.time()) + minutes * 60
    embed = create_embed(
        "Giveaway",
        f"Prize: {prize}\n"
        f"Hosted by: {interaction.user.mention}\n"
        f"Ends: <t:{end_timestamp}:R>\n\n"
        "React with the giveaway reaction to enter."
    )

    message = await channel.send(embed=embed)
    await message.add_reaction("🎉")

    await interaction.response.send_message(
        f"Giveaway started in {channel.mention}.", ephemeral=True
    )

    async def end_giveaway():
        await asyncio.sleep(minutes * 60)
        try:
            current = await channel.fetch_message(message.id)
            reaction = discord.utils.get(current.reactions, emoji="🎉")

            if reaction is None:
                await channel.send(f"Giveaway ended. No winner for: {prize}")
                return

            entrants = [
                user async for user in reaction.users()
                if not user.bot
            ]

            if not entrants:
                await channel.send(f"Giveaway ended. No entries for: {prize}")
                return

            winner = random.choice(entrants)
            await channel.send(
                f"Giveaway ended. Winner: {winner.mention}. Prize: {prize}"
            )
            await send_log(
                interaction.guild, "Giveaway Ended",
                f"Prize: {prize}\nWinner: {winner}\nChannel: {channel.mention}"
            )
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

    task = asyncio.create_task(end_giveaway())
    giveaway_tasks[message.id] = task


# ============================================================
# COMMAND ERROR HANDLING
# ============================================================

@bot.tree.error
async def on_app_command_error(interaction, error):
    if isinstance(error, app_commands.MissingPermissions):
        message = "You do not have permission to use this command."
    elif isinstance(error, app_commands.CheckFailure):
        message = "You are not authorized to use this command."
    else:
        print(f"Slash command error: {repr(error)}")
        message = "The command failed. Check the bot console."

    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    init_db()

    if not TOKEN:
        raise SystemExit(
            "DISCORD_TOKEN is missing. Set it in your hosting environment."
        )

    bot.run(TOKEN)
