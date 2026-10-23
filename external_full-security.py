import os
import time
import sqlite3
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone

import discord
from discord import app_commands
from discord.ext import commands

# ---------------- CONFIGURATION ----------------

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()

OWNER_IDS = {
    int(value.strip())
    for value in os.getenv("BOT_OWNER_IDS", "").split(",")
    if value.strip().isdigit()
}

DATABASE = "external_security.db"

INTENTS = discord.Intents.default()
INTENTS.guilds = True
INTENTS.members = True
INTENTS.message_content = True
INTENTS.moderation = True
INTENTS.invites = True

bot = commands.Bot(command_prefix="!", intents=INTENTS)

spam_messages = defaultdict(deque)
invite_cache = {}
ready_once = False


# ---------------- DATABASE ----------------

def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                log_channel_id INTEGER,
                anti_spam INTEGER DEFAULT 1,
                anti_nuke INTEGER DEFAULT 1,
                anti_bot INTEGER DEFAULT 1,
                spam_action TEXT DEFAULT 'timeout',
                spam_limit INTEGER DEFAULT 5,
                spam_seconds INTEGER DEFAULT 5
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS autoresponders (
                guild_id INTEGER,
                trigger TEXT,
                response TEXT,
                PRIMARY KEY (guild_id, trigger)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS authorized_members (
                guild_id INTEGER,
                user_id INTEGER,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS trusted_bots (
                guild_id INTEGER,
                bot_id INTEGER,
                PRIMARY KEY (guild_id, bot_id)
            )
        """)

        db.commit()


def get_settings(guild_id):
    with sqlite3.connect(DATABASE) as db:
        row = db.execute(
            "SELECT log_channel_id, anti_spam, anti_nuke, anti_bot, "
            "spam_action, spam_limit, spam_seconds "
            "FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        ).fetchone()

        if row is None:
            db.execute(
                "INSERT INTO guild_settings (guild_id) VALUES (?)",
                (guild_id,)
            )
            db.commit()

            return {
                "log_channel_id": None,
                "anti_spam": 1,
                "anti_nuke": 1,
                "anti_bot": 1,
                "spam_action": "timeout",
                "spam_limit": 5,
                "spam_seconds": 5
            }

    return {
        "log_channel_id": row[0],
        "anti_spam": row[1],
        "anti_nuke": row[2],
        "anti_bot": row[3],
        "spam_action": row[4],
        "spam_limit": row[5],
        "spam_seconds": row[6]
    }


def update_setting(guild_id, setting, value):
    allowed = {
        "log_channel_id",
        "anti_spam",
        "anti_nuke",
        "anti_bot",
        "spam_action",
        "spam_limit",
        "spam_seconds"
    }

    if setting not in allowed:
        raise ValueError("Invalid setting.")

    get_settings(guild_id)

    with sqlite3.connect(DATABASE) as db:
        db.execute(
            f"UPDATE guild_settings SET {setting} = ? WHERE guild_id = ?",
            (value, guild_id)
        )
        db.commit()


def is_authorized(guild_id, user_id):
    if user_id in OWNER_IDS:
        return True

    with sqlite3.connect(DATABASE) as db:
        result = db.execute(
            "SELECT 1 FROM authorized_members "
            "WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id)
        ).fetchone()

    return result is not None


def is_trusted_bot(guild_id, bot_id):
    with sqlite3.connect(DATABASE) as db:
        result = db.execute(
            "SELECT 1 FROM trusted_bots WHERE guild_id = ? AND bot_id = ?",
            (guild_id, bot_id)
        ).fetchone()

    return result is not None


# ---------------- LOGGING ----------------

def safe_text(value, limit=1000):
    if value is None:
        return "(unavailable)"

    value = str(value)

    if not value.strip():
        return "(empty)"

    return value[:limit]


def make_embed(title, description, color=discord.Color.blurple()):
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_footer(text="EXTERNAL FULL SECURITY")
    return embed


async def send_log(guild, title, description, color=None, jump_url=None):
    if guild is None:
        return

    settings = get_settings(guild.id)
    channel_id = settings["log_channel_id"]

    if not channel_id:
        return

    channel = guild.get_channel(channel_id)

    if channel is None:
        try:
            channel = await guild.fetch_channel(channel_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            return

    if not isinstance(channel, discord.TextChannel):
        return

    embed = make_embed(
        title,
        description,
        color or discord.Color.blurple()
    )

    if jump_url:
        embed.add_field(
            name="Message Location",
            value=f"[Open message location]({jump_url})",
            inline=False
        )

    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        pass


async def find_audit_actor(guild, action, target_id=None):
    """Best-effort audit-log lookup. The result is not guaranteed."""
    try:
        async for entry in guild.audit_logs(limit=8, action=action):
            if target_id is not None:
                entry_target = getattr(entry.target, "id", None)
                if entry_target != target_id:
                    continue

            age = (discord.utils.utcnow() - entry.created_at).total_seconds()

            if age <= 15:
                return entry.user, entry.reason

    except (discord.Forbidden, discord.HTTPException):
        pass

    return None, None


# ---------------- INVITE TRACKING ----------------

async def refresh_invites(guild):
    try:
        invites = await guild.invites()
        invite_cache[guild.id] = {
            invite.code: {
                "uses": invite.uses or 0,
                "inviter_id": invite.inviter.id if invite.inviter else None,
                "channel_id": invite.channel.id if invite.channel else None
            }
            for invite in invites
        }
    except (discord.Forbidden, discord.HTTPException):
        invite_cache[guild.id] = {}


@bot.event
async def on_ready():
    global ready_once

    init_db()

    if not ready_once:
        try:
            synced = await bot.tree.sync()
            print(f"Synced {len(synced)} global slash commands.")
        except discord.HTTPException as error:
            print(f"Command sync failed: {error}")

        ready_once = True

    for guild in bot.guilds:
        await refresh_invites(guild)

    print(f"Logged in as {bot.user} ({bot.user.id})")


@bot.event
async def on_guild_join(guild):
    await refresh_invites(guild)


@bot.event
async def on_invite_create(invite):
    await refresh_invites(invite.guild)

    await send_log(
        invite.guild,
        "Invite Created",
        f"Code: `{invite.code}`\n"
        f"Created by: {invite.inviter or 'Unknown'}\n"
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

    await refresh_invites(invite.guild)


# ---------------- MESSAGE LOGGING ----------------
# Normal messages are NOT logged.
# Only edited and deleted messages are logged.

@bot.event
async def on_message_edit(before, after):
    if before.guild is None or before.author.bot:
        return

    if before.content == after.content:
        return

    jump_url = (
        f"https://discord.com/channels/"
        f"{before.guild.id}/{before.channel.id}/{before.id}"
    )

    await send_log(
        before.guild,
        "Message Edited",
        f"Member: {before.author} (`{before.author.id}`)\n"
        f"Channel: {before.channel.mention}\n\n"
        f"Before:\n{safe_text(before.content)}\n\n"
        f"After:\n{safe_text(after.content)}",
        jump_url=jump_url
    )


@bot.event
async def on_message_delete(message):
    if message.guild is None or message.author.bot:
        return

    jump_url = (
        f"https://discord.com/channels/"
        f"{message.guild.id}/{message.channel.id}/{message.id}"
    )

    actor, reason = await find_audit_actor(
        message.guild,
        discord.AuditLogAction.message_delete,
        message.author.id
    )

    await send_log(
        message.guild,
        "Message Deleted",
        f"Original author: {message.author} (`{message.author.id}`)\n"
        f"Channel: {message.channel.mention}\n"
        f"Deleted by: {actor or 'Unknown'}\n"
        f"Reason: {safe_text(reason)}\n\n"
        f"Content:\n{safe_text(message.content)}",
        color=discord.Color.red(),
        jump_url=jump_url
    )


# ---------------- MEMBER LOGGING ----------------

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

    settings = get_settings(member.guild.id)

    actor, reason = await find_audit_actor(
        member.guild,
        discord.AuditLogAction.bot_add,
        member.id
    )

    old_invites = invite_cache.get(member.guild.id, {})
    await refresh_invites(member.guild)
    new_invites = invite_cache.get(member.guild.id, {})

    used_invite = None

    for code, data in new_invites.items():
        old_uses = old_invites.get(code, {}).get("uses", 0)
        if data["uses"] > old_uses:
            used_invite = data
            break

    inviter_text = str(actor) if actor else "Unknown"
    channel_text = "Unknown"

    if used_invite:
        inviter_text = (
            f"<@{used_invite['inviter_id']}>"
            if used_invite["inviter_id"]
            else inviter_text
        )

        if used_invite["channel_id"]:
            channel = member.guild.get_channel(used_invite["channel_id"])
            if channel:
                channel_text = channel.mention

    await send_log(
        member.guild,
        "Bot Joined",
        f"Bot: {member} (`{member.id}`)\n"
        f"Invited by: {inviter_text}\n"
        f"Invite channel: {channel_text}\n"
        f"Audit-log reason: {safe_text(reason)}"
    )

    if settings["anti_bot"] and not is_trusted_bot(member.guild.id, member.id):
        await send_log(
            member.guild,
            "Untrusted Bot Alert",
            f"Bot: {member} (`{member.id}`)\n"
            f"Invited by: {inviter_text}\n"
            "This bot is not on the server's trusted-bot list.",
            color=discord.Color.orange()
        )


@bot.event
async def on_member_remove(member):
    actor, reason = await find_audit_actor(
        member.guild,
        discord.AuditLogAction.kick,
        member.id
    )

    await send_log(
        member.guild,
        "Member Left or Was Removed",
        f"Member: {member} (`{member.id}`)\n"
        f"Possible kick executor: {actor or 'Unknown'}\n"
        f"Reason: {safe_text(reason)}"
    )


@bot.event
async def on_member_update(before, after):
    old_roles = {role.id: role for role in before.roles}
    new_roles = {role.id: role for role in after.roles}

    added = [r for rid, r in new_roles.items() if rid not in old_roles]
    removed = [r for rid, r in old_roles.items() if rid not in new_roles]

    if added or removed:
        actor, reason = await find_audit_actor(
            after.guild,
            discord.AuditLogAction.member_role_update,
            after.id
        )

        if added:
            await send_log(
                after.guild,
                "Member Role Added",
                f"Member: {after} (`{after.id}`)\n"
                f"Role(s): {', '.join(r.name for r in added)}\n"
                f"Changed by: {actor or 'Unknown'}\n"
                f"Reason: {safe_text(reason)}"
            )

        if removed:
            await send_log(
                after.guild,
                "Member Role Removed",
                f"Member: {after} (`{after.id}`)\n"
                f"Role(s): {', '.join(r.name for r in removed)}\n"
                f"Changed by: {actor or 'Unknown'}\n"
                f"Reason: {safe_text(reason)}"
            )

    if before.nick != after.nick:
        await send_log(
            after.guild,
            "Nickname Changed",
            f"Member: {after} (`{after.id}`)\n"
            f"Before: {safe_text(before.nick)}\n"
            f"After: {safe_text(after.nick)}"
        )

    if before.timed_out_until != after.timed_out_until:
        await send_log(
            after.guild,
            "Member Timeout Updated",
            f"Member: {after} (`{after.id}`)\n"
            f"Before: {safe_text(before.timed_out_until)}\n"
            f"After: {safe_text(after.timed_out_until)}"
        )


# ---------------- ROLE LOGGING ----------------

@bot.event
async def on_guild_role_create(role):
    actor, reason = await find_audit_actor(
        role.guild,
        discord.AuditLogAction.role_create,
        role.id
    )

    await send_log(
        role.guild,
        "Role Created",
        f"Role: {role.name} (`{role.id}`)\n"
        f"Created by: {actor or 'Unknown'}\n"
        f"Reason: {safe_text(reason)}"
    )


@bot.event
async def on_guild_role_delete(role):
    actor, reason = await find_audit_actor(
        role.guild,
        discord.AuditLogAction.role_delete,
        role.id
    )

    await send_log(
        role.guild,
        "Role Deleted",
        f"Role: {role.name} (`{role.id}`)\n"
        f"Deleted by: {actor or 'Unknown'}\n"
        f"Reason: {safe_text(reason)}",
        color=discord.Color.red()
    )


@bot.event
async def on_guild_role_update(before, after):
    changes = []

    for label, old, new in [
        ("Name", before.name, after.name),
        ("Colour", str(before.colour), str(after.colour)),
        ("Hoist", before.hoist, after.hoist),
        ("Mentionable", before.mentionable, after.mentionable),
        ("Permissions", str(before.permissions.value), str(after.permissions.value))
    ]:
        if old != new:
            changes.append(f"{label}: `{old}` -> `{new}`")

    if not changes:
        return

    actor, reason = await find_audit_actor(
        after.guild,
        discord.AuditLogAction.role_update,
        after.id
    )

    await send_log(
        after.guild,
        "Role Updated",
        f"Role: {after.name} (`{after.id}`)\n"
        f"Changed by: {actor or 'Unknown'}\n"
        f"{chr(10).join(changes)}\n"
        f"Reason: {safe_text(reason)}"
    )


# ---------------- CHANNEL LOGGING ----------------

@bot.event
async def on_guild_channel_create(channel):
    actor, reason = await find_audit_actor(
        channel.guild,
        discord.AuditLogAction.channel_create,
        channel.id
    )

    await send_log(
        channel.guild,
        "Channel Created",
        f"Channel: {channel.name} (`{channel.id}`)\n"
        f"Created by: {actor or 'Unknown'}\n"
        f"Reason: {safe_text(reason)}"
    )


@bot.event
async def on_guild_channel_delete(channel):
    actor, reason = await find_audit_actor(
        channel.guild,
        discord.AuditLogAction.channel_delete,
        channel.id
    )

    await send_log(
        channel.guild,
        "Channel Deleted",
        f"Channel: {channel.name} (`{channel.id}`)\n"
        f"Deleted by: {actor or 'Unknown'}\n"
        f"Reason: {safe_text(reason)}",
        color=discord.Color.red()
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
                f"{label}: `{safe_text(old, 300)}` -> `{safe_text(new, 300)}`"
            )

    if not changes:
        return

    actor, reason = await find_audit_actor(
        after.guild,
        discord.AuditLogAction.channel_update,
        after.id
    )

    await send_log(
        after.guild,
        "Channel Updated",
        f"Channel: {after.name} (`{after.id}`)\n"
        f"Changed by: {actor or 'Unknown'}\n"
        f"{chr(10).join(changes)}\n"
        f"Reason: {safe_text(reason)}"
    )


# ---------------- SERVER LOGGING ----------------

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

    actor, reason = await find_audit_actor(
        after,
        discord.AuditLogAction.guild_update
    )

    await send_log(
        after,
        "Server Settings Updated",
        f"Changed by: {actor or 'Unknown'}\n"
        f"{chr(10).join(changes)}\n"
        f"Reason: {safe_text(reason)}",
        color=discord.Color.orange()
    )


# ---------------- ANTI-SPAM ----------------

@bot.event
async def on_message(message):
    if message.guild is None or message.author.bot:
        return

    settings = get_settings(message.guild.id)

    if settings["anti_spam"] and not is_authorized(
        message.guild.id, message.author.id
    ):
        key = (message.guild.id, message.author.id)
        now = time.monotonic()
        queue = spam_messages[key]
        queue.append(now)

        while queue and now - queue[0] > settings["spam_seconds"]:
            queue.popleft()

        if len(queue) >= settings["spam_limit"]:
            queue.clear()

            try:
                await message.channel.purge(
                    limit=settings["spam_limit"],
                    check=lambda m: m.author.id == message.author.id
                )
            except discord.Forbidden:
                pass
            except discord.HTTPException:
                pass

            action = settings["spam_action"]

            try:
                if action == "kick":
                    await message.author.kick(reason="Automatic anti-spam")
                elif action == "ban":
                    await message.author.ban(reason="Automatic anti-spam")
                else:
                    await message.author.timeout(
                        discord.utils.utcnow() + discord.timedelta(minutes=1),
                        reason="Automatic anti-spam"
                    )
            except (discord.Forbidden, discord.HTTPException, AttributeError):
                pass

            await send_log(
                message.guild,
                "Anti-Spam Triggered",
                f"Member: {message.author} (`{message.author.id}`)\n"
                f"Channel: {message.channel.mention}\n"
                f"Configured action: {action}"
            )

    # Match autoresponders; normal chat messages are never sent to logs.
    with sqlite3.connect(DATABASE) as db:
        responses = db.execute(
            "SELECT trigger, response FROM autoresponders WHERE guild_id = ?",
            (message.guild.id,)
        ).fetchall()

    content = message.content.casefold()

    for trigger, response in responses:
        if trigger.casefold() in content:
            await message.channel.send(
                response,
                allowed_mentions=discord.AllowedMentions.none()
            )
            break

    await bot.process_commands(message)


# ---------------- SLASH COMMANDS ----------------

@bot.tree.command(
    name="all-logs-channel",
    description="Set the channel for server activity and security logs."
)
@app_commands.describe(channel="The channel where logs should be sent.")
@app_commands.checks.has_permissions(manage_guild=True)
async def all_logs_channel(
    interaction: discord.Interaction,
    channel: discord.TextChannel
):
    update_setting(interaction.guild_id, "log_channel_id", channel.id)

    await interaction.response.send_message(
        f"All activity and security logs will be sent to {channel.mention}.",
        ephemeral=True
    )

    await send_log(
        interaction.guild,
        "Logging Configured",
        f"Log channel set to {channel.mention} by {interaction.user}."
    )


@bot.tree.command(name="help", description="Show bot commands.")
async def help_command(interaction: discord.Interaction):
    text = (
        "**Logging**\n"
        "`/all-logs-channel channel:` Set the central log channel.\n\n"
        "**Moderation**\n"
        "`/kick member reason:` Kick a member.\n"
        "`/ban member reason:` Ban a member.\n"
        "`/addmembersrole member role:` Add a role to a member.\n\n"
        "**Security**\n"
        "`/security-settings` View current security settings.\n"
        "`/set-antispam enabled:` Enable or disable anti-spam.\n"
        "`/set-antinuke enabled:` Enable or disable anti-nuke monitoring.\n"
        "`/set-antibot enabled:` Enable or disable untrusted-bot alerts.\n"
        "`/set-spam-action action:` Choose timeout, kick, or ban.\n"
        "`/authorize-member member:` Allow a member to bypass anti-spam.\n"
        "`/trust-bot bot:` Add a bot to the trusted-bot list.\n\n"
        "**Utilities**\n"
        "`/announcement channel message:` Send an announcement.\n"
        "`/autoresponder-add trigger response:` Add an automatic response.\n"
        "`/autoresponder-remove trigger:` Remove an automatic response.\n"
        "`/giveaway channel minutes prize:` Start a simple giveaway."
    )

    await interaction.response.send_message(text, ephemeral=True)


@bot.tree.command(name="kick", description="Kick a member.")
@app_commands.checks.has_permissions(kick_members=True)
async def kick(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if member.top_role >= interaction.user.top_role and interaction.user.id not in OWNER_IDS:
        await interaction.response.send_message(
            "You cannot kick a member with an equal or higher role.",
            ephemeral=True
        )
        return

    await member.kick(reason=reason)
    await interaction.response.send_message(
        f"Kicked {member}. Reason: {reason}",
        ephemeral=True
    )

    await send_log(
        interaction.guild,
        "Member Kicked",
        f"Member: {member} (`{member.id}`)\n"
        f"By: {interaction.user}\nReason: {reason}"
    )


@bot.tree.command(name="ban", description="Ban a member.")
@app_commands.checks.has_permissions(ban_members=True)
async def ban(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if member.top_role >= interaction.user.top_role and interaction.user.id not in OWNER_IDS:
        await interaction.response.send_message(
            "You cannot ban a member with an equal or higher role.",
            ephemeral=True
        )
        return

    await member.ban(reason=reason)
    await interaction.response.send_message(
        f"Banned {member}. Reason: {reason}",
        ephemeral=True
    )

    await send_log(
        interaction.guild,
        "Member Banned",
        f"Member: {member} (`{member.id}`)\n"
        f"By: {interaction.user}\nReason: {reason}"
    )


@bot.tree.command(name="addmembersrole", description="Add a role to a member.")
@app_commands.checks.has_permissions(manage_roles=True)
async def addmembersrole(
    interaction: discord.Interaction,
    member: discord.Member,
    role: discord.Role
):
    if role >= interaction.guild.me.top_role:
        await interaction.response.send_message(
            "That role is above the bot's highest role.",
            ephemeral=True
        )
        return

    await member.add_roles(role, reason=f"Requested by {interaction.user}")
    await interaction.response.send_message(
        f"Added role {role.name} to {member}.",
        ephemeral=True
    )

    await send_log(
        interaction.guild,
        "Role Added by Command",
        f"Member: {member}\nRole: {role.name}\nBy: {interaction.user}"
    )


# ---------------- SECURITY SETTINGS ----------------

@bot.tree.command(
    name="security-settings",
    description="View this server's security configuration."
)
@app_commands.checks.has_permissions(manage_guild=True)
async def security_settings(interaction: discord.Interaction):
    s = get_settings(interaction.guild_id)

    await interaction.response.send_message(
        f"Log channel ID: {s['log_channel_id']}\n"
        f"Anti-spam: {'ON' if s['anti_spam'] else 'OFF'}\n"
        f"Anti-nuke monitoring: {'ON' if s['anti_nuke'] else 'OFF'}\n"
        f"Anti-bot alerts: {'ON' if s['anti_bot'] else 'OFF'}\n"
        f"Spam action: {s['spam_action']}\n"
        f"Spam threshold: {s['spam_limit']} messages / {s['spam_seconds']} seconds",
        ephemeral=True
    )


async def set_boolean_setting(interaction, setting, enabled):
    update_setting(interaction.guild_id, setting, int(enabled))
    await interaction.response.send_message(
        f"{setting.replace('_', ' ').title()} is now "
        f"{'enabled' if enabled else 'disabled'}.",
        ephemeral=True
    )


@bot.tree.command(name="set-antispam", description="Toggle anti-spam.")
@app_commands.checks.has_permissions(manage_guild=True)
async def set_antispam(interaction: discord.Interaction, enabled: bool):
    await set_boolean_setting(interaction, "anti_spam", enabled)


@bot.tree.command(name="set-antinuke", description="Toggle anti-nuke monitoring.")
@app_commands.checks.has_permissions(manage_guild=True)
async def set_antinuke(interaction: discord.Interaction, enabled: bool):
    await set_boolean_setting(interaction, "anti_nuke", enabled)


@bot.tree.command(name="set-antibot", description="Toggle untrusted-bot alerts.")
@app_commands.checks.has_permissions(manage_guild=True)
async def set_antibot(interaction: discord.Interaction, enabled: bool):
    await set_boolean_setting(interaction, "anti_bot", enabled)


@bot.tree.command(name="set-spam-action", description="Set anti-spam punishment.")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.choices(action=[
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban")
])
async def set_spam_action(
    interaction: discord.Interaction,
    action: app_commands.Choice[str]
):
    update_setting(interaction.guild_id, "spam_action", action.value)
    await interaction.response.send_message(
        f"Anti-spam action set to {action.name}.",
        ephemeral=True
    )


@bot.tree.command(
    name="authorize-member",
    description="Allow a member to bypass anti-spam."
)
@app_commands.checks.has_permissions(manage_guild=True)
async def authorize_member(
    interaction: discord.Interaction,
    member: discord.Member
):
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            "INSERT OR IGNORE INTO authorized_members VALUES (?, ?)",
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{member} is now authorized.",
        ephemeral=True
    )


@bot.tree.command(name="trust-bot", description="Trust a bot in this server.")
@app_commands.checks.has_permissions(manage_guild=True)
async def trust_bot(
    interaction: discord.Interaction,
    bot_member: discord.Member
):
    if not bot_member.bot:
        await interaction.response.send_message(
            "Choose a bot account.",
            ephemeral=True
        )
        return

    with sqlite3.connect(DATABASE) as db:
        db.execute(
            "INSERT OR IGNORE INTO trusted_bots VALUES (?, ?)",
            (interaction.guild_id, bot_member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{bot_member} is now on the trusted-bot list.",
        ephemeral=True
    )


# ---------------- ANNOUNCEMENTS ----------------

@bot.tree.command(name="announcement", description="Send an announcement.")
@app_commands.checks.has_permissions(manage_guild=True)
async def announcement(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    message: str
):
    embed = make_embed("Announcement", message)

    await channel.send(
        embed=embed,
        allowed_mentions=discord.AllowedMentions.none()
    )

    await interaction.response.send_message(
        f"Announcement sent to {channel.mention}.",
        ephemeral=True
    )

    await send_log(
        interaction.guild,
        "Announcement Sent",
        f"By: {interaction.user}\nChannel: {channel.mention}"
    )


# ---------------- AUTORESPONDER ----------------

@bot.tree.command(
    name="autoresponder-add",
    description="Create an automatic keyword response."
)
@app_commands.checks.has_permissions(manage_guild=True)
async def autoresponder_add(
    interaction: discord.Interaction,
    trigger: str,
    response: str
):
    if len(trigger) > 100 or len(response) > 1500:
        await interaction.response.send_message(
            "Trigger must be at most 100 characters and response at most 1500.",
            ephemeral=True
        )
        return

    with sqlite3.connect(DATABASE) as db:
        db.execute(
            "INSERT OR REPLACE INTO autoresponders VALUES (?, ?, ?)",
            (interaction.guild_id, trigger.casefold(), response)
        )
        db.commit()

    await interaction.response.send_message(
        f"Autoresponder added for `{trigger}`.",
        ephemeral=True
    )


@bot.tree.command(
    name="autoresponder-remove",
    description="Remove an automatic keyword response."
)
@app_commands.checks.has_permissions(manage_guild=True)
async def autoresponder_remove(
    interaction: discord.Interaction,
    trigger: str
):
    with sqlite3.connect(DATABASE) as db:
        cursor = db.execute(
            "DELETE FROM autoresponders WHERE guild_id = ? AND trigger = ?",
            (interaction.guild_id, trigger.casefold())
        )
        db.commit()

    await interaction.response.send_message(
        "Autoresponder removed." if cursor.rowcount else "Trigger not found.",
        ephemeral=True
    )


# ---------------- SIMPLE GIVEAWAY ----------------

@bot.tree.command(name="giveaway", description="Start a simple timed giveaway.")
@app_commands.checks.has_permissions(manage_guild=True)
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

    end_time = int(time.time()) + minutes * 60
    embed = make_embed(
        "Giveaway",
        f"Prize: {prize}\n"
        f"Hosted by: {interaction.user.mention}\n"
        f"Ends: <t:{end_time}:R>\n\n"
        "React with the ticket reaction below to enter."
    )

    message = await channel.send(embed=embed)
    await message.add_reaction("🎉")

    await interaction.response.send_message(
        f"Giveaway started in {channel.mention}.",
        ephemeral=True
    )

    await asyncio.sleep(minutes * 60)

    try:
        message = await channel.fetch_message(message.id)
        reaction = discord.utils.get(message.reactions, emoji="🎉")

        if reaction is None:
            await channel.send(f"Giveaway ended. No winner was selected for: {prize}")
            return

        users = [
            user async for user in reaction.users()
            if not user.bot
        ]

        if not users:
            await channel.send(f"Giveaway ended. No entries for: {prize}")
            return

        winner = users[0]
        await channel.send(f"Giveaway ended. Winner: {winner.mention}. Prize: {prize}")

        await send_log(
            interaction.guild,
            "Giveaway Ended",
            f"Prize: {prize}\nWinner: {winner}\nChannel: {channel.mention}"
        )

    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


# ---------------- ERROR HANDLING ----------------

@bot.tree.error
async def on_app_command_error(
    interaction: discord.Interaction,
    error: app_commands.AppCommandError
):
    if isinstance(error, app_commands.MissingPermissions):
        message = "You do not have permission to use this command."
    elif isinstance(error, app_commands.CheckFailure):
        message = "You are not authorized to use this command."
    else:
        message = "The command failed. Check the bot console for details."
        print(f"Slash command error: {repr(error)}")

    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


# ---------------- RUN ----------------

if __name__ == "__main__":
    init_db()

    if not TOKEN:
        raise SystemExit(
            "DISCORD_TOKEN is missing. Set it in your hosting environment."
        )

    bot.run(TOKEN)
