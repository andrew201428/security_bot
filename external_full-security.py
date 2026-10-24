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
from aiohttp import web


# ============================================================
# EXTERNAL | FULL SECURITY
# Discord security monitoring bot
# ============================================================

TOKEN = (os.getenv("DISCORD_TOKEN") or "").strip()

# Your Discord user ID.
# Only these IDs can use owner-only security commands.
OWNER_IDS = {1460495693536825479}

DATABASE = "external_security.db"

spam_cache = defaultdict(deque)
invite_cache = {}
giveaway_tasks = {}

web_runner = None


# ============================================================
# DISCORD INTENTS
# ============================================================

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True
intents.moderation = True
intents.invites = True


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
        db.execute(
            "INSERT OR IGNORE INTO settings (guild_id) VALUES (?)",
            (guild_id,)
        )

        row = db.execute(
            """
            SELECT log_channel_id, antispam, antinuke, antibot,
                   spam_limit, spam_window, spam_action
            FROM settings
            WHERE guild_id = ?
            """,
            (guild_id,)
        ).fetchone()

    return {
        "log_channel_id": row[0],
        "antispam": bool(row[1]),
        "antinuke": bool(row[2]),
        "antibot": bool(row[3]),
        "spam_limit": row[4],
        "spam_window": row[5],
        "spam_action": row[6],
    }


def set_setting(guild_id, name, value):
    allowed = {
        "log_channel_id",
        "antispam",
        "antinuke",
        "antibot",
        "spam_limit",
        "spam_window",
        "spam_action",
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
            """
            SELECT 1 FROM authorized_members
            WHERE guild_id = ? AND user_id = ?
            """,
            (guild_id, user_id)
        ).fetchone()

    return row is not None


def is_trusted_bot(guild_id, bot_id):
    with db_connect() as db:
        row = db.execute(
            """
            SELECT 1 FROM trusted_bots
            WHERE guild_id = ? AND bot_id = ?
            """,
            (guild_id, bot_id)
        ).fetchone()

    return row is not None


# ============================================================
# EMBEDS AND LOGGING
# ============================================================

def create_embed(title, description, color=None):
    embed = discord.Embed(
        title=title,
        description=str(description)[:4000],
        color=color or discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_footer(text="EXTERNAL | FULL SECURITY")
    return embed


async def send_log(
    guild,
    title,
    description,
    color=None,
    jump_url=None
):
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
        except (discord.HTTPException, discord.Forbidden):
            return

    if not isinstance(channel, discord.TextChannel):
        return

    embed = create_embed(title, description, color)

    if jump_url:
        embed.add_field(
            name="Message link",
            value=jump_url,
            inline=False
        )

    try:
        await channel.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none()
        )
    except (discord.HTTPException, discord.Forbidden):
        pass


async def audit_actor(guild, action, target_id=None):
    try:
        async for entry in guild.audit_logs(
            limit=8,
            action=action
        ):
            if (
                target_id is not None
                and getattr(entry.target, "id", None) != target_id
            ):
                continue

            age = (
                discord.utils.utcnow() - entry.created_at
            ).total_seconds()

            if 0 <= age <= 15:
                return entry.user, entry.reason

    except (discord.Forbidden, discord.HTTPException):
        pass

    return None, None


# ============================================================
# OWNER-ONLY CHECK
# ============================================================

def owner_only():
    async def predicate(interaction: discord.Interaction):
        if is_owner(interaction.user.id):
            return True

        raise app_commands.CheckFailure(
            "Only the configured bot owner can use this command."
        )

    return app_commands.check(predicate)


def manage_guild_only():
    return app_commands.checks.has_permissions(manage_guild=True)


# ============================================================
# HEALTH SERVER AND BOT CLASS
# ============================================================

async def health_check(request):
    return web.Response(
        text="EXTERNAL | FULL SECURITY is running",
        status=200
    )


class SecurityBot(commands.Bot):

    async def setup_hook(self):
        global web_runner

        init_db()

        # Render Web Service health endpoint.
        app = web.Application()
        app.router.add_get("/", health_check)
        app.router.add_get("/health", health_check)

        web_runner = web.AppRunner(app)
        await web_runner.setup()

        port = int(os.getenv("PORT", "10000"))

        site = web.TCPSite(
            web_runner,
            "0.0.0.0",
            port
        )

        await site.start()

        print(f"Health server listening on port {port}")

        # Register global slash commands.
        try:
            synced = await self.tree.sync()
            print(f"Registered {len(synced)} slash commands.")

            for command in synced:
                print(f"Registered command: /{command.name}")

        except discord.HTTPException as exc:
            print(f"Slash command sync failed: {exc}")

    async def close(self):
        global web_runner

        if web_runner is not None:
            await web_runner.cleanup()
            web_runner = None

        await super().close()


bot = SecurityBot(
    command_prefix="!",
    intents=intents
)


# ============================================================
# STARTUP
# ============================================================

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} ({bot.user.id})")
    print(f"Bot is in {len(bot.guilds)} server(s).")

    for guild in bot.guilds:
        try:
            invites = await guild.invites()

            invite_cache[guild.id] = {
                inv.code: {
                    "uses": inv.uses or 0,
                    "inviter_id": (
                        inv.inviter.id if inv.inviter else None
                    ),
                    "channel_id": (
                        inv.channel.id if inv.channel else None
                    )
                }
                for inv in invites
            }

        except (discord.Forbidden, discord.HTTPException):
            invite_cache[guild.id] = {}


@bot.event
async def on_guild_join(guild):
    await send_log(
        guild,
        "Bot Joined Server",
        f"Joined server: {guild.name} (`{guild.id}`)"
    )


# ============================================================
# CENTRAL LOG CHANNEL
# ============================================================

@bot.tree.command(
    name="all-logs-channel",
    description="Set the central server logging channel."
)
@owner_only()
@app_commands.guild_only()
@app_commands.describe(
    channel="The channel where activity logs will be sent."
)
async def all_logs_channel(
    interaction: discord.Interaction,
    channel: discord.TextChannel
):
    set_setting(
        interaction.guild_id,
        "log_channel_id",
        channel.id
    )

    await interaction.response.send_message(
        f"Central log channel set to {channel.mention}.",
        ephemeral=True
    )


# ============================================================
# HELP
# ============================================================

@bot.tree.command(
    name="help",
    description="Show available bot commands."
)
@app_commands.guild_only()
async def help_command(interaction: discord.Interaction):
    message = (
        "**EXTERNAL | FULL SECURITY COMMANDS**\n\n"
        "**Owner-only security settings**\n"
        "`/all-logs-channel`\n"
        "`/antinuke`\n"
        "`/antispam`\n"
        "`/antibot`\n"
        "`/spam-action`\n"
        "`/authorize-member`\n"
        "`/trust-bot`\n"
        "`/security-settings`\n"
        "`/autoresponder-add`\n"
        "`/autoresponder-remove`\n"
        "`/announcement`\n"
        "`/giveaway`\n\n"
        "**Server moderation permissions required**\n"
        "`/kick`\n"
        "`/ban`\n"
        "`/addmembersrole`\n\n"
        "Use the command options shown by Discord."
    )

    await interaction.response.send_message(
        message,
        ephemeral=True
    )


# ============================================================
# MESSAGE EDIT AND DELETE LOGS
# ============================================================

@bot.event
async def on_message_edit(before, after):
    if before.guild is None or before.author.bot:
        return

    if before.content == after.content:
        return

    await send_log(
        before.guild,
        "Message Edited",
        f"Author: {before.author} (`{before.author.id}`)\n"
        f"Channel: {before.channel.mention}\n\n"
        f"Before:\n{before.content[:900] or '(empty)'}\n\n"
        f"After:\n{after.content[:900] or '(empty)'}",
        jump_url=(
            f"https://discord.com/channels/"
            f"{before.guild.id}/{before.channel.id}/{before.id}"
        )
    )


@bot.event
async def on_message_delete(message):
    if message.guild is None or message.author.bot:
        return

    await send_log(
        message.guild,
        "Message Deleted",
        f"Author: {message.author} (`{message.author.id}`)\n"
        f"Channel: {message.channel.mention}\n"
        f"Cached content:\n{message.content[:1500] or '(empty)'}",
        discord.Color.red()
    )


# ============================================================
# MEMBER LOGS AND UNTRUSTED BOT ALERTS
# ============================================================

@bot.event
async def on_member_join(member):
    await send_log(
        member.guild,
        "Member Joined",
        f"Member: {member} (`{member.id}`)"
    )

    if not member.bot:
        return

    settings = get_settings(member.guild.id)

    actor, reason = await audit_actor(
        member.guild,
        discord.AuditLogAction.bot_add,
        member.id
    )

    await send_log(
        member.guild,
        "Bot Joined",
        f"Bot: {member} (`{member.id}`)\n"
        f"Added by: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}"
    )

    if (
        settings["antibot"]
        and not is_trusted_bot(member.guild.id, member.id)
    ):
        await send_log(
            member.guild,
            "Untrusted Bot Alert",
            f"Bot: {member} (`{member.id}`)\n"
            "This bot is not on the trusted-bot list.",
            discord.Color.orange()
        )


@bot.event
async def on_member_remove(member):
    actor, reason = await audit_actor(
        member.guild,
        discord.AuditLogAction.kick,
        member.id
    )

    await send_log(
        member.guild,
        "Member Left or Was Removed",
        f"Member: {member} (`{member.id}`)\n"
        f"Possible kick executor: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}"
    )


# ============================================================
# ROLE AND CHANNEL LOGS
# ============================================================

@bot.event
async def on_guild_role_create(role):
    actor, reason = await audit_actor(
        role.guild,
        discord.AuditLogAction.role_create,
        role.id
    )

    await send_log(
        role.guild,
        "Role Created",
        f"Role: {role.name} (`{role.id}`)\n"
        f"By: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}"
    )


@bot.event
async def on_guild_role_delete(role):
    actor, reason = await audit_actor(
        role.guild,
        discord.AuditLogAction.role_delete,
        role.id
    )

    await send_log(
        role.guild,
        "Role Deleted",
        f"Role: {role.name} (`{role.id}`)\n"
        f"By: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}",
        discord.Color.red()
    )


@bot.event
async def on_guild_channel_create(channel):
    actor, reason = await audit_actor(
        channel.guild,
        discord.AuditLogAction.channel_create,
        channel.id
    )

    await send_log(
        channel.guild,
        "Channel Created",
        f"Channel: {channel.name} (`{channel.id}`)\n"
        f"By: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}"
    )


@bot.event
async def on_guild_channel_delete(channel):
    actor, reason = await audit_actor(
        channel.guild,
        discord.AuditLogAction.channel_delete,
        channel.id
    )

    await send_log(
        channel.guild,
        "Channel Deleted",
        f"Channel: {channel.name} (`{channel.id}`)\n"
        f"By: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}",
        discord.Color.red()
    )


@bot.event
async def on_guild_channel_update(before, after):
    if before.name == after.name:
        return

    actor, reason = await audit_actor(
        after.guild,
        discord.AuditLogAction.channel_update,
        after.id
    )

    await send_log(
        after.guild,
        "Channel Updated",
        f"Before: {before.name}\n"
        f"After: {after.name}\n"
        f"By: {actor or 'Unknown'}\n"
        f"Reason: {reason or 'Unknown'}"
    )


# ============================================================
# BASIC ANTI-NUKE MONITORING
# ============================================================

@bot.event
async def on_guild_update(before, after):
    changes = []

    if before.name != after.name:
        changes.append(
            f"Server name: `{before.name}` -> `{after.name}`"
        )

    if before.verification_level != after.verification_level:
        changes.append(
            "Verification level changed."
        )

    if not changes:
        return

    settings = get_settings(after.id)

    if settings["antinuke"]:
        actor, reason = await audit_actor(
            after,
            discord.AuditLogAction.guild_update
        )

        await send_log(
            after,
            "Anti-Nuke Monitoring Alert",
            f"Changes:\n" + "\n".join(changes) + "\n"
            f"Changed by: {actor or 'Unknown'}\n"
            f"Reason: {reason or 'Unknown'}",
            discord.Color.orange()
        )


# ============================================================
# ANTI-SPAM AND AUTORESPONDER
# ============================================================

@bot.event
async def on_message(message):
    if message.guild is None or message.author.bot:
        return

    settings = get_settings(message.guild.id)

    if (
        settings["antispam"]
        and not is_authorized(message.guild.id, message.author.id)
    ):
        key = (message.guild.id, message.author.id)
        now = time.monotonic()
        queue = spam_cache[key]

        queue.append(now)

        while (
            queue
            and now - queue[0] > settings["spam_window"]
        ):
            queue.popleft()

        if len(queue) >= settings["spam_limit"]:
            queue.clear()

            try:
                await message.channel.purge(
                    limit=settings["spam_limit"],
                    check=lambda item: (
                        item.author.id == message.author.id
                    )
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

            try:
                if settings["spam_action"] == "kick":
                    await message.author.kick(
                        reason="Automatic anti-spam"
                    )

                elif settings["spam_action"] == "ban":
                    await message.author.ban(
                        reason="Automatic anti-spam"
                    )

                else:
                    await message.author.timeout(
                        timedelta(minutes=1),
                        reason="Automatic anti-spam"
                    )

            except (discord.Forbidden, discord.HTTPException):
                pass

            await send_log(
                message.guild,
                "Anti-Spam Triggered",
                f"Member: {message.author} (`{message.author.id}`)\n"
                f"Configured action: {settings['spam_action']}",
                discord.Color.orange()
            )

    with db_connect() as db:
        responders = db.execute(
            """
            SELECT trigger, response
            FROM autoresponders
            WHERE guild_id = ?
            """,
            (message.guild.id,)
        ).fetchall()

    content = message.content.casefold()

    for trigger, response in responders:
        if trigger and trigger in content:
            await message.channel.send(
                response,
                allowed_mentions=discord.AllowedMentions.none()
            )
            break


# ============================================================
# SECURITY COMMANDS — OWNER ONLY
# ============================================================

async def toggle_setting(interaction, name, enabled):
    set_setting(
        interaction.guild_id,
        name,
        int(enabled)
    )

    await interaction.response.send_message(
        f"{name.title()} is now "
        f"{'enabled' if enabled else 'disabled'}.",
        ephemeral=True
    )


@bot.tree.command(
    name="antinuke",
    description="Toggle basic anti-nuke monitoring."
)
@owner_only()
@app_commands.guild_only()
async def antinuke(
    interaction: discord.Interaction,
    enabled: bool
):
    await toggle_setting(interaction, "antinuke", enabled)


@bot.tree.command(
    name="antispam",
    description="Toggle anti-spam protection."
)
@owner_only()
@app_commands.guild_only()
async def antispam(
    interaction: discord.Interaction,
    enabled: bool
):
    await toggle_setting(interaction, "antispam", enabled)


@bot.tree.command(
    name="antibot",
    description="Toggle untrusted-bot alerts."
)
@owner_only()
@app_commands.guild_only()
async def antibot(
    interaction: discord.Interaction,
    enabled: bool
):
    await toggle_setting(interaction, "antibot", enabled)


@bot.tree.command(
    name="spam-action",
    description="Set the automatic anti-spam action."
)
@owner_only()
@app_commands.guild_only()
@app_commands.choices(action=[
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Ban", value="ban"),
])
async def spam_action(
    interaction: discord.Interaction,
    action: app_commands.Choice[str]
):
    set_setting(
        interaction.guild_id,
        "spam_action",
        action.value
    )

    await interaction.response.send_message(
        f"Anti-spam action set to {action.name}.",
        ephemeral=True
    )


@bot.tree.command(
    name="security-settings",
    description="View this server's security settings."
)
@owner_only()
@app_commands.guild_only()
async def security_settings(
    interaction: discord.Interaction
):
    settings = get_settings(interaction.guild_id)

    channel = (
        f"<#{settings['log_channel_id']}>"
        if settings["log_channel_id"]
        else "Not configured"
    )

    await interaction.response.send_message(
        f"Log channel: {channel}\n"
        f"Anti-spam: {'ON' if settings['antispam'] else 'OFF'}\n"
        f"Anti-nuke monitoring: "
        f"{'ON' if settings['antinuke'] else 'OFF'}\n"
        f"Anti-bot alerts: "
        f"{'ON' if settings['antibot'] else 'OFF'}\n"
        f"Spam action: {settings['spam_action']}",
        ephemeral=True
    )


@bot.tree.command(
    name="authorize-member",
    description="Allow a member to bypass anti-spam."
)
@owner_only()
@app_commands.guild_only()
async def authorize_member(
    interaction: discord.Interaction,
    member: discord.Member
):
    with db_connect() as db:
        db.execute(
            """
            INSERT OR IGNORE INTO authorized_members
            VALUES (?, ?)
            """,
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{member.mention} is now authorized to bypass anti-spam.",
        ephemeral=True
    )


@bot.tree.command(
    name="trust-bot",
    description="Add a bot to the trusted-bot list."
)
@owner_only()
@app_commands.guild_only()
async def trust_bot(
    interaction: discord.Interaction,
    bot_member: discord.Member
):
    if not bot_member.bot:
        await interaction.response.send_message(
            "Select a bot account.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT OR IGNORE INTO trusted_bots
            VALUES (?, ?)
            """,
            (interaction.guild_id, bot_member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{bot_member.mention} added to the trusted-bot list.",
        ephemeral=True
    )


# ============================================================
# MODERATION COMMANDS
# ============================================================

@bot.tree.command(
    name="kick",
    description="Kick a member from the server."
)
@app_commands.guild_only()
@app_commands.checks.has_permissions(kick_members=True)
async def kick(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if member.id == interaction.user.id:
        await interaction.response.send_message(
            "You cannot kick yourself.",
            ephemeral=True
        )
        return

    if member.top_role >= interaction.user.top_role:
        await interaction.response.send_message(
            "You cannot kick a member with an equal or higher role.",
            ephemeral=True
        )
        return

    try:
        await member.kick(reason=reason)
        await interaction.response.send_message(
            f"Kicked {member}.",
            ephemeral=True
        )
    except discord.Forbidden:
        await interaction.response.send_message(
            "The bot lacks permission to kick this member.",
            ephemeral=True
        )


@bot.tree.command(
    name="ban",
    description="Ban a member from the server."
)
@app_commands.guild_only()
@app_commands.checks.has_permissions(ban_members=True)
async def ban(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if member.id == interaction.user.id:
        await interaction.response.send_message(
            "You cannot ban yourself.",
            ephemeral=True
        )
        return

    if member.top_role >= interaction.user.top_role:
        await interaction.response.send_message(
            "You cannot ban a member with an equal or higher role.",
            ephemeral=True
        )
        return

    try:
        await member.ban(reason=reason)
        await interaction.response.send_message(
            f"Banned {member}.",
            ephemeral=True
        )
    except discord.Forbidden:
        await interaction.response.send_message(
            "The bot lacks permission to ban this member.",
            ephemeral=True
        )


@bot.tree.command(
    name="addmembersrole",
    description="Add a role to a member."
)
@app_commands.guild_only()
@app_commands.checks.has_permissions(manage_roles=True)
async def addmembersrole(
    interaction: discord.Interaction,
    member: discord.Member,
    role: discord.Role
):
    if role >= interaction.guild.me.top_role:
        await interaction.response.send_message(
            "That role is above or equal to the bot's highest role.",
            ephemeral=True
        )
        return

    if role >= interaction.user.top_role:
        await interaction.response.send_message(
            "That role is above or equal to your highest role.",
            ephemeral=True
        )
        return

    try:
        await member.add_roles(
            role,
            reason=f"Requested by {interaction.user}"
        )

        await interaction.response.send_message(
            f"Added {role.name} to {member}.",
            ephemeral=True
        )

    except discord.Forbidden:
        await interaction.response.send_message(
            "The bot cannot assign that role.",
            ephemeral=True
        )


# ============================================================
# ANNOUNCEMENT — OWNER ONLY
# ============================================================

@bot.tree.command(
    name="announcement",
    description="Send an announcement to a channel."
)
@owner_only()
@app_commands.guild_only()
async def announcement(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    message: str
):
    await channel.send(
        embed=create_embed("Announcement", message),
        allowed_mentions=discord.AllowedMentions.none()
    )

    await interaction.response.send_message(
        f"Announcement sent to {channel.mention}.",
        ephemeral=True
    )


# ============================================================
# AUTORESPONDER — OWNER ONLY
# ============================================================

@bot.tree.command(
    name="autoresponder-add",
    description="Add a keyword autoresponder."
)
@owner_only()
@app_commands.guild_only()
async def autoresponder_add(
    interaction: discord.Interaction,
    trigger: str,
    response: str
):
    if not trigger.strip() or len(trigger) > 100:
        await interaction.response.send_message(
            "Trigger must be between 1 and 100 characters.",
            ephemeral=True
        )
        return

    if len(response) > 1500:
        await interaction.response.send_message(
            "Response must be 1500 characters or fewer.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO autoresponders
            VALUES (?, ?, ?)
            """,
            (
                interaction.guild_id,
                trigger.casefold(),
                response
            )
        )
        db.commit()

    await interaction.response.send_message(
        f"Autoresponder added for `{trigger}`.",
        ephemeral=True
    )


@bot.tree.command(
    name="autoresponder-remove",
    description="Remove a keyword autoresponder."
)
@owner_only()
@app_commands.guild_only()
async def autoresponder_remove(
    interaction: discord.Interaction,
    trigger: str
):
    with db_connect() as db:
        cursor = db.execute(
            """
            DELETE FROM autoresponders
            WHERE guild_id = ? AND trigger = ?
            """,
            (interaction.guild_id, trigger.casefold())
        )
        db.commit()

    result = (
        "Autoresponder removed."
        if cursor.rowcount
        else "Trigger not found."
    )

    await interaction.response.send_message(
        result,
        ephemeral=True
    )


# ============================================================
# GIVEAWAY — OWNER ONLY
# ============================================================

@bot.tree.command(
    name="giveaway",
    description="Start a timed giveaway."
)
@owner_only()
@app_commands.guild_only()
async def giveaway(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    minutes: app_commands.Range[int, 1, 10080],
    prize: str
):
    if len(prize) > 200:
        await interaction.response.send_message(
            "Prize must be 200 characters or fewer.",
            ephemeral=True
        )
        return

    end_time = int(time.time()) + minutes * 60

    message = await channel.send(
        embed=create_embed(
            "Giveaway",
            f"Prize: {prize}\n"
            f"Hosted by: {interaction.user.mention}\n"
            f"Ends: <t:{end_time}:R>\n\n"
            "React with 🎉 to enter."
        )
    )

    await message.add_reaction("🎉")

    await interaction.response.send_message(
        f"Giveaway started in {channel.mention}.",
        ephemeral=True
    )

    async def finish():
        await asyncio.sleep(minutes * 60)

        try:
            current = await channel.fetch_message(message.id)
            reaction = discord.utils.get(
                current.reactions,
                emoji="🎉"
            )

            if reaction is None:
                await channel.send(
                    f"Giveaway ended. No winner for {prize}."
                )
                return

            entrants = [
                user async for user in reaction.users()
                if not user.bot
            ]

            if not entrants:
                await channel.send(
                    f"Giveaway ended. No entries for {prize}."
                )
                return

            winner = random.choice(entrants)

            await channel.send(
                f"🎉 Winner: {winner.mention}\nPrize: {prize}"
            )

        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException
        ):
            pass

    giveaway_tasks[message.id] = asyncio.create_task(finish())


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
        message = "The command failed. Check the Render logs."

    try:
        if interaction.response.is_done():
            await interaction.followup.send(
                message,
                ephemeral=True
            )
        else:
            await interaction.response.send_message(
                message,
                ephemeral=True
            )

    except discord.HTTPException:
        pass


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit(
            "DISCORD_TOKEN is missing. "
            "Set it in Render Environment Variables."
        )

    bot.run(TOKEN)
