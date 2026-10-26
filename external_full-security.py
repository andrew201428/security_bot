
import os
import time
import json
import random
import sqlite3
import asyncio
import logging
import re

from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

import discord
from discord import app_commands
from discord.ext import commands
from aiohttp import web


# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 1 - CORE SYSTEM
# ============================================================

TOKEN = (os.getenv("DISCORD_TOKEN") or "").strip()

DATABASE = "external_security.db"

OWNER_IDS = {
    1460495693536825479
}

AUTO_PREMIUM_GUILDS = {
    1563927346837327874
}

BOT_VERSION = "2.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("EXTERNAL_SECURITY")


# ============================================================
# RUNTIME CACHE
# ============================================================

spam_cache = defaultdict(deque)

invite_cache = {}

giveaway_tasks = {}

afk_cache = {}

snipe_cache = {}

edit_snipe_cache = {}

sticky_cooldowns = {}

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
intents.voice_states = True
intents.reactions = True


# ============================================================
# DATABASE CONNECTION
# ============================================================

def db_connect():
    connection = sqlite3.connect(
        DATABASE,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    with db_connect() as db:

        # Existing security settings
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

        # Existing authorized members
        db.execute("""
            CREATE TABLE IF NOT EXISTS authorized_members (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        # Existing trusted bots
        db.execute("""
            CREATE TABLE IF NOT EXISTS trusted_bots (
                guild_id INTEGER NOT NULL,
                bot_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, bot_id)
            )
        """)

        # Existing autoresponders
        db.execute("""
            CREATE TABLE IF NOT EXISTS autoresponders (
                guild_id INTEGER NOT NULL,
                trigger TEXT NOT NULL,
                response TEXT NOT NULL,
                PRIMARY KEY (guild_id, trigger)
            )
        """)

        # Medium-level command authorization
        db.execute("""
            CREATE TABLE IF NOT EXISTS moderator_authorizations (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                authorized_by INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        # Separate anti-nuke whitelist
        db.execute("""
            CREATE TABLE IF NOT EXISTS antinuke_authorizations (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                authorized_by INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        # Premium servers
        db.execute("""
            CREATE TABLE IF NOT EXISTS premium_servers (
                guild_id INTEGER PRIMARY KEY,
                premium_type TEXT NOT NULL,
                expires_at INTEGER,
                granted_by INTEGER,
                created_at INTEGER NOT NULL
            )
        """)

        # Advanced protection settings
        db.execute("""
            CREATE TABLE IF NOT EXISTS protection_settings (
                guild_id INTEGER PRIMARY KEY,
                antinsfw INTEGER NOT NULL DEFAULT 0,
                antimention INTEGER NOT NULL DEFAULT 0,
                antilink INTEGER NOT NULL DEFAULT 0,
                automod INTEGER NOT NULL DEFAULT 0,
                mention_limit INTEGER NOT NULL DEFAULT 5
            )
        """)

        # Link bypass members
        db.execute("""
            CREATE TABLE IF NOT EXISTS link_bypass (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        # Premium filter bypasses
        db.execute("""
            CREATE TABLE IF NOT EXISTS premium_bypass (
                guild_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                bypass_type TEXT NOT NULL,
                PRIMARY KEY (
                    guild_id,
                    target_id,
                    bypass_type
                )
            )
        """)

        # Jailed members
        db.execute("""
            CREATE TABLE IF NOT EXISTS jailed_members (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                previous_roles TEXT NOT NULL,
                jailed_at INTEGER NOT NULL,
                jailed_by INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        # Server backups
        db.execute("""
            CREATE TABLE IF NOT EXISTS server_backups (
                backup_id TEXT PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                backup_data TEXT NOT NULL
            )
        """)

        # Persistent giveaways
        db.execute("""
            CREATE TABLE IF NOT EXISTS giveaways (
                message_id INTEGER PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                channel_id INTEGER NOT NULL,
                prize TEXT NOT NULL,
                ends_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                winner_id INTEGER
            )
        """)

        # AFK system
        db.execute("""
            CREATE TABLE IF NOT EXISTS afk_users (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reason TEXT,
                started_at INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
        """)

        # Sticky messages
        db.execute("""
            CREATE TABLE IF NOT EXISTS sticky_messages (
                guild_id INTEGER NOT NULL,
                channel_id INTEGER PRIMARY KEY,
                message TEXT NOT NULL,
                last_message_id INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            )
        """)

        # Advanced log settings
        db.execute("""
            CREATE TABLE IF NOT EXISTS advanced_logs (
                guild_id INTEGER PRIMARY KEY,
                channel_logs INTEGER NOT NULL DEFAULT 1,
                role_logs INTEGER NOT NULL DEFAULT 1,
                member_logs INTEGER NOT NULL DEFAULT 1,
                moderation_logs INTEGER NOT NULL DEFAULT 1,
                invite_logs INTEGER NOT NULL DEFAULT 1,
                bot_logs INTEGER NOT NULL DEFAULT 1,
                server_logs INTEGER NOT NULL DEFAULT 1,
                message_logs INTEGER NOT NULL DEFAULT 1
            )
        """)

        # Automatic events
        db.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                channel_id INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                event_message TEXT NOT NULL,
                scheduled_at INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            )
        """)

        db.commit()

    logger.info("Database initialized successfully.")


# ============================================================
# GENERAL SETTINGS
# ============================================================

def get_settings(guild_id):

    with db_connect() as db:

        db.execute(
            """
            INSERT OR IGNORE INTO settings (guild_id)
            VALUES (?)
            """,
            (guild_id,)
        )

        row = db.execute(
            """
            SELECT *
            FROM settings
            WHERE guild_id = ?
            """,
            (guild_id,)
        ).fetchone()

        db.commit()

    return dict(row)


def set_setting(guild_id, name, value):

    allowed = {
        "log_channel_id",
        "antispam",
        "antinuke",
        "antibot",
        "spam_limit",
        "spam_window",
        "spam_action"
    }

    if name not in allowed:
        raise ValueError("Invalid setting name.")

    get_settings(guild_id)

    with db_connect() as db:

        db.execute(
            f"""
            UPDATE settings
            SET {name} = ?
            WHERE guild_id = ?
            """,
            (value, guild_id)
        )

        db.commit()


# ============================================================
# PROTECTION SETTINGS
# ============================================================

def get_protection_settings(guild_id):

    with db_connect() as db:

        db.execute(
            """
            INSERT OR IGNORE INTO protection_settings
            (guild_id)
            VALUES (?)
            """,
            (guild_id,)
        )

        row = db.execute(
            """
            SELECT *
            FROM protection_settings
            WHERE guild_id = ?
            """,
            (guild_id,)
        ).fetchone()

        db.commit()

    return dict(row)


def set_protection_setting(guild_id, name, value):

    allowed = {
        "antinsfw",
        "antimention",
        "antilink",
        "automod",
        "mention_limit"
    }

    if name not in allowed:
        raise ValueError("Invalid protection setting.")

    get_protection_settings(guild_id)

    with db_connect() as db:

        db.execute(
            f"""
            UPDATE protection_settings
            SET {name} = ?
            WHERE guild_id = ?
            """,
            (value, guild_id)
        )

        db.commit()


# ============================================================
# OWNER AND SERVER OWNER CHECKS
# ============================================================

def is_bot_owner(user_id):
    return user_id in OWNER_IDS


def is_server_owner(guild, user_id):

    if guild is None:
        return False

    return guild.owner_id == user_id


def is_high_authorized(guild, user_id):

    if is_bot_owner(user_id):
        return True

    return is_server_owner(guild, user_id)


# ============================================================
# MEDIUM COMMAND AUTHORIZATION
# ============================================================

def is_moderator_authorized(guild_id, user_id):

    if is_bot_owner(user_id):
        return True

    with db_connect() as db:

        row = db.execute(
            """
            SELECT 1
            FROM moderator_authorizations
            WHERE guild_id = ?
              AND user_id = ?
            """,
            (guild_id, user_id)
        ).fetchone()

    return row is not None


def authorize_moderator(
    guild_id,
    user_id,
    authorized_by
):

    with db_connect() as db:

        db.execute(
            """
            INSERT OR REPLACE
            INTO moderator_authorizations
            (
                guild_id,
                user_id,
                authorized_by,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                guild_id,
                user_id,
                authorized_by,
                int(time.time())
            )
        )

        db.commit()


def remove_moderator_authorization(guild_id, user_id):

    with db_connect() as db:

        cursor = db.execute(
            """
            DELETE FROM moderator_authorizations
            WHERE guild_id = ?
              AND user_id = ?
            """,
            (guild_id, user_id)
        )

        db.commit()

    return cursor.rowcount > 0


# ============================================================
# ANTI-NUKE AUTHORIZATION
# ============================================================

def is_antinuke_authorized(guild, user_id):

    if is_high_authorized(guild, user_id):
        return True

    with db_connect() as db:

        row = db.execute(
            """
            SELECT 1
            FROM antinuke_authorizations
            WHERE guild_id = ?
              AND user_id = ?
            """,
            (guild.id, user_id)
        ).fetchone()

    return row is not None


def authorize_antinuke_member(
    guild_id,
    user_id,
    authorized_by
):

    with db_connect() as db:

        db.execute(
            """
            INSERT OR REPLACE
            INTO antinuke_authorizations
            (
                guild_id,
                user_id,
                authorized_by,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                guild_id,
                user_id,
                authorized_by,
                int(time.time())
            )
        )

        db.commit()


def remove_antinuke_authorization(guild_id, user_id):

    with db_connect() as db:

        cursor = db.execute(
            """
            DELETE FROM antinuke_authorizations
            WHERE guild_id = ?
              AND user_id = ?
            """,
            (guild_id, user_id)
        )

        db.commit()

    return cursor.rowcount > 0


# ============================================================
# PERMISSION DECORATORS
# ============================================================

def bot_owner_only():

    async def predicate(interaction):

        if is_bot_owner(interaction.user.id):
            return True

        raise app_commands.CheckFailure(
            "Only the bot owner can use this command."
        )

    return app_commands.check(predicate)


def high_permission_only():

    async def predicate(interaction):

        if interaction.guild is None:
            raise app_commands.CheckFailure(
                "This command can only be used in a server."
            )

        if is_high_authorized(
            interaction.guild,
            interaction.user.id
        ):
            return True

        raise app_commands.CheckFailure(
            "Only the bot owner or server owner can use this command."
        )

    return app_commands.check(predicate)


def medium_permission_only():

    async def predicate(interaction):

        if interaction.guild is None:
            raise app_commands.CheckFailure(
                "This command can only be used in a server."
            )

        if is_high_authorized(
            interaction.guild,
            interaction.user.id
        ):
            return True

        if is_moderator_authorized(
            interaction.guild_id,
            interaction.user.id
        ):
            return True

        raise app_commands.CheckFailure(
            "You are not authorized to use this command."
        )

    return app_commands.check(predicate)


# ============================================================
# PREMIUM SERVER SYSTEM
# ============================================================

def get_premium_record(guild_id):

    with db_connect() as db:

        row = db.execute(
            """
            SELECT *
            FROM premium_servers
            WHERE guild_id = ?
            """,
            (guild_id,)
        ).fetchone()

    return dict(row) if row else None


def is_premium(guild_id):

    if guild_id in AUTO_PREMIUM_GUILDS:
        return True

    record = get_premium_record(guild_id)

    if record is None:
        return False

    if record["premium_type"] == "permanent":
        return True

    expires_at = record["expires_at"]

    if expires_at is None:
        return False

    return int(time.time()) < expires_at


def grant_permanent_premium(
    guild_id,
    granted_by
):

    with db_connect() as db:

        db.execute(
            """
            INSERT OR REPLACE INTO premium_servers
            (
                guild_id,
                premium_type,
                expires_at,
                granted_by,
                created_at
            )
            VALUES (?, ?, NULL, ?, ?)
            """,
            (
                guild_id,
                "permanent",
                granted_by,
                int(time.time())
            )
        )

        db.commit()


def grant_timed_premium(
    guild_id,
    days,
    granted_by
):

    if days < 1:
        raise ValueError(
            "Premium duration must be at least one day."
        )

    expires_at = int(time.time()) + days * 86400

    with db_connect() as db:

        db.execute(
            """
            INSERT OR REPLACE INTO premium_servers
            (
                guild_id,
                premium_type,
                expires_at,
                granted_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                guild_id,
                "timed",
                expires_at,
                granted_by,
                int(time.time())
            )
        )

        db.commit()


def remove_premium(guild_id):

    if guild_id in AUTO_PREMIUM_GUILDS:
        return False

    with db_connect() as db:

        cursor = db.execute(
            """
            DELETE FROM premium_servers
            WHERE guild_id = ?
            """,
            (guild_id,)
        )

        db.commit()

    return cursor.rowcount > 0


def premium_required():

    async def predicate(interaction):

        if interaction.guild_id is None:
            raise app_commands.CheckFailure(
                "Premium commands are server-only."
            )

        if not is_premium(interaction.guild_id):
            raise app_commands.CheckFailure(
                "This server does not have premium access."
            )

        return True

    return app_commands.check(predicate)


# ============================================================
# TRUSTED BOT LOOKUP
# ============================================================

def is_trusted_bot(guild_id, bot_id):

    with db_connect() as db:

        row = db.execute(
            """
            SELECT 1
            FROM trusted_bots
            WHERE guild_id = ?
              AND bot_id = ?
            """,
            (guild_id, bot_id)
        ).fetchone()

    return row is not None


# ============================================================
# LINK BYPASS LOOKUP
# ============================================================

def has_link_bypass(guild_id, user_id):

    with db_connect() as db:

        row = db.execute(
            """
            SELECT 1
            FROM link_bypass
            WHERE guild_id = ?
              AND user_id = ?
            """,
            (guild_id, user_id)
        ).fetchone()

    return row is not None


# ============================================================
# ADVANCED LOG SETTINGS
# ============================================================

def get_advanced_logs(guild_id):

    with db_connect() as db:

        db.execute(
            """
            INSERT OR IGNORE INTO advanced_logs
            (guild_id)
            VALUES (?)
            """,
            (guild_id,)
        )

        row = db.execute(
            """
            SELECT *
            FROM advanced_logs
            WHERE guild_id = ?
            """,
            (guild_id,)
        ).fetchone()

        db.commit()

    return dict(row)


def set_advanced_log(guild_id, name, enabled):

    allowed = {
        "channel_logs",
        "role_logs",
        "member_logs",
        "moderation_logs",
        "invite_logs",
        "bot_logs",
        "server_logs",
        "message_logs"
    }

    if name not in allowed:
        raise ValueError(
            "Invalid log category."
        )

    get_advanced_logs(guild_id)

    with db_connect() as db:

        db.execute(
            f"""
            UPDATE advanced_logs
            SET {name} = ?
            WHERE guild_id = ?
            """,
            (int(enabled), guild_id)
        )

        db.commit()


# ============================================================
# END OF PART 1
# ============================================================



# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 2 - BOT AND MANAGEMENT COMMANDS
# ============================================================


# ============================================================
# EMBED HELPER
# ============================================================

def create_embed(title, description, color=None):
    embed = discord.Embed(
        title=title,
        description=str(description)[:4000],
        color=color or discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_footer(text="EXTERNAL | FULL SECURITY v2.0")
    return embed


# ============================================================
# RENDER HEALTH SERVER
# ============================================================

async def health_check(request):
    return web.Response(
        text="EXTERNAL | FULL SECURITY v2.0 ONLINE",
        status=200
    )


class SecurityBot(commands.Bot):

    async def setup_hook(self):
        global web_runner

        init_db()

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

        logger.info("Health server listening on port %s", port)

        try:
            synced = await self.tree.sync()
            logger.info(
                "Registered %s slash commands.",
                len(synced)
            )
        except discord.HTTPException as exc:
            logger.error("Command sync failed: %s", exc)

    async def close(self):
        global web_runner

        if web_runner is not None:
            await web_runner.cleanup()
            web_runner = None

        await super().close()


bot = SecurityBot(
    command_prefix="!",
    intents=intents,
    allowed_mentions=discord.AllowedMentions.none()
)


# ============================================================
# AUTHORIZATION PANEL
# ============================================================

class AuthorizeMemberModal(discord.ui.Modal):
    def __init__(self, mode):
        super().__init__(
            title=(
                "Authorize Moderator"
                if mode == "add"
                else "Remove Moderator"
            )
        )
        self.mode = mode

        self.member_id = discord.ui.TextInput(
            label="Discord Member ID",
            placeholder="Enter the member's numeric ID",
            min_length=15,
            max_length=22
        )
        self.add_item(self.member_id)

    async def on_submit(self, interaction):
        try:
            user_id = int(str(self.member_id.value).strip())
        except ValueError:
            await interaction.response.send_message(
                "Invalid Discord user ID.",
                ephemeral=True
            )
            return

        guild = interaction.guild

        if guild is None or not is_high_authorized(
            guild, interaction.user.id
        ):
            await interaction.response.send_message(
                "Only the bot owner or server owner "
                "can manage authorizations.",
                ephemeral=True
            )
            return

        try:
            member = await guild.fetch_member(user_id)
        except (discord.NotFound, discord.HTTPException):
            await interaction.response.send_message(
                "Member not found in this server.",
                ephemeral=True
            )
            return

        if self.mode == "add":
            authorize_moderator(
                guild.id,
                member.id,
                interaction.user.id
            )
            result = f"Authorized {member.mention}."
        else:
            removed = remove_moderator_authorization(
                guild.id,
                member.id
            )
            result = (
                f"Removed authorization for {member.mention}."
                if removed else
                "This member was not authorized."
            )

        await interaction.response.send_message(
            result,
            ephemeral=True
        )


class AuthorizationView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)

    async def interaction_check(self, interaction):
        if interaction.guild and is_high_authorized(
            interaction.guild, interaction.user.id
        ):
            return True

        await interaction.response.send_message(
            "You cannot manage authorizations.",
            ephemeral=True
        )
        return False

    @discord.ui.button(
        label="Authorize Member",
        style=discord.ButtonStyle.success
    )
    async def authorize(self, interaction, button):
        await interaction.response.send_modal(
            AuthorizeMemberModal("add")
        )

    @discord.ui.button(
        label="Remove Member",
        style=discord.ButtonStyle.danger
    )
    async def remove(self, interaction, button):
        await interaction.response.send_modal(
            AuthorizeMemberModal("remove")
        )

    @discord.ui.button(
        label="Authorized List",
        style=discord.ButtonStyle.secondary
    )
    async def list_members(self, interaction, button):
        with db_connect() as db:
            rows = db.execute(
                """
                SELECT user_id FROM moderator_authorizations
                WHERE guild_id = ?
                ORDER BY created_at DESC
                LIMIT 40
                """,
                (interaction.guild_id,)
            ).fetchall()

        description = (
            "\n".join(
                f"<@{row['user_id']}> "
                f"(`{row['user_id']}`)"
                for row in rows
            )
            if rows else
            "No authorized moderators."
        )

        await interaction.response.send_message(
            embed=create_embed(
                "Authorized Moderators",
                description
            ),
            ephemeral=True
        )


@bot.tree.command(
    name="authorize",
    description="Manage medium-level command authorization."
)
@app_commands.guild_only()
@high_permission_only()
async def authorize_command(interaction: discord.Interaction):
    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | AUTHORIZATION",
            "Manage trusted moderators.\n\n"
            "Authorized moderators can use medium-level "
            "commands but cannot manage premium or "
            "global bot settings."
        ),
        view=AuthorizationView(),
        ephemeral=True
    )


# ============================================================
# ANTI-NUKE MANAGEMENT PANEL
# ============================================================

class AntiNukeMemberModal(discord.ui.Modal):
    def __init__(self, mode):
        super().__init__(
            title=(
                "Anti-Nuke Authorize Member"
                if mode == "add"
                else "Anti-Nuke Remove Member"
            )
        )
        self.mode = mode

        self.member_id = discord.ui.TextInput(
            label="Member ID",
            placeholder="Enter Discord user ID",
            min_length=15,
            max_length=22
        )
        self.add_item(self.member_id)

    async def on_submit(self, interaction):
        if not interaction.guild or not is_high_authorized(
            interaction.guild, interaction.user.id
        ):
            await interaction.response.send_message(
                "Not authorized.",
                ephemeral=True
            )
            return

        try:
            user_id = int(str(self.member_id.value).strip())
        except ValueError:
            await interaction.response.send_message(
                "Invalid user ID.",
                ephemeral=True
            )
            return

        try:
            member = await interaction.guild.fetch_member(user_id)
        except (discord.NotFound, discord.HTTPException):
            await interaction.response.send_message(
                "Member not found.",
                ephemeral=True
            )
            return

        if self.mode == "add":
            authorize_antinuke_member(
                interaction.guild_id,
                member.id,
                interaction.user.id
            )
            message = (
                f"{member.mention} added to the "
                "anti-nuke authorization list."
            )
        else:
            removed = remove_antinuke_authorization(
                interaction.guild_id,
                member.id
            )
            message = (
                f"{member.mention} removed from anti-nuke authorization."
                if removed else
                "Member was not on the anti-nuke list."
            )

        await interaction.response.send_message(
            message,
            ephemeral=True
        )


class AntiNukeView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)

    async def interaction_check(self, interaction):
        if interaction.guild and is_high_authorized(
            interaction.guild, interaction.user.id
        ):
            return True

        await interaction.response.send_message(
            "You are not authorized.",
            ephemeral=True
        )
        return False

    @discord.ui.button(
        label="Enable",
        style=discord.ButtonStyle.success
    )
    async def enable(self, interaction, button):
        set_setting(interaction.guild_id, "antinuke", 1)
        await interaction.response.send_message(
            "Anti-nuke monitoring enabled.",
            ephemeral=True
        )

    @discord.ui.button(
        label="Disable",
        style=discord.ButtonStyle.danger
    )
    async def disable(self, interaction, button):
        set_setting(interaction.guild_id, "antinuke", 0)
        await interaction.response.send_message(
            "Anti-nuke monitoring disabled.",
            ephemeral=True
        )

    @discord.ui.button(
        label="Authorize Member",
        style=discord.ButtonStyle.primary
    )
    async def authorize_member(self, interaction, button):
        await interaction.response.send_modal(
            AntiNukeMemberModal("add")
        )

    @discord.ui.button(
        label="Remove Member",
        style=discord.ButtonStyle.secondary
    )
    async def remove_member(self, interaction, button):
        await interaction.response.send_modal(
            AntiNukeMemberModal("remove")
        )

    @discord.ui.button(
        label="Authorized List",
        style=discord.ButtonStyle.secondary,
        row=1
    )
    async def authorized_list(self, interaction, button):
        with db_connect() as db:
            rows = db.execute(
                """
                SELECT user_id
                FROM antinuke_authorizations
                WHERE guild_id = ?
                ORDER BY created_at DESC
                LIMIT 40
                """,
                (interaction.guild_id,)
            ).fetchall()

        content = (
            "\n".join(
                f"<@{row['user_id']}> "
                f"(`{row['user_id']}`)"
                for row in rows
            )
            if rows else
            "No anti-nuke authorized members."
        )

        await interaction.response.send_message(
            embed=create_embed(
                "Anti-Nuke Authorized Members",
                content
            ),
            ephemeral=True
        )


@bot.tree.command(
    name="antinuke",
    description="Open the anti-nuke management panel."
)
@app_commands.guild_only()
@high_permission_only()
async def antinuke_command(interaction: discord.Interaction):
    settings = get_settings(interaction.guild_id)

    status = (
        "Enabled" if settings["antinuke"] else "Disabled"
    )

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | ANTI-NUKE",
            f"Monitoring status: **{status}**\n\n"
            "Configure anti-nuke monitoring and "
            "manage trusted members.\n\n"
            "Note: Protection enforcement will be "
            "implemented in a later part."
        ),
        view=AntiNukeView(),
        ephemeral=True
    )


# ============================================================
# PREMIUM MANAGEMENT COMMAND GROUP
# ============================================================

prem_group = app_commands.Group(
    name="prem",
    description="Manage premium servers."
)

prem_add_group = app_commands.Group(
    name="add",
    description="Grant premium access.",
    parent=prem_group
)


@prem_add_group.command(
    name="perm",
    description="Grant permanent premium to a server."
)
@bot_owner_only()
async def premium_add_permanent(
    interaction: discord.Interaction,
    server_id: str
):
    try:
        guild_id = int(server_id)
        if guild_id <= 0:
            raise ValueError()
    except ValueError:
        await interaction.response.send_message(
            "Invalid server ID.",
            ephemeral=True
        )
        return

    if bot.get_guild(guild_id) is None:
        await interaction.response.send_message(
            "The bot is not in that server.",
            ephemeral=True
        )
        return

    grant_permanent_premium(
        guild_id,
        interaction.user.id
    )

    await interaction.response.send_message(
        f"Permanent premium granted to `{guild_id}`.",
        ephemeral=True
    )


@prem_add_group.command(
    name="time",
    description="Grant timed premium to a server."
)
@bot_owner_only()
async def premium_add_timed(
    interaction: discord.Interaction,
    server_id: str,
    days: app_commands.Range[int, 1, 3650]
):
    try:
        guild_id = int(server_id)
        if guild_id <= 0:
            raise ValueError()
    except ValueError:
        await interaction.response.send_message(
            "Invalid server ID.",
            ephemeral=True
        )
        return

    if bot.get_guild(guild_id) is None:
        await interaction.response.send_message(
            "The bot is not in that server.",
            ephemeral=True
        )
        return

    grant_timed_premium(
        guild_id,
        days,
        interaction.user.id
    )

    await interaction.response.send_message(
        f"Timed premium granted to `{guild_id}` "
        f"for {days} day(s).",
        ephemeral=True
    )


@prem_group.command(
    name="list",
    description="List premium servers."
)
@bot_owner_only()
async def premium_list(interaction: discord.Interaction):
    with db_connect() as db:
        records = db.execute(
            """
            SELECT guild_id, premium_type, expires_at
            FROM premium_servers
            ORDER BY created_at DESC
            """
        ).fetchall()

    entries = []

    for guild_id in sorted(AUTO_PREMIUM_GUILDS):
        entries.append(
            f"`{guild_id}` - Automatic Permanent"
        )

    for record in records:
        guild_id = record["guild_id"]

        if guild_id in AUTO_PREMIUM_GUILDS:
            continue

        if record["premium_type"] == "permanent":
            status = "Permanent"
        elif is_premium(guild_id):
            status = f"Expires <t:{record['expires_at']}:R>"
        else:
            status = "Expired"

        entries.append(f"`{guild_id}` - {status}")

    description = (
        "\n".join(entries[:50])
        if entries else
        "No premium servers."
    )

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | PREMIUM SERVERS",
            description
        ),
        ephemeral=True
    )


@prem_group.command(
    name="remove",
    description="Remove premium access from a server."
)
@bot_owner_only()
async def premium_remove(
    interaction: discord.Interaction,
    server_id: str
):
    try:
        guild_id = int(server_id)
        if guild_id <= 0:
            raise ValueError()
    except ValueError:
        await interaction.response.send_message(
            "Invalid server ID.",
            ephemeral=True
        )
        return

    if guild_id in AUTO_PREMIUM_GUILDS:
        await interaction.response.send_message(
            "This server has automatic permanent premium.",
            ephemeral=True
        )
        return

    removed = remove_premium(guild_id)

    await interaction.response.send_message(
        (
            f"Premium removed from `{guild_id}`."
            if removed else
            "Server does not have a premium database record."
        ),
        ephemeral=True
    )


bot.tree.add_command(prem_group)


# ============================================================
# OWNER-ONLY SERVER MANAGEMENT
# ============================================================

class ServerListView(discord.ui.View):
    def __init__(self, owner_id):
        super().__init__(timeout=180)
        self.owner_id = owner_id
        self.page = 0

    async def interaction_check(self, interaction):
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            "This panel belongs to another user.",
            ephemeral=True
        )
        return False

    def make_embed(self):
        guilds = sorted(
            bot.guilds,
            key=lambda guild: guild.name.casefold()
        )

        page_size = 10
        start = self.page * page_size
        current = guilds[start:start + page_size]
        total_pages = max(
            1, (len(guilds) + page_size - 1) // page_size
        )

        lines = [
            f"**{index}. {discord.utils.escape_markdown(guild.name)}**\n"
            f"ID: `{guild.id}`"
            for index, guild in enumerate(
                current, start=start + 1
            )
        ]

        return create_embed(
            "EXTERNAL | SERVER LIST",
            f"Total: {len(guilds)}\n"
            f"Page: {self.page + 1}/{total_pages}\n\n"
            + (
                "\n\n".join(lines)
                if lines else "No servers."
            )
        )

    @discord.ui.button(
        label="Previous",
        style=discord.ButtonStyle.secondary
    )
    async def previous(self, interaction, button):
        self.page = max(0, self.page - 1)
        await interaction.response.edit_message(
            embed=self.make_embed(),
            view=self
        )

    @discord.ui.button(
        label="Next",
        style=discord.ButtonStyle.secondary
    )
    async def next_page(self, interaction, button):
        max_page = max(0, (len(bot.guilds) - 1) // 10)
        self.page = min(max_page, self.page + 1)
        await interaction.response.edit_message(
            embed=self.make_embed(),
            view=self
        )


class ServerLeaveConfirm(discord.ui.View):
    def __init__(self, owner_id, guild_id):
        super().__init__(timeout=60)
        self.owner_id = owner_id
        self.guild_id = guild_id

    async def interaction_check(self, interaction):
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            "Not authorized.",
            ephemeral=True
        )
        return False

    @discord.ui.button(
        label="Confirm Leave",
        style=discord.ButtonStyle.danger
    )
    async def confirm(self, interaction, button):
        guild = bot.get_guild(self.guild_id)

        if guild is None:
            await interaction.response.edit_message(
                content="Server not found.",
                embed=None,
                view=None
            )
            return

        await interaction.response.defer(ephemeral=True)

        try:
            await guild.leave()
        except discord.HTTPException:
            await interaction.followup.send(
                "Could not leave the server.",
                ephemeral=True
            )
            return

        await interaction.followup.send(
            f"Bot left **{guild.name}**.",
            ephemeral=True
        )

    @discord.ui.button(
        label="Cancel",
        style=discord.ButtonStyle.secondary
    )
    async def cancel(self, interaction, button):
        await interaction.response.edit_message(
            content="Cancelled.",
            embed=None,
            view=None
        )


class ServerRemoveSelect(discord.ui.Select):
    def __init__(self, guilds, owner_id):
        self.owner_id = owner_id

        options = [
            discord.SelectOption(
                label=guild.name[:100],
                value=str(guild.id),
                description=f"ID: {guild.id}"
            )
            for guild in guilds[:25]
        ]

        super().__init__(
            placeholder="Choose a server",
            options=options
        )

    async def callback(self, interaction):
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "Not authorized.",
                ephemeral=True
            )
            return

        guild_id = int(self.values[0])
        guild = bot.get_guild(guild_id)

        if guild is None:
            await interaction.response.send_message(
                "Server not found.",
                ephemeral=True
            )
            return

        await interaction.response.send_message(
            embed=create_embed(
                "Confirm Server Removal",
                f"Remove the bot from **{guild.name}**?\n"
                f"Server ID: `{guild.id}`"
            ),
            view=ServerLeaveConfirm(
                self.owner_id, guild.id
            ),
            ephemeral=True
        )


class ServerRemoveView(discord.ui.View):
    def __init__(self, guilds, owner_id):
        super().__init__(timeout=180)
        self.add_item(
            ServerRemoveSelect(guilds, owner_id)
        )


class ServerSettingsView(discord.ui.View):
    def __init__(self, owner_id):
        super().__init__(timeout=180)
        self.owner_id = owner_id

    async def interaction_check(self, interaction):
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            "Not authorized.",
            ephemeral=True
        )
        return False

    @discord.ui.button(
        label="Server List",
        style=discord.ButtonStyle.primary
    )
    async def server_list(self, interaction, button):
        view = ServerListView(self.owner_id)
        await interaction.response.send_message(
            embed=view.make_embed(),
            view=view,
            ephemeral=True
        )

    @discord.ui.button(
        label="Server Remove",
        style=discord.ButtonStyle.danger
    )
    async def server_remove(self, interaction, button):
        guilds = sorted(
            bot.guilds,
            key=lambda guild: guild.name.casefold()
        )

        if not guilds:
            await interaction.response.send_message(
                "Bot is not in any servers.",
                ephemeral=True
            )
            return

        await interaction.response.send_message(
            "Choose a server for the bot to leave.",
            view=ServerRemoveView(
                guilds, self.owner_id
            ),
            ephemeral=True
        )


@bot.tree.command(
    name="server-setting",
    description="Manage the bot's connected servers."
)
@bot_owner_only()
async def server_setting(interaction: discord.Interaction):
    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | SERVER SETTINGS",
            f"Connected servers: **{len(bot.guilds)}**\n\n"
            "Choose Server List or Server Remove."
        ),
        view=ServerSettingsView(interaction.user.id),
        ephemeral=True
    )


# ============================================================
# END OF PART 2
# ============================================================



# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 3 - SECURITY AND ADVANCED LOGGING
# ============================================================


# ============================================================
# SECURITY UTILITIES
# ============================================================

URL_PATTERN = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>]+"
)

INVITE_PATTERN = re.compile(
    r"(?i)(?:discord\.gg/|discord\.com/invite/)"
    r"[a-z0-9-]+"
)

BLOCKED_ADULT_DOMAINS = {
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "xhamster.com",
    "redtube.com"
}

EXPLICIT_TERMS = {
    "pornography",
    "pornographic"
}

SECURITY_LOG_CATEGORIES = {
    "channel_logs": "Channel Logs",
    "role_logs": "Role Logs",
    "member_logs": "Member Logs",
    "moderation_logs": "Moderation Logs",
    "invite_logs": "Invite Logs",
    "bot_logs": "Bot Activity Logs",
    "server_logs": "Server Settings Logs",
    "message_logs": "Message Logs"
}


def security_admin_allowed(interaction):
    return (
        interaction.guild is not None
        and is_high_authorized(
            interaction.guild,
            interaction.user.id
        )
    )


def member_bypasses_filter(guild_id, user_id, filter_name):
    if has_link_bypass(guild_id, user_id):
        if filter_name == "antilink":
            return True

    with db_connect() as db:
        row = db.execute(
            """
            SELECT 1
            FROM premium_bypass
            WHERE guild_id = ?
              AND target_id = ?
              AND bypass_type IN (?, 'all')
            """,
            (guild_id, user_id, filter_name)
        ).fetchone()

    return row is not None


def contains_adult_content(text):
    content = text.casefold()

    for domain in BLOCKED_ADULT_DOMAINS:
        if domain in content:
            return True

    for term in EXPLICIT_TERMS:
        if re.search(
            rf"\b{re.escape(term)}\b",
            content
        ):
            return True

    return False


def contains_link(text):
    return bool(
        URL_PATTERN.search(text)
        or INVITE_PATTERN.search(text)
    )


def count_mentions(message):
    return (
        len(set(message.raw_mentions))
        + len(set(message.raw_role_mentions))
        + int(message.mention_everyone)
    )


# ============================================================
# ADVANCED LOG DISPATCHER
# ============================================================

async def advanced_send_log(
    guild,
    category,
    title,
    description,
    color=None
):
    if guild is None:
        return

    if category not in SECURITY_LOG_CATEGORIES:
        return

    log_settings = get_advanced_logs(guild.id)

    if not log_settings.get(category, 0):
        return

    settings = get_settings(guild.id)
    channel_id = settings.get("log_channel_id")

    if not channel_id:
        return

    channel = guild.get_channel(channel_id)

    if channel is None:
        try:
            channel = await guild.fetch_channel(channel_id)
        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException
        ):
            return

    if not isinstance(channel, discord.TextChannel):
        return

    embed = create_embed(
        title,
        description,
        color
    )

    embed.add_field(
        name="Log Category",
        value=SECURITY_LOG_CATEGORIES[category],
        inline=False
    )

    try:
        await channel.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none()
        )
    except (discord.Forbidden, discord.HTTPException):
        pass


# ============================================================
# SECURITY FILTER ENGINE
# Call from the main on_message handler in a later part.
# ============================================================

async def process_security_filters(message):
    if message.guild is None:
        return False

    if message.author.bot:
        return False

    guild = message.guild

    settings = get_protection_settings(guild.id)

    if not settings["automod"]:
        return False

    if is_high_authorized(guild, message.author.id):
        return False

    content = message.content or ""

    violation = None

    if (
        settings["antilink"]
        and contains_link(content)
        and not member_bypasses_filter(
            guild.id,
            message.author.id,
            "antilink"
        )
    ):
        violation = "Unauthorized link"

    elif (
        settings["antimention"]
        and count_mentions(message) >
        settings["mention_limit"]
        and not member_bypasses_filter(
            guild.id,
            message.author.id,
            "antimention"
        )
    ):
        violation = "Excessive mentions"

    elif (
        settings["antinsfw"]
        and contains_adult_content(content)
        and not member_bypasses_filter(
            guild.id,
            message.author.id,
            "antinsfw"
        )
    ):
        violation = "Blocked adult content"

    if violation is None:
        return False

    try:
        await message.delete()
    except (discord.Forbidden, discord.HTTPException):
        return False

    await advanced_send_log(
        guild,
        "moderation_logs",
        "AutoMod Action",
        (
            f"Member: {message.author.mention}\n"
            f"Member ID: `{message.author.id}`\n"
            f"Channel: {message.channel.mention}\n"
            f"Reason: {violation}\n"
            "Action: Message deleted"
        ),
        discord.Color.orange()
    )

    return True


# ============================================================
# AUTOMOD CONTROL PANEL
# ============================================================

class AutoModView(discord.ui.View):

    def __init__(self):
        super().__init__(timeout=180)

    async def interaction_check(self, interaction):
        if security_admin_allowed(interaction):
            return True

        await interaction.response.send_message(
            "Only the bot owner or server owner "
            "can manage AutoMod.",
            ephemeral=True
        )
        return False

    @discord.ui.button(
        label="Enable AutoMod",
        style=discord.ButtonStyle.success
    )
    async def enable(self, interaction, button):
        set_protection_setting(
            interaction.guild_id,
            "automod",
            1
        )

        await interaction.response.send_message(
            "AutoMod enabled.",
            ephemeral=True
        )

    @discord.ui.button(
        label="Disable AutoMod",
        style=discord.ButtonStyle.danger
    )
    async def disable(self, interaction, button):
        set_protection_setting(
            interaction.guild_id,
            "automod",
            0
        )

        await interaction.response.send_message(
            "AutoMod disabled.",
            ephemeral=True
        )

    @discord.ui.button(
        label="View Settings",
        style=discord.ButtonStyle.secondary
    )
    async def view_settings(self, interaction, button):
        settings = get_protection_settings(
            interaction.guild_id
        )

        def status(key):
            return "ON" if settings[key] else "OFF"

        embed = create_embed(
            "EXTERNAL | AUTOMOD SETTINGS",
            (
                f"AutoMod: **{status('automod')}**\n"
                f"Anti-Link: **{status('antilink')}**\n"
                f"Anti-Mention: **{status('antimention')}**\n"
                f"Anti-NSFW: **{status('antinsfw')}**\n"
                f"Mention Limit: "
                f"**{settings['mention_limit']}**"
            )
        )

        await interaction.response.send_message(
            embed=embed,
            ephemeral=True
        )


@bot.tree.command(
    name="automod",
    description="Open the AutoMod management panel."
)
@app_commands.guild_only()
@high_permission_only()
async def automod_command(
    interaction: discord.Interaction
):
    settings = get_protection_settings(
        interaction.guild_id
    )

    status = (
        "Enabled"
        if settings["automod"]
        else "Disabled"
    )

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | AUTOMOD",
            (
                f"Status: **{status}**\n\n"
                "Manage automated message filtering.\n"
                "Individual protections are configured "
                "with their own slash commands."
            )
        ),
        view=AutoModView(),
        ephemeral=True
    )


# ============================================================
# GENERAL PROTECTION TOGGLE
# ============================================================

class ProtectionToggleView(discord.ui.View):

    def __init__(self, setting_name, display_name):
        super().__init__(timeout=180)

        self.setting_name = setting_name
        self.display_name = display_name

    async def interaction_check(self, interaction):
        if security_admin_allowed(interaction):
            return True

        await interaction.response.send_message(
            "You are not authorized.",
            ephemeral=True
        )
        return False

    @discord.ui.button(
        label="Enable",
        style=discord.ButtonStyle.success
    )
    async def enable(self, interaction, button):
        set_protection_setting(
            interaction.guild_id,
            self.setting_name,
            1
        )

        await interaction.response.send_message(
            f"{self.display_name} enabled.\n"
            "Note: AutoMod must also be enabled.",
            ephemeral=True
        )

    @discord.ui.button(
        label="Disable",
        style=discord.ButtonStyle.danger
    )
    async def disable(self, interaction, button):
        set_protection_setting(
            interaction.guild_id,
            self.setting_name,
            0
        )

        await interaction.response.send_message(
            f"{self.display_name} disabled.",
            ephemeral=True
        )


async def send_protection_panel(
    interaction,
    setting_name,
    display_name
):
    settings = get_protection_settings(
        interaction.guild_id
    )

    status = (
        "Enabled"
        if settings[setting_name]
        else "Disabled"
    )

    await interaction.response.send_message(
        embed=create_embed(
            f"EXTERNAL | {display_name.upper()}",
            (
                f"Status: **{status}**\n"
                "Choose an action below."
            )
        ),
        view=ProtectionToggleView(
            setting_name,
            display_name
        ),
        ephemeral=True
    )


# ============================================================
# ANTI-LINK
# ============================================================

@bot.tree.command(
    name="antilink",
    description="Configure anti-link protection."
)
@app_commands.guild_only()
@high_permission_only()
async def antilink_command(
    interaction: discord.Interaction
):
    await send_protection_panel(
        interaction,
        "antilink",
        "Anti-Link"
    )


# ============================================================
# ANTI-MENTION
# ============================================================

@bot.tree.command(
    name="antimention",
    description="Configure excessive mention protection."
)
@app_commands.guild_only()
@high_permission_only()
async def antimention_command(
    interaction: discord.Interaction
):
    await send_protection_panel(
        interaction,
        "antimention",
        "Anti-Mention"
    )


@bot.tree.command(
    name="mention-limit",
    description="Set the maximum mentions per message."
)
@app_commands.guild_only()
@high_permission_only()
async def mention_limit_command(
    interaction: discord.Interaction,
    limit: app_commands.Range[int, 1, 50]
):
    set_protection_setting(
        interaction.guild_id,
        "mention_limit",
        limit
    )

    await interaction.response.send_message(
        f"Mention limit set to {limit}.",
        ephemeral=True
    )


# ============================================================
# ANTI-NSFW
# ============================================================

@bot.tree.command(
    name="antinsfw",
    description="Configure basic adult-content filtering."
)
@app_commands.guild_only()
@high_permission_only()
async def antinsfw_command(
    interaction: discord.Interaction
):
    await send_protection_panel(
        interaction,
        "antinsfw",
        "Anti-NSFW"
    )


# ============================================================
# LINK BYPASS COMMAND GROUP
# ============================================================

bypass_link_group = app_commands.Group(
    name="bypass-link",
    description="Manage anti-link exemptions."
)


@bypass_link_group.command(
    name="add",
    description="Allow a member to send links."
)
@high_permission_only()
async def bypass_link_add(
    interaction: discord.Interaction,
    member: discord.Member
):
    with db_connect() as db:
        db.execute(
            """
            INSERT OR IGNORE INTO link_bypass
            (guild_id, user_id)
            VALUES (?, ?)
            """,
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"{member.mention} can now bypass Anti-Link.",
        ephemeral=True
    )


@bypass_link_group.command(
    name="remove",
    description="Remove a member's link exemption."
)
@high_permission_only()
async def bypass_link_remove(
    interaction: discord.Interaction,
    member: discord.Member
):
    with db_connect() as db:
        cursor = db.execute(
            """
            DELETE FROM link_bypass
            WHERE guild_id = ?
              AND user_id = ?
            """,
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        (
            f"Link bypass removed for {member.mention}."
            if cursor.rowcount
            else "Member was not on the bypass list."
        ),
        ephemeral=True
    )


@bypass_link_group.command(
    name="list",
    description="Show members allowed to bypass Anti-Link."
)
@high_permission_only()
async def bypass_link_list(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT user_id
            FROM link_bypass
            WHERE guild_id = ?
            ORDER BY user_id
            LIMIT 40
            """,
            (interaction.guild_id,)
        ).fetchall()

    content = (
        "\n".join(
            f"<@{row['user_id']}> "
            f"(`{row['user_id']}`)"
            for row in rows
        )
        if rows
        else "No link bypass members."
    )

    await interaction.response.send_message(
        embed=create_embed(
            "Anti-Link Bypass List",
            content
        ),
        ephemeral=True
    )


bot.tree.add_command(bypass_link_group)


# ============================================================
# ADVANCED LOG MANAGEMENT
# ============================================================

class AdvancedLogSelect(discord.ui.Select):

    def __init__(self):
        options = [
            discord.SelectOption(
                label=display_name,
                value=setting_name
            )
            for setting_name, display_name
            in SECURITY_LOG_CATEGORIES.items()
        ]

        super().__init__(
            placeholder="Choose a log category",
            options=options,
            min_values=1,
            max_values=1
        )

    async def callback(self, interaction):
        if not security_admin_allowed(interaction):
            await interaction.response.send_message(
                "Not authorized.",
                ephemeral=True
            )
            return

        setting_name = self.values[0]

        settings = get_advanced_logs(
            interaction.guild_id
        )

        new_status = not bool(settings[setting_name])

        set_advanced_log(
            interaction.guild_id,
            setting_name,
            new_status
        )

        await interaction.response.send_message(
            (
                f"{SECURITY_LOG_CATEGORIES[setting_name]} "
                f"is now "
                f"{'enabled' if new_status else 'disabled'}."
            ),
            ephemeral=True
        )


class AdvancedLogsView(discord.ui.View):

    def __init__(self):
        super().__init__(timeout=180)
        self.add_item(AdvancedLogSelect())

    async def interaction_check(self, interaction):
        if security_admin_allowed(interaction):
            return True

        await interaction.response.send_message(
            "Not authorized.",
            ephemeral=True
        )
        return False


@bot.tree.command(
    name="advanced-logs",
    description="Configure advanced server logging."
)
@app_commands.guild_only()
@high_permission_only()
async def advanced_logs_command(
    interaction: discord.Interaction
):
    settings = get_advanced_logs(
        interaction.guild_id
    )

    lines = []

    for key, name in SECURITY_LOG_CATEGORIES.items():
        status = "ON" if settings[key] else "OFF"
        lines.append(f"**{name}:** {status}")

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | ADVANCED LOGS",
            (
                "\n".join(lines)
                + "\n\nSelect a category to toggle it.\n"
                "Use /all-logs-channel to configure "
                "the destination channel."
            )
        ),
        view=AdvancedLogsView(),
        ephemeral=True
    )


# ============================================================
# AUDIT LOG EVENT LISTENER
# ============================================================

AUDIT_LOG_ACTION_CATEGORIES = {
    discord.AuditLogAction.channel_create: "channel_logs",
    discord.AuditLogAction.channel_update: "channel_logs",
    discord.AuditLogAction.channel_delete: "channel_logs",

    discord.AuditLogAction.role_create: "role_logs",
    discord.AuditLogAction.role_update: "role_logs",
    discord.AuditLogAction.role_delete: "role_logs",

    discord.AuditLogAction.kick: "moderation_logs",
    discord.AuditLogAction.ban: "moderation_logs",
    discord.AuditLogAction.unban: "moderation_logs",
    discord.AuditLogAction.member_update: "member_logs",

    discord.AuditLogAction.bot_add: "bot_logs",

    discord.AuditLogAction.guild_update: "server_logs",

    discord.AuditLogAction.invite_create: "invite_logs",
    discord.AuditLogAction.invite_delete: "invite_logs",
    discord.AuditLogAction.invite_update: "invite_logs"
}


@bot.event
async def on_audit_log_entry_create(entry):
    guild = entry.guild

    if guild is None:
        return

    category = AUDIT_LOG_ACTION_CATEGORIES.get(
        entry.action
    )

    if category is None:
        return

    actor = entry.user
    target = entry.target

    actor_text = (
        f"{actor} (`{actor.id}`)"
        if actor
        else "Unknown"
    )

    target_text = (
        f"{target} (`{target.id}`)"
        if target and getattr(target, "id", None)
        else str(target or "Unknown")
    )

    description = (
        f"**Action:** {entry.action.name}\n"
        f"**Executor:** {actor_text}\n"
        f"**Target:** {target_text}\n"
        f"**Reason:** {entry.reason or 'None'}\n"
        f"**Audit Entry ID:** `{entry.id}`"
    )

    await advanced_send_log(
        guild,
        category,
        "Discord Audit Log",
        description,
        discord.Color.blurple()
    )


# ============================================================
# END OF PART 3
# ============================================================



# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 4 - MODERATION SYSTEM
# ============================================================


# ============================================================
# MODERATION HELPERS
# ============================================================

def can_manage_target(interaction, member):
    guild = interaction.guild
    actor = interaction.user
    me = guild.me if guild else None

    if guild is None or me is None:
        return False, "Server information unavailable."

    if member.id == guild.owner_id:
        return False, "The server owner cannot be targeted."

    if member.id == actor.id:
        return False, "You cannot target yourself."

    if member.id == me.id:
        return False, "You cannot target this bot."

    if (
        actor.id != guild.owner_id
        and member.top_role >= actor.top_role
    ):
        return False, "Target has an equal or higher role."

    if member.top_role >= me.top_role:
        return False, "Target is above the bot's role."

    return True, None


def moderator_has_permission(interaction, permission):
    permissions = interaction.user.guild_permissions
    return bool(getattr(permissions, permission, False))


def moderation_embed(action, member, reason):
    return create_embed(
        f"Moderation | {action}",
        (
            f"Member: {member.mention}\n"
            f"User ID: `{member.id}`\n"
            f"Reason: {reason}"
        )
    )


async def moderation_log(
    guild,
    action,
    moderator,
    target,
    reason
):
    await advanced_send_log(
        guild,
        "moderation_logs",
        f"Moderation: {action}",
        (
            f"Moderator: {moderator} "
            f"(`{moderator.id}`)\n"
            f"Target: {target} (`{target.id}`)\n"
            f"Reason: {reason}"
        ),
        discord.Color.orange()
    )


async def deny_permission(interaction):
    await interaction.response.send_message(
        "You do not have the required Discord permissions.",
        ephemeral=True
    )


# ============================================================
# JAIL SYSTEM
# ============================================================

async def get_or_create_jail_role(guild):
    role = discord.utils.get(
        guild.roles,
        name="EXTERNAL | JAILED"
    )

    if role is None:
        role = await guild.create_role(
            name="EXTERNAL | JAILED",
            reason="EXTERNAL jail system"
        )

    me = guild.me
    if me is None or role >= me.top_role:
        raise discord.Forbidden(
            discord.Object(id=guild.id),
            "Jail role is above the bot's role."
        )

    for channel in guild.text_channels:
        await channel.set_permissions(
            role,
            send_messages=False,
            add_reactions=False,
            create_public_threads=False,
            create_private_threads=False,
            send_messages_in_threads=False,
            reason="Configure jail role"
        )

    return role


@bot.tree.command(
    name="jail",
    description="Restrict a member using the jail role."
)
@app_commands.guild_only()
@medium_permission_only()
async def jail_command(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if not moderator_has_permission(
        interaction, "manage_roles"
    ):
        return await deny_permission(interaction)

    allowed, error = can_manage_target(
        interaction, member
    )

    if not allowed:
        await interaction.response.send_message(
            error,
            ephemeral=True
        )
        return

    with db_connect() as db:
        existing = db.execute(
            """
            SELECT 1 FROM jailed_members
            WHERE guild_id = ? AND user_id = ?
            """,
            (interaction.guild_id, member.id)
        ).fetchone()

    if existing:
        await interaction.response.send_message(
            "This member is already jailed.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    try:
        role = await get_or_create_jail_role(
            interaction.guild
        )

        me = interaction.guild.me

        previous_roles = [
            r.id for r in member.roles
            if r != interaction.guild.default_role
            and not r.managed
            and r < me.top_role
        ]

        removable_roles = [
            r for r in member.roles
            if r.id in previous_roles
        ]

        if removable_roles:
            await member.remove_roles(
                *removable_roles,
                reason=f"Jailed by {interaction.user}"
            )

        await member.add_roles(
            role,
            reason=reason
        )

    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Could not jail the member. "
            "Check bot permissions and role hierarchy.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT INTO jailed_members
            (guild_id, user_id, previous_roles,
             jailed_at, jailed_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                interaction.guild_id,
                member.id,
                json.dumps(previous_roles),
                int(time.time()),
                interaction.user.id
            )
        )
        db.commit()

    await interaction.followup.send(
        f"{member.mention} has been jailed.",
        ephemeral=True
    )

    await moderation_log(
        interaction.guild,
        "Jail",
        interaction.user,
        member,
        reason
    )


@bot.tree.command(
    name="unjail",
    description="Release a jailed member."
)
@app_commands.guild_only()
@medium_permission_only()
async def unjail_command(
    interaction: discord.Interaction,
    member: discord.Member
):
    if not moderator_has_permission(
        interaction, "manage_roles"
    ):
        return await deny_permission(interaction)

    allowed, error = can_manage_target(
        interaction, member
    )

    if not allowed:
        await interaction.response.send_message(
            error,
            ephemeral=True
        )
        return

    with db_connect() as db:
        record = db.execute(
            """
            SELECT previous_roles
            FROM jailed_members
            WHERE guild_id = ? AND user_id = ?
            """,
            (interaction.guild_id, member.id)
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "This member is not jailed.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    role = discord.utils.get(
        interaction.guild.roles,
        name="EXTERNAL | JAILED"
    )

    previous_ids = json.loads(
        record["previous_roles"]
    )

    me = interaction.guild.me

    restore_roles = [
        r for r in interaction.guild.roles
        if r.id in previous_ids
        and not r.managed
        and r < me.top_role
    ]

    try:
        if role in member.roles:
            await member.remove_roles(
                role,
                reason="Member unjailed"
            )

        if restore_roles:
            await member.add_roles(
                *restore_roles,
                reason="Restore roles after jail"
            )

    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Failed to restore member roles.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            DELETE FROM jailed_members
            WHERE guild_id = ? AND user_id = ?
            """,
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.followup.send(
        f"{member.mention} has been unjailed.",
        ephemeral=True
    )

    await moderation_log(
        interaction.guild,
        "Unjail",
        interaction.user,
        member,
        "Released from jail"
    )


@bot.tree.command(
    name="jlist",
    description="Show currently jailed members."
)
@app_commands.guild_only()
@medium_permission_only()
async def jlist_command(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT user_id, jailed_at
            FROM jailed_members
            WHERE guild_id = ?
            ORDER BY jailed_at DESC
            LIMIT 30
            """,
            (interaction.guild_id,)
        ).fetchall()

    lines = [
        f"<@{row['user_id']}> "
        f"— <t:{row['jailed_at']}:R>"
        for row in rows
    ]

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | JAIL LIST",
            "\n".join(lines)
            if lines else "No jailed members."
        ),
        ephemeral=True
    )


# ============================================================
# CHANNEL LOCK SYSTEM
# ============================================================

def init_channel_lock_db():
    with db_connect() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS channel_locks (
                channel_id INTEGER PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                previous_send_messages INTEGER
            )
            """
        )
        db.commit()


@bot.tree.command(
    name="lock",
    description="Lock a text channel."
)
@app_commands.guild_only()
@medium_permission_only()
async def lock_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel = None
):
    if not moderator_has_permission(
        interaction, "manage_channels"
    ):
        return await deny_permission(interaction)

    channel = channel or interaction.channel

    if not isinstance(channel, discord.TextChannel):
        await interaction.response.send_message(
            "Select a text channel.",
            ephemeral=True
        )
        return

    init_channel_lock_db()

    with db_connect() as db:
        existing = db.execute(
            "SELECT 1 FROM channel_locks WHERE channel_id = ?",
            (channel.id,)
        ).fetchone()

    if existing:
        await interaction.response.send_message(
            "This channel is already locked by the bot.",
            ephemeral=True
        )
        return

    overwrite = channel.overwrites_for(
        interaction.guild.default_role
    )

    previous = overwrite.send_messages

    previous_value = (
        None if previous is None
        else int(previous)
    )

    overwrite.send_messages = False

    try:
        await channel.set_permissions(
            interaction.guild.default_role,
            overwrite=overwrite,
            reason=f"Locked by {interaction.user}"
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Failed to lock the channel.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT INTO channel_locks
            (channel_id, guild_id, previous_send_messages)
            VALUES (?, ?, ?)
            """,
            (
                channel.id,
                interaction.guild_id,
                previous_value
            )
        )
        db.commit()

    await interaction.response.send_message(
        f"Locked {channel.mention}.",
        ephemeral=True
    )


@bot.tree.command(
    name="unlock",
    description="Restore a channel's previous send permission."
)
@app_commands.guild_only()
@medium_permission_only()
async def unlock_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel = None
):
    if not moderator_has_permission(
        interaction, "manage_channels"
    ):
        return await deny_permission(interaction)

    channel = channel or interaction.channel

    if not isinstance(channel, discord.TextChannel):
        await interaction.response.send_message(
            "Select a text channel.",
            ephemeral=True
        )
        return

    init_channel_lock_db()

    with db_connect() as db:
        record = db.execute(
            """
            SELECT previous_send_messages
            FROM channel_locks
            WHERE channel_id = ?
              AND guild_id = ?
            """,
            (channel.id, interaction.guild_id)
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "No saved lock state for this channel.",
            ephemeral=True
        )
        return

    previous = record["previous_send_messages"]

    overwrite = channel.overwrites_for(
        interaction.guild.default_role
    )

    overwrite.send_messages = (
        None if previous is None
        else bool(previous)
    )

    try:
        await channel.set_permissions(
            interaction.guild.default_role,
            overwrite=overwrite,
            reason=f"Unlocked by {interaction.user}"
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Failed to unlock the channel.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            "DELETE FROM channel_locks WHERE channel_id = ?",
            (channel.id,)
        )
        db.commit()

    await interaction.response.send_message(
        f"Unlocked {channel.mention}.",
        ephemeral=True
    )


# ============================================================
# PURGE SYSTEM
# ============================================================

async def purge_messages(
    interaction,
    amount,
    check=None
):
    if not moderator_has_permission(
        interaction, "manage_messages"
    ):
        return await deny_permission(interaction)

    if not isinstance(
        interaction.channel,
        discord.TextChannel
    ):
        await interaction.response.send_message(
            "Use this command in a text channel.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    try:
        deleted = await interaction.channel.purge(
            limit=amount,
            check=check,
            reason=f"Purge requested by {interaction.user}"
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Purge failed. Check Manage Messages permission.",
            ephemeral=True
        )
        return

    await interaction.followup.send(
        f"Deleted {len(deleted)} message(s).",
        ephemeral=True
    )

    await advanced_send_log(
        interaction.guild,
        "moderation_logs",
        "Message Purge",
        (
            f"Moderator: {interaction.user.mention}\n"
            f"Channel: {interaction.channel.mention}\n"
            f"Messages deleted: {len(deleted)}"
        )
    )


@bot.tree.command(
    name="purge",
    description="Delete recent messages from this channel."
)
@app_commands.guild_only()
@medium_permission_only()
async def purge_command(
    interaction: discord.Interaction,
    amount: app_commands.Range[int, 1, 100]
):
    await purge_messages(interaction, amount)


@bot.tree.command(
    name="purgeuser",
    description="Delete recent messages from a selected member."
)
@app_commands.guild_only()
@medium_permission_only()
async def purgeuser_command(
    interaction: discord.Interaction,
    member: discord.Member,
    amount: app_commands.Range[int, 1, 100] = 25
):
    await purge_messages(
        interaction,
        amount,
        check=lambda message: message.author.id == member.id
    )


@bot.tree.command(
    name="purgebot",
    description="Delete recent messages from a selected bot."
)
@app_commands.guild_only()
@medium_permission_only()
async def purgebot_command(
    interaction: discord.Interaction,
    bot_member: discord.Member,
    amount: app_commands.Range[int, 1, 100] = 25
):
    if not bot_member.bot:
        await interaction.response.send_message(
            "The selected member is not a bot.",
            ephemeral=True
        )
        return

    await purge_messages(
        interaction,
        amount,
        check=lambda message: (
            message.author.id == bot_member.id
        )
    )


# ============================================================
# TIMEOUT / UNMUTE
# ============================================================

@bot.tree.command(
    name="timeout",
    description="Temporarily timeout a member."
)
@app_commands.guild_only()
@medium_permission_only()
async def timeout_command(
    interaction: discord.Interaction,
    member: discord.Member,
    minutes: app_commands.Range[int, 1, 40320],
    reason: str = "No reason provided"
):
    if not moderator_has_permission(
        interaction, "moderate_members"
    ):
        return await deny_permission(interaction)

    allowed, error = can_manage_target(
        interaction, member
    )

    if not allowed:
        await interaction.response.send_message(
            error,
            ephemeral=True
        )
        return

    try:
        await member.timeout(
            timedelta(minutes=minutes),
            reason=reason
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Failed to timeout the member.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        f"Timed out {member.mention} for {minutes} minute(s).",
        ephemeral=True
    )

    await moderation_log(
        interaction.guild,
        "Timeout",
        interaction.user,
        member,
        reason
    )


@bot.tree.command(
    name="unmute",
    description="Remove a member's timeout."
)
@app_commands.guild_only()
@medium_permission_only()
async def unmute_command(
    interaction: discord.Interaction,
    member: discord.Member
):
    if not moderator_has_permission(
        interaction, "moderate_members"
    ):
        return await deny_permission(interaction)

    allowed, error = can_manage_target(
        interaction, member
    )

    if not allowed:
        await interaction.response.send_message(
            error,
            ephemeral=True
        )
        return

    try:
        await member.timeout(
            None,
            reason=f"Unmuted by {interaction.user}"
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Failed to remove timeout.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        f"Removed timeout from {member.mention}.",
        ephemeral=True
    )


# ============================================================
# HIGH-LEVEL MODERATION
# ============================================================

def high_moderation_allowed(interaction, permission):
    if not is_high_authorized(
        interaction.guild,
        interaction.user.id
    ):
        return False

    return moderator_has_permission(
        interaction,
        permission
    )


@bot.tree.command(
    name="kick",
    description="Kick a member from the server."
)
@app_commands.guild_only()
async def kick_command_v2(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if not high_moderation_allowed(
        interaction, "kick_members"
    ):
        return await deny_permission(interaction)

    allowed, error = can_manage_target(
        interaction, member
    )

    if not allowed:
        await interaction.response.send_message(
            error,
            ephemeral=True
        )
        return

    try:
        await member.kick(reason=reason)
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Kick failed.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        f"Kicked {member}.",
        ephemeral=True
    )

    await moderation_log(
        interaction.guild,
        "Kick",
        interaction.user,
        member,
        reason
    )


@bot.tree.command(
    name="ban",
    description="Ban a member from the server."
)
@app_commands.guild_only()
async def ban_command_v2(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided"
):
    if not high_moderation_allowed(
        interaction, "ban_members"
    ):
        return await deny_permission(interaction)

    allowed, error = can_manage_target(
        interaction, member
    )

    if not allowed:
        await interaction.response.send_message(
            error,
            ephemeral=True
        )
        return

    try:
        await member.ban(reason=reason)
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Ban failed.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        f"Banned {member}.",
        ephemeral=True
    )

    await moderation_log(
        interaction.guild,
        "Ban",
        interaction.user,
        member,
        reason
    )


@bot.tree.command(
    name="unban",
    description="Unban a user by Discord user ID."
)
@app_commands.guild_only()
async def unban_command(
    interaction: discord.Interaction,
    user_id: str,
    reason: str = "No reason provided"
):
    if not high_moderation_allowed(
        interaction, "ban_members"
    ):
        return await deny_permission(interaction)

    try:
        target_id = int(user_id)
        if target_id <= 0:
            raise ValueError()
    except ValueError:
        await interaction.response.send_message(
            "Invalid user ID.",
            ephemeral=True
        )
        return

    try:
        user = await bot.fetch_user(target_id)

        await interaction.guild.unban(
            user,
            reason=reason
        )

    except discord.NotFound:
        await interaction.response.send_message(
            "User not found or not banned.",
            ephemeral=True
        )
        return

    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Unban failed.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        f"Unbanned {user}.",
        ephemeral=True
    )

    await moderation_log(
        interaction.guild,
        "Unban",
        interaction.user,
        user,
        reason
    )


# ============================================================
# END OF PART 4
# ============================================================



# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 5 - UTILITY, AFK, SNIPE AND STICKY
# ============================================================


# ============================================================
# AVATAR COMMAND
# ============================================================

@bot.tree.command(
    name="avatar",
    description="Display a user's Discord avatar."
)
@app_commands.guild_only()
async def avatar_command(
    interaction: discord.Interaction,
    member: discord.Member = None
):
    member = member or interaction.user

    avatar = member.display_avatar

    embed = create_embed(
        "EXTERNAL | USER AVATAR",
        f"Avatar of {member.mention}"
    )

    embed.set_image(url=avatar.url)

    await interaction.response.send_message(
        embed=embed
    )


# ============================================================
# BANNER COMMAND
# ============================================================

@bot.tree.command(
    name="banner",
    description="Display a user's profile banner."
)
@app_commands.guild_only()
async def banner_command(
    interaction: discord.Interaction,
    member: discord.Member = None
):
    member = member or interaction.user

    try:
        user = await bot.fetch_user(member.id)
    except discord.HTTPException:
        await interaction.response.send_message(
            "Could not retrieve this user's profile.",
            ephemeral=True
        )
        return

    if user.banner is None:
        await interaction.response.send_message(
            "This user does not have a profile banner.",
            ephemeral=True
        )
        return

    embed = create_embed(
        "EXTERNAL | USER BANNER",
        f"Banner of {member.mention}"
    )

    embed.set_image(url=user.banner.url)

    await interaction.response.send_message(
        embed=embed
    )


# ============================================================
# USER INFORMATION
# ============================================================

@bot.tree.command(
    name="userinfo",
    description="Show information about a server member."
)
@app_commands.guild_only()
async def userinfo_command(
    interaction: discord.Interaction,
    member: discord.Member = None
):
    member = member or interaction.user

    created = int(member.created_at.timestamp())

    joined = (
        int(member.joined_at.timestamp())
        if member.joined_at
        else None
    )

    joined_text = (
        f"<t:{joined}:F>"
        if joined
        else "Unavailable"
    )

    roles = [
        role.mention
        for role in reversed(member.roles)
        if role != interaction.guild.default_role
    ]

    roles_text = (
        ", ".join(roles[:15])
        if roles
        else "No additional roles"
    )

    embed = create_embed(
        "EXTERNAL | USER INFORMATION",
        (
            f"**Username:** {discord.utils.escape_markdown(str(member))}\n"
            f"**Display Name:** {discord.utils.escape_markdown(member.display_name)}\n"
            f"**User ID:** `{member.id}`\n"
            f"**Bot Account:** {'Yes' if member.bot else 'No'}\n"
            f"**Created:** <t:{created}:F>\n"
            f"**Joined Server:** {joined_text}\n"
            f"**Top Role:** {member.top_role.mention}\n"
            f"**Roles:** {roles_text}"
        )
    )

    embed.set_thumbnail(
        url=member.display_avatar.url
    )

    await interaction.response.send_message(
        embed=embed
    )


# ============================================================
# SERVER INFORMATION
# ============================================================

@bot.tree.command(
    name="serverinfo",
    description="Display server information."
)
@app_commands.guild_only()
async def serverinfo_command(
    interaction: discord.Interaction
):
    guild = interaction.guild

    created = int(guild.created_at.timestamp())

    embed = create_embed(
        "EXTERNAL | SERVER INFORMATION",
        (
            f"**Server Name:** {discord.utils.escape_markdown(guild.name)}\n"
            f"**Server ID:** `{guild.id}`\n"
            f"**Owner:** <@{guild.owner_id}>\n"
            f"**Created:** <t:{created}:F>\n"
            f"**Members:** {guild.member_count or 0}\n"
            f"**Text Channels:** {len(guild.text_channels)}\n"
            f"**Voice Channels:** {len(guild.voice_channels)}\n"
            f"**Roles:** {len(guild.roles)}\n"
            f"**Boost Level:** {guild.premium_tier}\n"
            f"**Boost Count:** {guild.premium_subscription_count or 0}\n"
            f"**EXTERNAL Premium:** "
            f"{'Active' if is_premium(guild.id) else 'Inactive'}"
        )
    )

    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)

    await interaction.response.send_message(
        embed=embed
    )


# ============================================================
# AFK SYSTEM
# ============================================================

@bot.tree.command(
    name="afk",
    description="Set your AFK status."
)
@app_commands.guild_only()
async def afk_command(
    interaction: discord.Interaction,
    reason: str = "AFK"
):
    reason = reason.strip()[:200] or "AFK"

    with db_connect() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO afk_users
            (guild_id, user_id, reason, started_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                interaction.guild_id,
                interaction.user.id,
                reason,
                int(time.time())
            )
        )
        db.commit()

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | AFK",
            (
                f"{interaction.user.mention} is now AFK.\n"
                f"**Reason:** {discord.utils.escape_markdown(reason)}"
            )
        )
    )


async def process_afk_message(message):
    if message.guild is None or message.author.bot:
        return

    guild_id = message.guild.id

    with db_connect() as db:
        own_record = db.execute(
            """
            SELECT reason FROM afk_users
            WHERE guild_id = ? AND user_id = ?
            """,
            (guild_id, message.author.id)
        ).fetchone()

        if own_record:
            db.execute(
                """
                DELETE FROM afk_users
                WHERE guild_id = ? AND user_id = ?
                """,
                (guild_id, message.author.id)
            )
            db.commit()

    if own_record:
        try:
            await message.channel.send(
                f"{message.author.mention}, "
                "your AFK status has been removed.",
                delete_after=8,
                allowed_mentions=discord.AllowedMentions.none()
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    mentioned_ids = set(message.raw_mentions)

    if not mentioned_ids:
        return

    with db_connect() as db:
        records = db.execute(
            """
            SELECT user_id, reason, started_at
            FROM afk_users
            WHERE guild_id = ?
            """,
            (guild_id,)
        ).fetchall()

    notices = []

    for record in records:
        if record["user_id"] in mentioned_ids:
            notices.append(
                f"<@{record['user_id']}> is AFK: "
                f"{discord.utils.escape_markdown(record['reason'] or 'AFK')}"
            )

    if notices:
        try:
            await message.channel.send(
                "\n".join(notices[:5]),
                delete_after=15,
                allowed_mentions=discord.AllowedMentions.none()
            )
        except (discord.Forbidden, discord.HTTPException):
            pass


# ============================================================
# SNIPE CACHE
# ============================================================

SNIPE_RETENTION_SECONDS = 300


def cache_deleted_message(message):
    if message.guild is None:
        return

    if message.author.bot:
        return

    if not message.content:
        return

    snipe_cache[
        (message.guild.id, message.channel.id)
    ] = {
        "author_id": message.author.id,
        "content": message.content[:1500],
        "timestamp": int(time.time())
    }


def cache_edited_message(before, after):
    if before.guild is None:
        return

    if before.author.bot:
        return

    if before.content == after.content:
        return

    edit_snipe_cache[
        (before.guild.id, before.channel.id)
    ] = {
        "author_id": before.author.id,
        "before": (before.content or "")[:1000],
        "after": (after.content or "")[:1000],
        "timestamp": int(time.time())
    }


# ============================================================
# CLEAR SNIPE
# ============================================================

@bot.tree.command(
    name="clearsnipe",
    description="View the latest deleted message in a channel."
)
@app_commands.guild_only()
@medium_permission_only()
async def clearsnipe_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel = None
):
    if not moderator_has_permission(
        interaction,
        "manage_messages"
    ):
        return await deny_permission(interaction)

    channel = channel or interaction.channel

    record = snipe_cache.get(
        (interaction.guild_id, channel.id)
    )

    if (
        record is None
        or time.time() - record["timestamp"] >
        SNIPE_RETENTION_SECONDS
    ):
        await interaction.response.send_message(
            "No recent deleted message available.",
            ephemeral=True
        )
        return

    embed = create_embed(
        "EXTERNAL | DELETED MESSAGE",
        (
            f"**Author:** <@{record['author_id']}>\n"
            f"**Channel:** {channel.mention}\n"
            f"**Deleted:** <t:{record['timestamp']}:R>\n\n"
            f"**Content:**\n"
            f"{discord.utils.escape_markdown(record['content'])}"
        )
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True
    )


# ============================================================
# EDIT SNIPE
# ============================================================

@bot.tree.command(
    name="editsnipe",
    description="View the latest edited message in a channel."
)
@app_commands.guild_only()
@medium_permission_only()
async def editsnipe_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel = None
):
    if not moderator_has_permission(
        interaction,
        "manage_messages"
    ):
        return await deny_permission(interaction)

    channel = channel or interaction.channel

    record = edit_snipe_cache.get(
        (interaction.guild_id, channel.id)
    )

    if (
        record is None
        or time.time() - record["timestamp"] >
        SNIPE_RETENTION_SECONDS
    ):
        await interaction.response.send_message(
            "No recent edited message available.",
            ephemeral=True
        )
        return

    embed = create_embed(
        "EXTERNAL | EDITED MESSAGE",
        (
            f"**Author:** <@{record['author_id']}>\n"
            f"**Channel:** {channel.mention}\n"
            f"**Edited:** <t:{record['timestamp']}:R>\n\n"
            f"**Before:**\n"
            f"{discord.utils.escape_markdown(record['before'])}\n\n"
            f"**After:**\n"
            f"{discord.utils.escape_markdown(record['after'])}"
        )
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True
    )


# ============================================================
# STICKY MESSAGE SYSTEM
# ============================================================

stick_group = app_commands.Group(
    name="stick",
    description="Manage sticky channel messages."
)


@stick_group.command(
    name="set",
    description="Create or update a sticky message."
)
@medium_permission_only()
async def stick_set(
    interaction: discord.Interaction,
    message: str
):
    if not moderator_has_permission(
        interaction,
        "manage_messages"
    ):
        return await deny_permission(interaction)

    if not isinstance(
        interaction.channel,
        discord.TextChannel
    ):
        await interaction.response.send_message(
            "Use this in a text channel.",
            ephemeral=True
        )
        return

    if len(message) > 1800:
        await interaction.response.send_message(
            "Sticky message must be 1800 characters or fewer.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO sticky_messages
            (guild_id, channel_id, message,
             last_message_id, enabled)
            VALUES (?, ?, ?, NULL, 1)
            """,
            (
                interaction.guild_id,
                interaction.channel_id,
                message
            )
        )
        db.commit()

    await interaction.response.send_message(
        "Sticky message configured.",
        ephemeral=True
    )


@stick_group.command(
    name="remove",
    description="Remove a channel's sticky message."
)
@medium_permission_only()
async def stick_remove(
    interaction: discord.Interaction
):
    if not moderator_has_permission(
        interaction,
        "manage_messages"
    ):
        return await deny_permission(interaction)

    with db_connect() as db:
        cursor = db.execute(
            """
            DELETE FROM sticky_messages
            WHERE guild_id = ? AND channel_id = ?
            """,
            (
                interaction.guild_id,
                interaction.channel_id
            )
        )
        db.commit()

    await interaction.response.send_message(
        (
            "Sticky message removed."
            if cursor.rowcount
            else "No sticky message configured."
        ),
        ephemeral=True
    )


@stick_group.command(
    name="view",
    description="View the configured sticky message."
)
@medium_permission_only()
async def stick_view(
    interaction: discord.Interaction
):
    with db_connect() as db:
        record = db.execute(
            """
            SELECT message, enabled
            FROM sticky_messages
            WHERE guild_id = ? AND channel_id = ?
            """,
            (
                interaction.guild_id,
                interaction.channel_id
            )
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "No sticky message configured.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | STICKY MESSAGE",
            discord.utils.escape_markdown(
                record["message"]
            )
        ),
        ephemeral=True
    )


bot.tree.add_command(stick_group)


# ============================================================
# STICKY MESSAGE PROCESSOR
# Called by the final on_message handler.
# ============================================================

async def process_sticky_message(message):
    if message.guild is None or message.author.bot:
        return

    channel = message.channel

    if not isinstance(channel, discord.TextChannel):
        return

    with db_connect() as db:
        record = db.execute(
            """
            SELECT message, last_message_id
            FROM sticky_messages
            WHERE guild_id = ?
              AND channel_id = ?
              AND enabled = 1
            """,
            (
                message.guild.id,
                channel.id
            )
        ).fetchone()

    if record is None:
        return

    key = (message.guild.id, channel.id)

    now = time.monotonic()

    if now - sticky_cooldowns.get(key, 0) < 15:
        return

    sticky_cooldowns[key] = now

    old_message_id = record["last_message_id"]

    if old_message_id:
        try:
            old_message = await channel.fetch_message(
                old_message_id
            )
            await old_message.delete()
        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException
        ):
            pass

    try:
        new_message = await channel.send(
            embed=create_embed(
                "EXTERNAL | STICKY MESSAGE",
                discord.utils.escape_markdown(
                    record["message"]
                )
            ),
            allowed_mentions=discord.AllowedMentions.none()
        )
    except (discord.Forbidden, discord.HTTPException):
        return

    with db_connect() as db:
        db.execute(
            """
            UPDATE sticky_messages
            SET last_message_id = ?
            WHERE guild_id = ? AND channel_id = ?
            """,
            (
                new_message.id,
                message.guild.id,
                channel.id
            )
        )
        db.commit()


# ============================================================
# END OF PART 5
# ============================================================



# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 6 - PREMIUM COMMANDS
# ============================================================


# ============================================================
# PREMIUM PERMISSION CHECK
# ============================================================

def premium_admin_only():

    async def predicate(interaction):
        if interaction.guild is None:
            raise app_commands.CheckFailure(
                "This command is server-only."
            )

        if not is_premium(interaction.guild.id):
            raise app_commands.CheckFailure(
                "This server does not have premium."
            )

        if not is_high_authorized(
            interaction.guild,
            interaction.user.id
        ):
            raise app_commands.CheckFailure(
                "Only the server owner or bot owner "
                "can use this premium command."
            )

        return True

    return app_commands.check(predicate)


def premium_permission_allowed(interaction, permission):
    return bool(
        interaction.user.guild_permissions.administrator
        or getattr(
            interaction.user.guild_permissions,
            permission,
            False
        )
    )


# ============================================================
# PREMIUM SCRIPT LIBRARY
# ============================================================

leak_group = app_commands.Group(
    name="leak",
    description="Share your own or public scripts."
)


@leak_group.command(
    name="script",
    description="Publish a script in the server."
)
@app_commands.guild_only()
@premium_admin_only()
async def leak_script_command(
    interaction: discord.Interaction,
    name: str,
    language: str,
    description: str,
    source_url: str
):
    source_url = source_url.strip()

    if not source_url.startswith(
        ("https://", "http://")
    ):
        await interaction.response.send_message(
            "Provide a valid public source URL.",
            ephemeral=True
        )
        return

    if len(name) > 100 or len(description) > 1000:
        await interaction.response.send_message(
            "Script name or description is too long.",
            ephemeral=True
        )
        return

    embed = create_embed(
        "EXTERNAL | SCRIPT LIBRARY",
        (
            f"**Script:** "
            f"{discord.utils.escape_markdown(name)}\n"
            f"**Language:** "
            f"{discord.utils.escape_markdown(language[:60])}\n\n"
            f"**Description:**\n"
            f"{discord.utils.escape_markdown(description)}"
        )
    )

    embed.add_field(
        name="Public Source",
        value=discord.utils.escape_markdown(
            source_url[:1000]
        ),
        inline=False
    )

    embed.add_field(
        name="Shared By",
        value=interaction.user.mention,
        inline=False
    )

    await interaction.response.send_message(
        embed=embed,
        allowed_mentions=discord.AllowedMentions.none()
    )


bot.tree.add_command(leak_group)


# ============================================================
# PREMIUM MEMBER BYPASS
# ============================================================

bypass_group = app_commands.Group(
    name="bypass",
    description="Manage premium security exemptions."
)

bypass_member_group = app_commands.Group(
    name="member",
    description="Manage member filter exemptions.",
    parent=bypass_group
)

bypass_bot_group = app_commands.Group(
    name="bot",
    description="Manage trusted bots.",
    parent=bypass_group
)


BYPASS_FILTER_CHOICES = [
    app_commands.Choice(
        name="All AutoMod Filters",
        value="all"
    ),
    app_commands.Choice(
        name="Anti-Link",
        value="antilink"
    ),
    app_commands.Choice(
        name="Anti-Mention",
        value="antimention"
    ),
    app_commands.Choice(
        name="Anti-NSFW",
        value="antinsfw"
    )
]


@bypass_member_group.command(
    name="add",
    description="Exempt a member from a selected filter."
)
@app_commands.choices(filter_name=BYPASS_FILTER_CHOICES)
@premium_admin_only()
async def bypass_member_add(
    interaction: discord.Interaction,
    member: discord.Member,
    filter_name: app_commands.Choice[str]
):
    with db_connect() as db:
        db.execute(
            """
            INSERT OR IGNORE INTO premium_bypass
            (guild_id, target_id, bypass_type)
            VALUES (?, ?, ?)
            """,
            (
                interaction.guild_id,
                member.id,
                filter_name.value
            )
        )
        db.commit()

    await interaction.response.send_message(
        f"Added exemption for {member.mention}: "
        f"{filter_name.name}.",
        ephemeral=True
    )


@bypass_member_group.command(
    name="remove",
    description="Remove a member's filter exemption."
)
@app_commands.choices(filter_name=BYPASS_FILTER_CHOICES)
@premium_admin_only()
async def bypass_member_remove(
    interaction: discord.Interaction,
    member: discord.Member,
    filter_name: app_commands.Choice[str]
):
    with db_connect() as db:
        cursor = db.execute(
            """
            DELETE FROM premium_bypass
            WHERE guild_id = ?
              AND target_id = ?
              AND bypass_type = ?
            """,
            (
                interaction.guild_id,
                member.id,
                filter_name.value
            )
        )
        db.commit()

    await interaction.response.send_message(
        (
            "Member exemption removed."
            if cursor.rowcount
            else "No matching exemption found."
        ),
        ephemeral=True
    )


@bypass_member_group.command(
    name="list",
    description="List premium member exemptions."
)
@premium_admin_only()
async def bypass_member_list(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT target_id, bypass_type
            FROM premium_bypass
            WHERE guild_id = ?
            ORDER BY target_id
            LIMIT 40
            """,
            (interaction.guild_id,)
        ).fetchall()

    lines = [
        f"<@{row['target_id']}> - "
        f"`{row['bypass_type']}`"
        for row in rows
    ]

    await interaction.response.send_message(
        embed=create_embed(
            "Premium Member Bypass",
            "\n".join(lines)
            if lines else "No member exemptions."
        ),
        ephemeral=True
    )


# ============================================================
# PREMIUM TRUSTED BOTS
# ============================================================

@bypass_bot_group.command(
    name="add",
    description="Add a trusted bot."
)
@premium_admin_only()
async def bypass_bot_add(
    interaction: discord.Interaction,
    member: discord.Member
):
    if not member.bot:
        await interaction.response.send_message(
            "Selected member is not a bot.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT OR IGNORE INTO trusted_bots
            (guild_id, bot_id)
            VALUES (?, ?)
            """,
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        f"Trusted bot added: {member.mention}.",
        ephemeral=True
    )


@bypass_bot_group.command(
    name="remove",
    description="Remove a trusted bot."
)
@premium_admin_only()
async def bypass_bot_remove(
    interaction: discord.Interaction,
    member: discord.Member
):
    with db_connect() as db:
        cursor = db.execute(
            """
            DELETE FROM trusted_bots
            WHERE guild_id = ?
              AND bot_id = ?
            """,
            (interaction.guild_id, member.id)
        )
        db.commit()

    await interaction.response.send_message(
        (
            "Trusted bot removed."
            if cursor.rowcount
            else "Bot is not on the trusted list."
        ),
        ephemeral=True
    )


@bypass_bot_group.command(
    name="list",
    description="List trusted bots."
)
@premium_admin_only()
async def bypass_bot_list(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT bot_id
            FROM trusted_bots
            WHERE guild_id = ?
            LIMIT 40
            """,
            (interaction.guild_id,)
        ).fetchall()

    content = (
        "\n".join(
            f"<@{row['bot_id']}> (`{row['bot_id']}`)"
            for row in rows
        )
        if rows else "No trusted bots."
    )

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | TRUSTED BOTS",
            content
        ),
        ephemeral=True
    )


bot.tree.add_command(bypass_group)


# ============================================================
# PREMIUM SERVER BAN LIST
# ============================================================

@bot.tree.command(
    name="server-ban-list",
    description="View the server's banned users."
)
@app_commands.guild_only()
@premium_admin_only()
async def server_ban_list_command(
    interaction: discord.Interaction
):
    if not premium_permission_allowed(
        interaction, "ban_members"
    ):
        await deny_permission(interaction)
        return

    await interaction.response.defer(ephemeral=True)

    entries = []

    try:
        async for ban_entry in interaction.guild.bans(
            limit=30
        ):
            user = ban_entry.user
            entries.append(
                f"{discord.utils.escape_markdown(str(user))} "
                f"(`{user.id}`)"
            )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Unable to retrieve the ban list.",
            ephemeral=True
        )
        return

    await interaction.followup.send(
        embed=create_embed(
            "EXTERNAL | SERVER BAN LIST",
            "\n".join(entries)
            if entries else "No bans found."
        ),
        ephemeral=True
    )


# ============================================================
# PREMIUM INVITE CREATION
# ============================================================

@bot.tree.command(
    name="create-invite",
    description="Create a Discord server invite."
)
@app_commands.guild_only()
@premium_admin_only()
async def create_invite_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel = None,
    hours: app_commands.Range[int, 0, 168] = 24,
    max_uses: app_commands.Range[int, 0, 100] = 0
):
    if not premium_permission_allowed(
        interaction, "create_instant_invite"
    ):
        await deny_permission(interaction)
        return

    channel = channel or interaction.channel

    if not isinstance(channel, discord.TextChannel):
        await interaction.response.send_message(
            "Select a text channel.",
            ephemeral=True
        )
        return

    try:
        invite = await channel.create_invite(
            max_age=hours * 3600,
            max_uses=max_uses,
            unique=True,
            reason=f"Created by {interaction.user}"
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Unable to create invite.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        f"Invite created:\n{invite.url}",
        ephemeral=True
    )


# ============================================================
# PREMIUM EMOJI IMPORT
# ============================================================

@bot.tree.command(
    name="steal-emoji",
    description="Import an emoji from an image attachment."
)
@app_commands.guild_only()
@premium_admin_only()
async def steal_emoji_command(
    interaction: discord.Interaction,
    name: str,
    image: discord.Attachment
):
    if not premium_permission_allowed(
        interaction, "manage_emojis_and_stickers"
    ):
        await deny_permission(interaction)
        return

    if not re.fullmatch(r"[A-Za-z0-9_]{2,32}", name):
        await interaction.response.send_message(
            "Emoji name must be 2-32 letters, "
            "numbers or underscores.",
            ephemeral=True
        )
        return

    if image.size > 256 * 1024:
        await interaction.response.send_message(
            "Image must be 256 KB or smaller.",
            ephemeral=True
        )
        return

    if not image.filename.lower().endswith(
        (".png", ".jpg", ".jpeg", ".gif")
    ):
        await interaction.response.send_message(
            "Upload a PNG, JPG or GIF image.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    try:
        data = await image.read()

        emoji = await interaction.guild.create_custom_emoji(
            name=name,
            image=data,
            reason=f"Imported by {interaction.user}"
        )

    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Emoji import failed. Check permissions, "
            "image format and available emoji slots.",
            ephemeral=True
        )
        return

    await interaction.followup.send(
        f"Emoji created: {emoji}",
        ephemeral=True
    )


# ============================================================
# PREMIUM STICKER IMPORT
# ============================================================

@bot.tree.command(
    name="steal-sticker",
    description="Import a sticker from a PNG attachment."
)
@app_commands.guild_only()
@premium_admin_only()
async def steal_sticker_command(
    interaction: discord.Interaction,
    name: str,
    description: str,
    emoji: str,
    image: discord.Attachment
):
    if not premium_permission_allowed(
        interaction, "manage_emojis_and_stickers"
    ):
        await deny_permission(interaction)
        return

    if not image.filename.lower().endswith(".png"):
        await interaction.response.send_message(
            "This command accepts PNG stickers only.",
            ephemeral=True
        )
        return

    if image.size > 512 * 1024:
        await interaction.response.send_message(
            "Sticker image must be 512 KB or smaller.",
            ephemeral=True
        )
        return

    if not (2 <= len(name) <= 30):
        await interaction.response.send_message(
            "Sticker name must contain 2-30 characters.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    try:
        data = await image.read()

        sticker_file = discord.File(
            fp=__import__("io").BytesIO(data),
            filename="sticker.png"
        )

        sticker = await interaction.guild.create_sticker(
            name=name,
            description=description[:100],
            emoji=emoji,
            file=sticker_file,
            reason=f"Imported by {interaction.user}"
        )

    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Sticker import failed. Check permissions, "
            "PNG dimensions and available sticker slots.",
            ephemeral=True
        )
        return

    await interaction.followup.send(
        f"Sticker created: {sticker.name}",
        ephemeral=True
    )


# ============================================================
# END OF PART 6
# ============================================================


# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 7 - BACKUPS, GIVEAWAYS, EVENTS AND PREMIUM UTILITIES
# ============================================================

import secrets


# ============================================================
# BACKUP HELPERS
# ============================================================

def make_backup_id():
    return "EXT-" + secrets.token_hex(5).upper()


def build_server_backup(guild):
    return {
        "version": 1,
        "guild_name": guild.name,
        "created_at": int(time.time()),
        "roles": [
            {
                "name": role.name,
                "color": role.color.value,
                "hoist": role.hoist,
                "mentionable": role.mentionable
            }
            for role in guild.roles
            if role != guild.default_role
            and not role.managed
        ],
        "categories": [
            {
                "name": category.name,
                "position": category.position
            }
            for category in guild.categories
        ],
        "text_channels": [
            {
                "name": channel.name,
                "category": (
                    channel.category.name
                    if channel.category else None
                ),
                "topic": channel.topic,
                "nsfw": channel.nsfw,
                "slowmode_delay": channel.slowmode_delay
            }
            for channel in guild.text_channels
        ],
        "voice_channels": [
            {
                "name": channel.name,
                "category": (
                    channel.category.name
                    if channel.category else None
                ),
                "user_limit": channel.user_limit,
                "bitrate": channel.bitrate
            }
            for channel in guild.voice_channels
        ]
    }


# ============================================================
# SERVER BACKUP
# ============================================================

@bot.tree.command(
    name="backup",
    description="Save a backup of the server structure."
)
@app_commands.guild_only()
@premium_admin_only()
async def backup_command(
    interaction: discord.Interaction
):
    if not moderator_has_permission(
        interaction, "manage_guild"
    ):
        return await deny_permission(interaction)

    backup_id = make_backup_id()
    data = build_server_backup(interaction.guild)

    with db_connect() as db:
        db.execute(
            """
            INSERT INTO server_backups
            (backup_id, guild_id, created_by,
             created_at, backup_data)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                backup_id,
                interaction.guild_id,
                interaction.user.id,
                int(time.time()),
                json.dumps(data)
            )
        )
        db.commit()

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | BACKUP CREATED",
            (
                f"Backup ID: `{backup_id}`\n"
                f"Roles: {len(data['roles'])}\n"
                f"Categories: {len(data['categories'])}\n"
                f"Text Channels: {len(data['text_channels'])}\n"
                f"Voice Channels: {len(data['voice_channels'])}\n\n"
                "This is a structure backup, not a "
                "backup of messages or member data."
            )
        ),
        ephemeral=True
    )


# ============================================================
# BACKUP LIST AND PREVIEW
# ============================================================

backup_group = app_commands.Group(
    name="backup-manage",
    description="Manage saved server backups."
)


@backup_group.command(
    name="list",
    description="List saved server backups."
)
@premium_admin_only()
async def backup_list_command(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT backup_id, created_at
            FROM server_backups
            WHERE guild_id = ?
            ORDER BY created_at DESC
            LIMIT 20
            """,
            (interaction.guild_id,)
        ).fetchall()

    lines = [
        f"`{row['backup_id']}` - "
        f"<t:{row['created_at']}:F>"
        for row in rows
    ]

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | BACKUP LIST",
            "\n".join(lines)
            if lines else "No backups saved."
        ),
        ephemeral=True
    )


@backup_group.command(
    name="preview",
    description="Preview a saved backup."
)
@premium_admin_only()
async def backup_preview_command(
    interaction: discord.Interaction,
    backup_id: str
):
    with db_connect() as db:
        record = db.execute(
            """
            SELECT backup_data
            FROM server_backups
            WHERE backup_id = ?
              AND guild_id = ?
            """,
            (backup_id, interaction.guild_id)
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "Backup not found in this server.",
            ephemeral=True
        )
        return

    data = json.loads(record["backup_data"])

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | BACKUP PREVIEW",
            (
                f"Backup ID: `{backup_id}`\n"
                f"Original Server: "
                f"{discord.utils.escape_markdown(data['guild_name'])}\n"
                f"Roles: {len(data['roles'])}\n"
                f"Categories: {len(data['categories'])}\n"
                f"Text Channels: {len(data['text_channels'])}\n"
                f"Voice Channels: {len(data['voice_channels'])}"
            )
        ),
        ephemeral=True
    )


bot.tree.add_command(backup_group)


# ============================================================
# BACKUP RESTORE
# Non-destructive: creates missing categories/channels.
# Existing channels and roles are not deleted.
# ============================================================

@bot.tree.command(
    name="backupload",
    description="Restore missing channels from a backup."
)
@app_commands.guild_only()
@premium_admin_only()
async def backupload_command(
    interaction: discord.Interaction,
    backup_id: str,
    confirm: bool = False
):
    if not moderator_has_permission(
        interaction, "manage_channels"
    ):
        return await deny_permission(interaction)

    with db_connect() as db:
        record = db.execute(
            """
            SELECT backup_data
            FROM server_backups
            WHERE backup_id = ?
              AND guild_id = ?
            """,
            (backup_id, interaction.guild_id)
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "Backup not found.",
            ephemeral=True
        )
        return

    data = json.loads(record["backup_data"])

    if not confirm:
        await interaction.response.send_message(
            embed=create_embed(
                "EXTERNAL | RESTORE CONFIRMATION",
                (
                    f"Backup: `{backup_id}`\n\n"
                    "This operation creates missing categories "
                    "and channels. It will not delete existing "
                    "channels.\n\n"
                    "Run the command again with confirm=True "
                    "to proceed."
                )
            ),
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    created = 0
    failed = 0

    categories = {
        category.name: category
        for category in guild.categories
    }

    for item in data.get("categories", []):
        name = item["name"]

        if name in categories:
            continue

        try:
            category = await guild.create_category(
                name,
                reason=f"Backup restore {backup_id}"
            )
            categories[name] = category
            created += 1
        except (discord.Forbidden, discord.HTTPException):
            failed += 1

    for item in data.get("text_channels", []):
        category = categories.get(item.get("category"))

        exists = any(
            channel.name == item["name"]
            and channel.category == category
            for channel in guild.text_channels
        )

        if exists:
            continue

        try:
            await guild.create_text_channel(
                item["name"],
                category=category,
                topic=item.get("topic"),
                nsfw=item.get("nsfw", False),
                slowmode_delay=item.get(
                    "slowmode_delay", 0
                ),
                reason=f"Backup restore {backup_id}"
            )
            created += 1
        except (discord.Forbidden, discord.HTTPException):
            failed += 1

    for item in data.get("voice_channels", []):
        category = categories.get(item.get("category"))

        exists = any(
            channel.name == item["name"]
            and channel.category == category
            for channel in guild.voice_channels
        )

        if exists:
            continue

        try:
            await guild.create_voice_channel(
                item["name"],
                category=category,
                user_limit=item.get("user_limit", 0),
                reason=f"Backup restore {backup_id}"
            )
            created += 1
        except (discord.Forbidden, discord.HTTPException):
            failed += 1

    await interaction.followup.send(
        f"Restore completed.\n"
        f"Created: {created}\n"
        f"Failed: {failed}\n\n"
        "Role restoration and permission overwrites "
        "are not included in this version.",
        ephemeral=True
    )


# ============================================================
# GIVEAWAY DATABASE EXTENSION
# ============================================================

def init_giveaway_entries():
    with db_connect() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS giveaway_entries (
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (message_id, user_id)
            )
            """
        )
        db.commit()


# ============================================================
# GIVEAWAY ENTRY BUTTON
# ============================================================

class GiveawayEntryView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Enter Giveaway",
        style=discord.ButtonStyle.success,
        custom_id="external_giveaway_enter"
    )
    async def enter(self, interaction, button):
        init_giveaway_entries()

        if interaction.guild is None:
            await interaction.response.send_message(
                "Server-only giveaway.",
                ephemeral=True
            )
            return

        message_id = interaction.message.id

        with db_connect() as db:
            giveaway = db.execute(
                """
                SELECT status, ends_at, guild_id
                FROM giveaways
                WHERE message_id = ?
                """,
                (message_id,)
            ).fetchone()

            if (
                giveaway is None
                or giveaway["status"] != "active"
                or giveaway["guild_id"] != interaction.guild_id
                or int(time.time()) >= giveaway["ends_at"]
            ):
                await interaction.response.send_message(
                    "This giveaway is closed.",
                    ephemeral=True
                )
                return

            if interaction.user.bot:
                await interaction.response.send_message(
                    "Bots cannot enter giveaways.",
                    ephemeral=True
                )
                return

            cursor = db.execute(
                """
                INSERT OR IGNORE INTO giveaway_entries
                (message_id, user_id)
                VALUES (?, ?)
                """,
                (message_id, interaction.user.id)
            )
            db.commit()

        await interaction.response.send_message(
            (
                "You entered the giveaway."
                if cursor.rowcount
                else "You have already entered."
            ),
            ephemeral=True
        )


# ============================================================
# GIVEAWAY COMMAND GROUP
# ============================================================

giveaway_group = app_commands.Group(
    name="giveaway",
    description="Create and manage giveaways."
)


@giveaway_group.command(
    name="start",
    description="Start a giveaway."
)
@medium_permission_only()
async def giveaway_start_command(
    interaction: discord.Interaction,
    prize: str,
    minutes: app_commands.Range[int, 1, 10080]
):
    if not moderator_has_permission(
        interaction, "manage_guild"
    ):
        return await deny_permission(interaction)

    init_giveaway_entries()

    ends_at = int(time.time()) + minutes * 60

    await interaction.response.defer(ephemeral=True)

    embed = create_embed(
        "EXTERNAL | GIVEAWAY",
        (
            f"**Prize:** {discord.utils.escape_markdown(prize[:200])}\n"
            f"**Host:** {interaction.user.mention}\n"
            f"**Ends:** <t:{ends_at}:R>\n\n"
            "Press Enter Giveaway to participate."
        )
    )

    try:
        message = await interaction.channel.send(
            embed=embed,
            view=GiveawayEntryView(),
            allowed_mentions=discord.AllowedMentions.none()
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Could not post the giveaway.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        db.execute(
            """
            INSERT INTO giveaways
            (message_id, guild_id, channel_id,
             prize, ends_at, status)
            VALUES (?, ?, ?, ?, ?, 'active')
            """,
            (
                message.id,
                interaction.guild_id,
                interaction.channel_id,
                prize[:200],
                ends_at
            )
        )
        db.commit()

    await interaction.followup.send(
        f"Giveaway started. Message ID: `{message.id}`",
        ephemeral=True
    )


@giveaway_group.command(
    name="list",
    description="List active giveaways."
)
@medium_permission_only()
async def giveaway_list_command(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT message_id, prize, ends_at
            FROM giveaways
            WHERE guild_id = ?
              AND status = 'active'
            ORDER BY ends_at
            LIMIT 20
            """,
            (interaction.guild_id,)
        ).fetchall()

    lines = [
        f"`{row['message_id']}` — "
        f"{discord.utils.escape_markdown(row['prize'])} "
        f"— <t:{row['ends_at']}:R>"
        for row in rows
    ]

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | ACTIVE GIVEAWAYS",
            "\n".join(lines)
            if lines else "No active giveaways."
        ),
        ephemeral=True
    )


async def finish_giveaway(message_id, reroll=False):
    init_giveaway_entries()

    with db_connect() as db:
        giveaway = db.execute(
            """
            SELECT * FROM giveaways
            WHERE message_id = ?
            """,
            (message_id,)
        ).fetchone()

        if giveaway is None:
            return False, "Giveaway not found."

        if not reroll and giveaway["status"] != "active":
            return False, "Giveaway already ended."

        entries = db.execute(
            """
            SELECT user_id FROM giveaway_entries
            WHERE message_id = ?
            """,
            (message_id,)
        ).fetchall()

    guild = bot.get_guild(giveaway["guild_id"])

    if guild is None:
        return False, "Server unavailable."

    eligible = []

    for entry in entries:
        member = guild.get_member(entry["user_id"])

        if member is None:
            try:
                member = await guild.fetch_member(
                    entry["user_id"]
                )
            except (
                discord.NotFound,
                discord.Forbidden,
                discord.HTTPException
            ):
                continue

        if not member.bot:
            eligible.append(member)

    winner = (
        secrets.choice(eligible)
        if eligible else None
    )

    with db_connect() as db:
        db.execute(
            """
            UPDATE giveaways
            SET status = 'ended',
                winner_id = ?
            WHERE message_id = ?
            """,
            (
                winner.id if winner else None,
                message_id
            )
        )
        db.commit()

    channel = guild.get_channel(
        giveaway["channel_id"]
    )

    if channel:
        try:
            original = await channel.fetch_message(
                message_id
            )
            if not reroll:
                await original.edit(view=None)

            announcement = (
                f"Giveaway {'rerolled' if reroll else 'ended'}.\n"
                f"Prize: {giveaway['prize']}\n"
                f"Winner: {winner.mention}"
                if winner else
                f"Giveaway ended: {giveaway['prize']}\n"
                "No eligible participants."
            )

            await channel.send(
                announcement,
                allowed_mentions=discord.AllowedMentions(
                    users=True,
                    roles=False,
                    everyone=False
                )
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    return True, (
        f"Winner: {winner}"
        if winner else
        "No eligible participants."
    )


@giveaway_group.command(
    name="roll",
    description="End a giveaway and choose a winner."
)
@medium_permission_only()
async def giveaway_roll_command(
    interaction: discord.Interaction,
    message_id: str
):
    if not moderator_has_permission(
        interaction, "manage_guild"
    ):
        return await deny_permission(interaction)

    try:
        giveaway_id = int(message_id)
    except ValueError:
        await interaction.response.send_message(
            "Invalid message ID.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        record = db.execute(
            """
            SELECT 1 FROM giveaways
            WHERE message_id = ? AND guild_id = ?
            """,
            (giveaway_id, interaction.guild_id)
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "Giveaway not found in this server.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    success, result = await finish_giveaway(
        giveaway_id
    )

    await interaction.followup.send(
        result,
        ephemeral=True
    )


@giveaway_group.command(
    name="reroll",
    description="Choose a new winner for an ended giveaway."
)
@medium_permission_only()
async def giveaway_reroll_command(
    interaction: discord.Interaction,
    message_id: str
):
    if not moderator_has_permission(
        interaction, "manage_guild"
    ):
        return await deny_permission(interaction)

    try:
        giveaway_id = int(message_id)
    except ValueError:
        await interaction.response.send_message(
            "Invalid message ID.",
            ephemeral=True
        )
        return

    with db_connect() as db:
        record = db.execute(
            """
            SELECT 1 FROM giveaways
            WHERE message_id = ?
              AND guild_id = ?
              AND status = 'ended'
            """,
            (giveaway_id, interaction.guild_id)
        ).fetchone()

    if record is None:
        await interaction.response.send_message(
            "Ended giveaway not found.",
            ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    success, result = await finish_giveaway(
        giveaway_id,
        reroll=True
    )

    await interaction.followup.send(
        result,
        ephemeral=True
    )


bot.tree.add_command(giveaway_group)


# ============================================================
# PREMIUM SCHEDULED ANNOUNCEMENTS
# ============================================================

event_group = app_commands.Group(
    name="auto-event",
    description="Manage scheduled announcements."
)


@event_group.command(
    name="add",
    description="Schedule a server announcement."
)
@premium_admin_only()
async def auto_event_add(
    interaction: discord.Interaction,
    name: str,
    message: str,
    minutes: app_commands.Range[int, 1, 10080],
    channel: discord.TextChannel
):
    if not moderator_has_permission(
        interaction, "manage_guild"
    ):
        return await deny_permission(interaction)

    scheduled_at = int(time.time()) + minutes * 60

    with db_connect() as db:
        cursor = db.execute(
            """
            INSERT INTO scheduled_events
            (guild_id, channel_id, event_name,
             event_message, scheduled_at,
             created_by, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                interaction.guild_id,
                channel.id,
                name[:100],
                message[:1800],
                scheduled_at,
                interaction.user.id
            )
        )
        event_id = cursor.lastrowid
        db.commit()

    await interaction.response.send_message(
        f"Scheduled event created.\n"
        f"Event ID: `{event_id}`\n"
        f"Channel: {channel.mention}\n"
        f"Time: <t:{scheduled_at}:F>",
        ephemeral=True
    )


@event_group.command(
    name="list",
    description="List scheduled announcements."
)
@premium_admin_only()
async def auto_event_list(
    interaction: discord.Interaction
):
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT event_id, event_name, scheduled_at
            FROM scheduled_events
            WHERE guild_id = ?
              AND status = 'pending'
            ORDER BY scheduled_at
            LIMIT 20
            """,
            (interaction.guild_id,)
        ).fetchall()

    lines = [
        f"`{row['event_id']}` - "
        f"{discord.utils.escape_markdown(row['event_name'])} "
        f"- <t:{row['scheduled_at']}:R>"
        for row in rows
    ]

    await interaction.response.send_message(
        embed=create_embed(
            "EXTERNAL | SCHEDULED EVENTS",
            "\n".join(lines)
            if lines else "No scheduled events."
        ),
        ephemeral=True
    )


@event_group.command(
    name="remove",
    description="Cancel a scheduled announcement."
)
@premium_admin_only()
async def auto_event_remove(
    interaction: discord.Interaction,
    event_id: int
):
    with db_connect() as db:
        cursor = db.execute(
            """
            UPDATE scheduled_events
            SET status = 'cancelled'
            WHERE event_id = ?
              AND guild_id = ?
              AND status = 'pending'
            """,
            (event_id, interaction.guild_id)
        )
        db.commit()

    await interaction.response.send_message(
        (
            "Scheduled event cancelled."
            if cursor.rowcount
            else "Pending event not found."
        ),
        ephemeral=True
    )


bot.tree.add_command(event_group)


# ============================================================
# PREMIUM BOT NICKNAME
# ============================================================

@bot.tree.command(
    name="setallnamebot",
    description="Change this bot's nickname in the server."
)
@app_commands.guild_only()
@premium_admin_only()
async def setallnamebot_command(
    interaction: discord.Interaction,
    nickname: str
):
    if not moderator_has_permission(
        interaction, "manage_nicknames"
    ):
        return await deny_permission(interaction)

    if len(nickname) > 32:
        await interaction.response.send_message(
            "Nickname must be 32 characters or fewer.",
            ephemeral=True
        )
        return

    try:
        await interaction.guild.me.edit(
            nick=nickname,
            reason=f"Nickname changed by {interaction.user}"
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.response.send_message(
            "Could not change bot nickname.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        "Bot nickname updated.",
        ephemeral=True
    )


# ============================================================
# PREMIUM SERVER TEMPLATE
# ============================================================

@bot.tree.command(
    name="create-server-template",
    description="Create a Discord server template."
)
@app_commands.guild_only()
@premium_admin_only()
async def create_server_template_command(
    interaction: discord.Interaction,
    name: str,
    description: str = "Server template"
):
    if not moderator_has_permission(
        interaction, "manage_guild"
    ):
        return await deny_permission(interaction)

    await interaction.response.defer(ephemeral=True)

    try:
        template = await interaction.guild.create_template(
            name=name[:100],
            description=description[:120]
        )
    except (discord.Forbidden, discord.HTTPException):
        await interaction.followup.send(
            "Unable to create server template. "
            "Check server permissions and Discord limits.",
            ephemeral=True
        )
        return

    await interaction.followup.send(
        f"Server template created:\n{template.url}",
        ephemeral=True
    )


# ============================================================
# END OF PART 7
# ============================================================


# ============================================================
# EXTERNAL | FULL SECURITY v2.0
# PART 8 - FINAL EVENT HANDLERS AND STARTUP
# ============================================================

from discord.ext import tasks


# ============================================================
# FINAL RUNTIME STATE
# ============================================================

external_runtime_started = False
external_last_log_channel_check = set()
external_spam_tracking = defaultdict(deque)


# ============================================================
# ALL LOGS CHANNEL
# ============================================================

async def ensure_all_logs_channel(guild):
    settings = get_settings(guild.id)

    existing_id = settings.get("log_channel_id")

    if existing_id:
        channel = guild.get_channel(existing_id)

        if isinstance(channel, discord.TextChannel):
            return channel

    channel = discord.utils.get(
        guild.text_channels,
        name="all-logs"
    )

    if channel is None:
        me = guild.me

        if (
            me is None
            or not me.guild_permissions.manage_channels
        ):
            return None

        try:
            channel = await guild.create_text_channel(
                "all-logs",
                overwrites={
                    guild.default_role:
                        discord.PermissionOverwrite(
                            view_channel=False
                        ),
                    me:
                        discord.PermissionOverwrite(
                            view_channel=True,
                            send_messages=True,
                            embed_links=True,
                            read_message_history=True
                        )
                },
                reason="EXTERNAL automatic audit log setup"
            )
        except (discord.Forbidden, discord.HTTPException):
            return None

    set_setting(
        guild.id,
        "log_channel_id",
        channel.id
    )

    return channel


@bot.tree.command(
    name="all-logs-channel",
    description="Set the server's central audit log channel."
)
@app_commands.guild_only()
@high_permission_only()
async def all_logs_channel_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel
):
    if not interaction.user.guild_permissions.manage_guild:
        return await deny_permission(interaction)

    me = interaction.guild.me

    if me is None:
        await interaction.response.send_message(
            "Bot member information unavailable.",
            ephemeral=True
        )
        return

    permissions = channel.permissions_for(me)

    if not (
        permissions.view_channel
        and permissions.send_messages
        and permissions.embed_links
    ):
        await interaction.response.send_message(
            "The bot needs View Channel, Send Messages "
            "and Embed Links permissions there.",
            ephemeral=True
        )
        return

    set_setting(
        interaction.guild_id,
        "log_channel_id",
        channel.id
    )

    await interaction.response.send_message(
        f"All logs channel set to {channel.mention}.",
        ephemeral=True
    )


# ============================================================
# HELP COMMAND
# ============================================================

@bot.tree.command(
    name="help",
    description="Display EXTERNAL bot commands."
)
@app_commands.guild_only()
async def external_help_command(
    interaction: discord.Interaction
):
    embed = create_embed(
        "EXTERNAL | FULL SECURITY v2.0",
        (
            "**UTILITY**\n"
            "`/avatar` `/banner` `/userinfo` "
            "`/serverinfo` `/afk`\n\n"

            "**MODERATION**\n"
            "`/authorize` `/purge` `/purgeuser` "
            "`/purgebot` `/timeout` `/unmute` "
            "`/jail` `/unjail` `/jlist` "
            "`/lock` `/unlock` `/kick` `/ban` `/unban`\n\n"

            "**SECURITY**\n"
            "`/antinuke` `/automod` `/antilink` "
            "`/antimention` `/antinsfw` "
            "`/mention-limit` `/advanced-logs` "
            "`/all-logs-channel`\n\n"

            "**UTILITIES**\n"
            "`/clearsnipe` `/editsnipe` "
            "`/stick` `/giveaway`\n\n"

            "**PREMIUM**\n"
            "`/prem` `/bypass` `/bypass-link` "
            "`/leak` `/backup` `/backup-manage` "
            "`/backupload` `/auto-event` "
            "`/server-ban-list` `/create-invite` "
            "`/steal-emoji` `/steal-sticker` "
            "`/setallnamebot` "
            "`/create-server-template`\n\n"

            "**BOT OWNER**\n"
            "`/server-setting`\n\n"

            "Some commands require authorization, "
            "Discord permissions or server premium."
        )
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True
    )


# ============================================================
# ANTI-SPAM PROCESSOR
# ============================================================

async def process_external_antispam(message):
    if message.guild is None or message.author.bot:
        return False

    guild = message.guild
    settings = get_settings(guild.id)

    if not settings.get("antispam"):
        return False

    if is_high_authorized(guild, message.author.id):
        return False

    if is_moderator_authorized(
        guild.id,
        message.author.id
    ):
        return False

    limit = max(
        2,
        int(settings.get("spam_limit", 5))
    )

    window = max(
        2,
        int(settings.get("spam_window", 5))
    )

    key = (guild.id, message.author.id)
    now = time.monotonic()

    entries = external_spam_tracking[key]

    while entries and now - entries[0] > window:
        entries.popleft()

    entries.append(now)

    if len(entries) <= limit:
        return False

    entries.clear()

    action = settings.get(
        "spam_action",
        "timeout"
    )

    member = message.author
    me = guild.me

    if me is None:
        return False

    if (
        member.id == guild.owner_id
        or member.top_role >= me.top_role
    ):
        return False

    result = "Detected excessive messages"

    try:
        if (
            action == "timeout"
            and me.guild_permissions.moderate_members
            and not member.guild_permissions.administrator
        ):
            await member.timeout(
                timedelta(minutes=5),
                reason="EXTERNAL Anti-Spam"
            )
            result = "Timed out for 5 minutes"

        elif (
            action == "kick"
            and me.guild_permissions.kick_members
        ):
            await member.kick(
                reason="EXTERNAL Anti-Spam"
            )
            result = "Kicked"

        elif (
            action == "ban"
            and me.guild_permissions.ban_members
        ):
            await member.ban(
                reason="EXTERNAL Anti-Spam"
            )
            result = "Banned"

    except (discord.Forbidden, discord.HTTPException):
        result = "Detection only; punishment failed"

    await advanced_send_log(
        guild,
        "moderation_logs",
        "Anti-Spam Detection",
        (
            f"Member: {member} (`{member.id}`)\n"
            f"Channel: {message.channel.mention}\n"
            f"Threshold: {limit} messages / {window}s\n"
            f"Action: {result}"
        ),
        discord.Color.orange()
    )

    return True


# ============================================================
# MESSAGE EVENT
# ============================================================

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    if message.guild is None:
        return

    try:
        blocked = await process_security_filters(
            message
        )

        if blocked:
            return

        await process_external_antispam(
            message
        )

        await process_afk_message(
            message
        )

        await process_sticky_message(
            message
        )

    except Exception:
        logging.exception(
            "EXTERNAL message handler error"
        )

    await bot.process_commands(message)


# ============================================================
# DELETED MESSAGE EVENT
# ============================================================

@bot.event
async def on_message_delete(message):
    if message.guild is None:
        return

    cache_deleted_message(message)

    if message.author.bot:
        return

    await advanced_send_log(
        message.guild,
        "message_logs",
        "Message Deleted",
        (
            f"Author: {message.author} "
            f"(`{message.author.id}`)\n"
            f"Channel: {message.channel.mention}\n"
            f"Message ID: `{message.id}`\n"
            "Content is not included in audit logs."
        )
    )


# ============================================================
# EDITED MESSAGE EVENT
# ============================================================

@bot.event
async def on_message_edit(before, after):
    if before.guild is None:
        return

    cache_edited_message(before, after)

    if before.author.bot:
        return

    if before.content == after.content:
        return

    await advanced_send_log(
        before.guild,
        "message_logs",
        "Message Edited",
        (
            f"Author: {before.author} "
            f"(`{before.author.id}`)\n"
            f"Channel: {before.channel.mention}\n"
            f"Message ID: `{before.id}`\n"
            f"[Jump to message]({after.jump_url})\n"
            "Message content is not included in audit logs."
        )
    )


# ============================================================
# MEMBER JOIN AND LEAVE
# ============================================================

@bot.event
async def on_member_join(member):
    guild = member.guild

    await advanced_send_log(
        guild,
        "member_logs",
        "Member Joined",
        (
            f"Member: {member} (`{member.id}`)\n"
            f"Account Created: "
            f"<t:{int(member.created_at.timestamp())}:F>\n"
            f"Bot Account: {'Yes' if member.bot else 'No'}"
        )
    )

    if not member.bot:
        return

    settings = get_settings(guild.id)

    if not settings.get("antibot"):
        return

    if is_trusted_bot(guild.id, member.id):
        return

    await advanced_send_log(
        guild,
        "bot_logs",
        "Untrusted Bot Joined",
        (
            f"Bot: {member} (`{member.id}`)\n"
            "Status: Not on trusted bot list.\n"
            "Review this bot and its permissions."
        ),
        discord.Color.orange()
    )


@bot.event
async def on_member_remove(member):
    await advanced_send_log(
        member.guild,
        "member_logs",
        "Member Left",
        (
            f"Member: {member}\n"
            f"User ID: `{member.id}`"
        )
    )


# ============================================================
# GUILD JOIN
# ============================================================

@bot.event
async def on_guild_join(guild):
    await ensure_all_logs_channel(guild)

    logging.info(
        "Joined server: %s (%s)",
        guild.name,
        guild.id
    )


# ============================================================
# AUTOMATIC GIVEAWAY PROCESSOR
# ============================================================

@tasks.loop(seconds=30)
async def external_giveaway_worker():
    init_giveaway_entries()

    with db_connect() as db:
        rows = db.execute(
            """
            SELECT message_id
            FROM giveaways
            WHERE status = 'active'
              AND ends_at <= ?
            LIMIT 10
            """,
            (int(time.time()),)
        ).fetchall()

    for row in rows:
        try:
            await finish_giveaway(
                row["message_id"]
            )
        except Exception:
            logging.exception(
                "Giveaway completion failed: %s",
                row["message_id"]
            )


@external_giveaway_worker.before_loop
async def before_external_giveaway_worker():
    await bot.wait_until_ready()


# ============================================================
# SCHEDULED EVENT PROCESSOR
# ============================================================

@tasks.loop(seconds=30)
async def external_event_worker():
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT *
            FROM scheduled_events
            WHERE status = 'pending'
              AND scheduled_at <= ?
            ORDER BY scheduled_at
            LIMIT 10
            """,
            (int(time.time()),)
        ).fetchall()

    for row in rows:
        guild = bot.get_guild(row["guild_id"])

        if guild is None:
            continue

        channel = guild.get_channel(
            row["channel_id"]
        )

        if not isinstance(
            channel,
            discord.TextChannel
        ):
            continue

        try:
            await channel.send(
                embed=create_embed(
                    row["event_name"],
                    row["event_message"]
                ),
                allowed_mentions=discord.AllowedMentions.none()
            )

        except (discord.Forbidden, discord.HTTPException):
            logging.exception(
                "Scheduled event delivery failed"
            )
            continue

        with db_connect() as db:
            db.execute(
                """
                UPDATE scheduled_events
                SET status = 'sent'
                WHERE event_id = ?
                  AND status = 'pending'
                """,
                (row["event_id"],)
            )
            db.commit()


@external_event_worker.before_loop
async def before_external_event_worker():
    await bot.wait_until_ready()


# ============================================================
# PERIODIC SNIPE CACHE CLEANUP
# ============================================================

@tasks.loop(minutes=5)
async def external_cache_worker():
    now = int(time.time())

    for cache in (
        snipe_cache,
        edit_snipe_cache
    ):
        expired = [
            key for key, value in cache.items()
            if now - value.get("timestamp", now)
            > SNIPE_RETENTION_SECONDS
        ]

        for key in expired:
            cache.pop(key, None)


@external_cache_worker.before_loop
async def before_external_cache_worker():
    await bot.wait_until_ready()


# ============================================================
# READY EVENT
# ============================================================

@bot.event
async def on_ready():
    global external_runtime_started

    logging.info(
        "EXTERNAL online as %s (%s)",
        bot.user,
        bot.user.id
    )

    if external_runtime_started:
        return

    external_runtime_started = True

    init_giveaway_entries()
    init_channel_lock_db()

    # Persistent giveaway buttons
    bot.add_view(GiveawayEntryView())

    if not external_giveaway_worker.is_running():
        external_giveaway_worker.start()

    if not external_event_worker.is_running():
        external_event_worker.start()

    if not external_cache_worker.is_running():
        external_cache_worker.start()

    for guild in bot.guilds:
        try:
            await ensure_all_logs_channel(guild)
        except Exception:
            logging.exception(
                "Log channel setup failed for %s",
                guild.id
            )

    logging.info(
        "EXTERNAL background services started."
    )


# ============================================================
# SLASH COMMAND ERROR HANDLER
# ============================================================

@bot.tree.error
async def external_slash_error(
    interaction: discord.Interaction,
    error: app_commands.AppCommandError
):
    original = getattr(error, "original", error)

    if isinstance(
        error,
        app_commands.CheckFailure
    ):
        message = (
            str(error)
            if str(error)
            else "You do not have permission to use this command."
        )

    elif isinstance(
        original,
        discord.Forbidden
    ):
        message = (
            "The bot lacks the required Discord permissions."
        )

    elif isinstance(
        original,
        discord.HTTPException
    ):
        message = (
            "Discord could not complete this action."
        )

    else:
        logging.error(
            "Slash command error: %r",
            error,
            exc_info=(
                type(error),
                error,
                error.__traceback__
            )
        )

        message = (
            "An internal command error occurred. "
            "Check the bot logs."
        )

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
# FINAL STARTUP
# THIS MUST REMAIN AT THE VERY END OF THE FILE
# ============================================================

if __name__ == "__main__":

    if not TOKEN:
        raise RuntimeError(
            "DISCORD_TOKEN environment variable is missing."
        )

    logging.info(
        "Starting EXTERNAL FULL SECURITY v%s",
        BOT_VERSION
    )

    bot.run(TOKEN)


# ============================================================
# END OF PART 8 - FINAL
# ============================================================
