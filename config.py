import logging
import os

# This is a minimal configuration to get you started with the Text mode.
# If you want to connect Errbot to chat services, checkout
# the options in the more complete config-template.py from here:
# https://raw.githubusercontent.com/errbotio/errbot/master/errbot/config-template.py

BACKEND = 'Slack'  # Errbot will start in text mode (console only mode) and will answer commands from there.

BOT_DATA_DIR = r'data'
BOT_EXTRA_PLUGIN_DIR = r'plugins'

BOT_LOG_FILE = r'errbot.log'
BOT_LOG_LEVEL = logging.INFO

BOT_ADMINS = ('@your_slack_users', )  # !! Don't leave that to "@CHANGE_ME" if you connect your errbot to a chat system !!
BOT_IDENTITY = { 
    'token': os.getenv('SLACK_TOKEN'),
}
BOT_ALT_PREFIXES = ('@your_slack_bot_name',)

BOT_ASYNC = True
BOT_ASYNC_POOLSIZE = 40
