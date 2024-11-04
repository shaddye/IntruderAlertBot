This Discord bot monitors network packets using Scapy and alerts a specified user via direct message when multiple login attempts are detected from the same IP address.

Features
Monitors network packets for login attempts on specified ports (default: 22, 80, 443).
Tracks multiple login attempts from the same IP within a defined time window.
Sends alerts to a designated Discord user when thresholds are exceeded.

Requirements
Python 3.x
Discord.py library
Scapy library

Installation
Clone the repository or download the files.

Install the required libraries:
pip install discord.py scapy

Replace bot_token and user_id in the script with your bot token and the user ID for receiving alerts.

Running the Bot
Run the bot using the following command:
python discord_login_alert_bot.py
