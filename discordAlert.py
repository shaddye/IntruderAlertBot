import discord
import scapy
from discord.ext import commands
from scapy.all import sniff, TCP
from collections import defaultdict
from datetime import datetime, timedelta

# Your Discord Bot Token
bot_token = 'XXXPLACEHOLDER'

# Discord Bot Prefix
bot = commands.Bot(command_prefix='!')

# User ID for Receiving Alerts
user_id = XXXPLACEHOLDERXXX

# Global dictionary to track login attempts
login_attempts = defaultdict(lambda: {'count': 0, 'first_attempt_time': None})

# Thresholds for detection
MAX_ATTEMPTS = 2
TIME_WINDOW = timedelta(minutes=5)  # Time window for counting attempts

async def send_dm_alert(message):
    user = await bot.fetch_user(user_id)
    await user.send(message)

def packet_callback(packet):
    if packet.haslayer(TCP) and packet[TCP].dport in [22, 80, 443]:  # Add other ports as needed
        src_ip = packet[IP].src
        current_time = datetime.now()

        if login_attempts[src_ip]['count'] == 0:
            # First attempt from this IP
            login_attempts[src_ip]['first_attempt_time'] = current_time
            login_attempts[src_ip]['count'] = 1
        else:
            # Subsequent attempts
            time_diff = current_time - login_attempts[src_ip]['first_attempt_time']
            if time_diff <= TIME_WINDOW:
                login_attempts[src_ip]['count'] += 1
                if login_attempts[src_ip]['count'] >= MAX_ATTEMPTS:
                    # Send alert
                    alert_message = f"Multiple login attempts detected from IP: {src_ip}"
                    bot.loop.create_task(send_dm_alert(alert_message))
                    # Reset count after alerting
                    login_attempts[src_ip] = {'count': 0, 'first_attempt_time': None}
            else:
                # Reset if outside time window
                login_attempts[src_ip] = {'count': 1, 'first_attempt_time': current_time}

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')
    sniff(prn=packet_callback, store=0)

bot.run(bot_token)
