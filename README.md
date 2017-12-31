## PasswordBot - Set up password protections in your Discord server!

### [Add me to your server](https://discordapp.com/login?redirect_to=%2Foauth2%2Fauthorize%3Fclient_id%3D394983131033370625%26permissions%3D268438548%26scope%3Dbot)

Please leave feedback or report problems to me! I'm peyrin#6869 on Discord.

### Features
- **Security**: Your passwords are hashed through bcrypt and stored on a secure server. I don't ever see your passwords.
- **Automatically prompt new users for a password**: Users who enter too many incorrect guesses can be banned from entering your server for a set amount of time.
- **Multiple passwords**: You can password-protect any role in your server.

### To do
The bot is still in its early stages, but I wanted to release it as soon as possible to test across more servers. Future improvements include:
- **Migrate to the new discord.py API**: Because of the introduction of channel categories, channels currently appear out-of-order when creating a new password-protected role. The new discord.py API fixes this but I'd have to migrate everything to the new API.
- **Admin permissions**: Currently, only the server owner is able to set new passwords.
- **Prevent too many guesses**: Establish a logging system and set up a wait time between attempts to prevent users from guessing too many times.
I'm always open to new suggestions, send any ideas to peyrin#6869 on Discord!

### Requirements

PasswordBot is written in Python 3. If you want to run the bot yourself, make sure you have bcrypt (`pip install bcrypt`) and discord.py (`pip install discord`) and simply run `passwordbot.py` with your own token and the bot should be up and running. I've only tested it on Ubuntu 16.04 but it should work on other systems too.

### But you could just set up roles to do the same thing!
Yeah, I know. Every mention of password-protected servers comes with this complaint. But password-protected servers are [one of the most-requested Discord features of the past few months](https://feedback.discordapp.com/forums/326712-discord-dream-land/suggestions/31529110-password-protected-servers). Gotta give the people what they want.
