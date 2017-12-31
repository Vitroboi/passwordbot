import discord
from discord.ext import commands
import asyncio
import json
import bcrypt

bot = commands.Bot(command_prefix=commands.when_mentioned)

def set_onjoin(server, index, duration):
    passwords = get_passwords(server)
    for item in passwords:
        item['onjoin'] = 'no'
    passwords[index]['onjoin'] = duration
    save_password(passwords, server)

def get_passwords(server):
    with open('passwords.json', 'r') as f:
        data = json.load(f)
    if data.get(server.id):
        return data[server.id]
    else:
        data[server.id] = []
        with open('passwords.json', 'w') as f:
            json.dump(data, f)
        return data[server.id]

def save_password(password, server):
    with open('passwords.json', 'r') as f:
        data = json.load(f)
    data[server.id] = password
    with open('passwords.json', 'w') as f:
        json.dump(data, f)

def delete_password(member, index):
    passwords = get_passwords(member.server)
    passwords.pop(index)
    save_password(passwords, member.server)

def print_time(seconds):
    message = ''
    if seconds // 86400:
        message += str(seconds // 86400) + ' days, '
    if seconds // 3600 % 24:
        message += str(seconds // 3600 % 24) + ' hours, '
    if seconds // 60 % 60:
        message += str(seconds // 60 % 60) + ' minutes, '
    if seconds % 60:
        message += str(seconds % 60) + ' seconds, '
    return message[:-2] + '.'

def parse_range(selection, max_index):
    tokens = selection.split()
    values = set()
    tokens = [x.strip() for x in selection.split(',')]
    valid = lambda token: token.isdigit() and 1 <= int(token) and int(token) <= max_index
    for i in tokens:
        if valid(i):
            values.add(int(i))
        else:
            token = [x.strip() for x in i.split('-')]
            if len(token) == 2 and valid(token[0]) and valid(token[1]):
                for j in range(int(token[0]), int(token[1])+1):
                    values.add(j)
            else:
                return None
    return values

async def tempban(member, duration):
    if duration == 0:
        await bot.kick(member)
    elif duration >= 604800:
        await bot.ban(member, 0)
    else:
        await bot.ban(member, 0)
        await asyncio.sleep(duration)
        await bot.unban(member.server, member)

async def user_input(member, prompt):
    await bot.send_message(member, prompt)
    dm_channel = discord.utils.get(bot.private_channels, recipients=[member])
    response = await bot.wait_for_message(author=member, channel=dm_channel)
    return response

async def repeated_user_input(member, prompt, invalid_prompt, check):
    first_time = True
    while True:
        response = await user_input(member, prompt if first_time else invalid_prompt)
        first_time = False
        if check(response.content):
            return response.content

async def authenticate(member, prompt, correct):
    for tries in range(3):
        attempt = await user_input(member, prompt if tries==0 else 'Incorrect. Please try again.')
        if bcrypt.checkpw(str.encode(attempt.content), str.encode(correct)):
            return True
    return False

async def select_role(member):
    passwords = get_passwords(member.server)
    if len(passwords) == 1:
        return passwords[0]
    else:
        prompt = 'Type the corresponding role number:\n'
        for index, item in zip(range(len(passwords)), passwords):
            role_id = passwords[index]['role']
            role_name = discord.utils.get(member.server.roles, id=role_id)
            prompt += '{}. {}\n'.format(index+1, role_name)
        invalid_prompt = 'Invalid choice. Please type a number between 1 and {}'.format(str(len(passwords)))
        choice = await repeated_user_input(member, prompt, invalid_prompt, lambda ans: ans.isdigit() and int(ans) <= len(passwords))
        return passwords[int(choice)-1]

async def configure_password(member, level):
    new1 = await user_input(member, 'Type new password.')
    new2 = await user_input(member, 'Retype new password.')
    if new1.content == new2.content:
        hashed_pw = bcrypt.hashpw(str.encode(new1.content), bcrypt.gensalt())
        server_password = hashed_pw.decode('utf-8')
        passwords = get_passwords(member.server)
        try:
            passwords[level]['password'] = server_password
        except IndexError:
            passwords.append({"password": server_password})
        save_password(passwords, member.server)
        return True
    else:
        await bot.send_message(member, 'Retyped password doesn\'t match.')
        return False

async def configure_onjoin(member, index):
    prompt = 'Should I prompt new users for this password on join? Answering yes will override the previous join password. (y/n)'
    invalid_prompt = 'Invalid response. Type y or n:'
    choice = await repeated_user_input(member, prompt, invalid_prompt, lambda ans: ans=='y' or ans=='n')
    passwords = get_passwords(member.server)
    if choice == 'y':
        prompt = 'After 3 incorrect attempts, how long should users have to wait before being allowed to rejoin? Type a length as D:HH:MM:SS. Max length 7 days. Times longer than 7 days will be treated as an indefinite ban.'
        if passwords[index].get('onjoin') and passwords[index]['onjoin'] != 'no':
            prompt += '\nCurrent setting is {}'.format(print_time(int(passwords[index]['onjoin'])))
        invalid_prompt = 'Invalid response. Type a length D:MM:HH:SS.'
        valid_time = lambda ans: all([i.isdigit() for i in ans.split(':')]) and len(ans.split(':')) <= 4
        duration = await repeated_user_input(member, prompt, invalid_prompt, valid_time)
        times = [int(i) for i in duration.split(':')]
        seconds = 0
        for j,k in zip([1,60,3600,86400], reversed(times)):
            seconds += j*k
        set_onjoin(member.server, index, duration)
    else:
        passwords[index]['onjoin'] = 'no'
        save_password(passwords, member.server)
    await bot.send_message(member, 'Configuration complete!')

async def allow_access(member, role_id):
    role = discord.utils.get(member.server.roles, id=role_id)
    try:
        await bot.add_roles(member, *[role])
    except discord.errors.Forbidden:
        await bot.send_message(member, 'I don\'t have the permissions to do that right now. I\'ll let you in once the server admin fixes this.')
        prompt = 'Please make sure my bot role is above {}. Type anything to continue.'.format(role.name)
        await repeated_user_input(member.server.owner, prompt, prompt, lambda ans: member.server.me.top_role > role)
        await bot.add_roles(member, *[role])

async def new_authentication(member):
    roles = member.server.roles
    passwords = get_passwords(member.server)
    index = len(passwords)
    prompt = 'Do you have an existing role or should we make one from scratch? Type 1 or 2.\n1. Existing role\n2. New role'
    invalid_prompt = 'Invalid response. Type 1 or 2:'
    response = await repeated_user_input(member, prompt, invalid_prompt, lambda ans: ans == '1' or ans == '2')
    if response == '1':
        while True:
            prompt = 'Type the role name or ID.'
            invalid_prompt = 'Invalid role. Please try again.'
            valid_role = lambda ans: discord.utils.get(roles, id=ans) or discord.utils.get(roles, name=ans) is not None
            role_search = await repeated_user_input(member, prompt, invalid_prompt, valid_role)
            role = discord.utils.get(roles, id=role_search) or discord.utils.get(roles, name=role_search)
            if role.id in [i['role'] for i in passwords]:
                response = await repeated_user_input(member, 'This role is already password-protected. Override? (y/n)', 'Type y or n.', lambda ans: ans=='y' or ans=='n')
                if response == 'y':
                    override_role = next(i for i in passwords if i['role'] == role.id)
                    index = passwords.index(override_role)
                    break
            else:
                break
    else:
        role_name = await repeated_user_input(member, 'Name the new role', 'Invalid name.', lambda ans: type(ans)==str)
        role = await bot.create_role(member.server, name=role_name, permissions=discord.Permissions.none())
        await configure_overrides(member, role)
    prompt = 'Please make sure my bot role is above {}. Type anything to continue.'.format(role.name)
    if member.server.me.top_role <= role:
        await repeated_user_input(member, prompt, prompt, lambda ans: member.server.me.top_role > role)
    while True:
        success_change = await configure_password(member, index)
        if success_change:
            break
    passwords = get_passwords(member.server)
    passwords[index]['role'] = role.id
    save_password(passwords, member.server)
    await configure_onjoin(member, index)

async def configure_overrides(member, role):
    channels = list(member.server.channels)
    channels.sort(key=lambda x: x.position)
    prompt = 'Using the corresponding numbers, list the channels you want to be password-protected under this role. e.g. \'2-4, 6\'\n'
    for index, channel in zip(range(len(channels)), channels):
        prompt += '{}. {}\n'.format(index+1, channel.name)
    invalid_prompt = 'I couldn\'t parse that. Try again.'
    protected_input = await repeated_user_input(member, prompt, invalid_prompt, lambda ans: parse_range(ans, len(channels)) is not None)
    protected_indices = parse_range(protected_input, len(channels))
    for index in range(len(channels)):
        if index+1 in protected_indices:
            await bot.edit_channel_permissions(channels[index], role, discord.PermissionOverwrite(read_messages=True))
            await bot.edit_channel_permissions(channels[index], member.server.default_role, discord.PermissionOverwrite(read_messages=False))
        else:
            await bot.edit_channel_permissions(channels[index], role, discord.PermissionOverwrite())
    await bot.add_roles(member.server.me, *[role])
    await bot.send_message(member, 'Role setup complete. You can edit any specific settings yourself in the roles section.')

@bot.event
async def on_ready():
    #print('Logged in as')
    #print(bot.user.name)
    #print(bot.user.id)
    print('ready')

@bot.event
async def on_server_join(server):
    await bot.send_message(server.owner, 'Thanks for installing me! Type `@password help` in the server for a help message. First, let\'s set up a password-protected role.')
    await new_authentication(server.owner)

@bot.event
async def on_member_join(member):
    auth_level = None
    passwords = get_passwords(member.server)
    for index in passwords:
        if index['onjoin'] != 'no':
            auth_level = index
            break
    if auth_level != None:
        success = await authenticate(member, 'Enter server password to gain access.', auth_level['password'])
        if success:
            await allow_access(member, auth_level['role'])
            await bot.send_message(member, 'Authenticated')
        else:
            wait_time = int(auth_level['onjoin'])
            wait_message = 'Three incorrect attempts. Try again in '
            wait_message += print_time(wait_time)
            await bot.send_message(member, wait_message)
            await tempban(member, wait_time)

def is_admin(ctx):
    return ctx.message.author == ctx.message.server.owner

@bot.command(name='new', pass_context=True)
@commands.check(is_admin)
async def new(ctx):
    '''Sets up a new password.'''
    await new_authentication(ctx.message.author)

@bot.command(name='change', pass_context=True)
@commands.check(is_admin)
async def change(ctx):
    '''Change an existing password.'''
    member = ctx.message.author
    auth_level = await select_role(member)
    success = await authenticate(member, 'Type current password.', auth_level['password'])
    if success:
        passwords = get_passwords(member.server)
        index = passwords.index(auth_level)
        while True:
            success_change = await configure_password(member, index)
            if success_change:
                await bot.send_message(member, 'Password successfully changed.')
                break
    else:
        await bot.send_message(member, 'Three incorrect attempts. Try again later.')

@bot.command(name='onjoin', aliases=['on join'], pass_context=True)
@commands.check(is_admin)
async def onjoin(ctx):
    '''Choose which password is required when a new user joins.'''
    member = ctx.message.author
    auth_level = await select_role(member)
    success = await authenticate(member, 'Type current password.', auth_level['password'])
    if success:
        passwords = get_passwords(member.server)
        index = passwords.index(auth_level)
        await configure_onjoin(member, index)
    else:
        await bot.send_message(member, 'Three incorrect attempts. Try again later.')

@bot.command(name='permissions', pass_context=True)
@commands.check(is_admin)
async def edit_permissions(ctx):
    '''Choose the channels protected by a password.'''
    member = ctx.message.author
    auth_level = await select_role(member)
    success = await authenticate(member, 'Type current password.', auth_level['password'])
    if success:
        role = discord.utils.get(member.server.roles, id=auth_level['role'])
        await configure_overrides(member, role)
    else:
        await bot.send_message(member, 'Three incorrect attempts. Try again later.')

@bot.command(name='delete', pass_context=True)
@commands.check(is_admin)
async def delete(ctx):
    '''Deletes a password.'''
    member = ctx.message.author
    auth_level = await select_role(member)
    success = await authenticate(member, 'Type current password.', auth_level['password'])
    if success:
        passwords = get_passwords(member.server)
        index = passwords.index(auth_level)
        delete_password(member, index)
        await bot.send_message(member, 'Password successfully deleted.')
    else:
        await bot.send_message(member, 'Three incorrect attempts. Try again later.')

@bot.command(name='authenticate', aliases=['auth'], pass_context=True)
async def user_authenticate(ctx, role_search=None):
    '''Enter a password to gain access to password-protected roles.'''
    member = ctx.message.author
    role_search = discord.utils.get(member.server.roles, name=role_search) or discord.utils.get(member.server.roles, id=role_search)
    passwords = get_passwords(member.server)
    if role_search:
        role = next(i for i in passwords if i['role'] == role_search.id)
    else:
        role = await select_role(member)
    index = passwords.index(role)
    success = await authenticate(member, 'Enter password.', role['password'])
    if success:
        await allow_access(member, role['role'])
        await bot.send_message(member, 'Authenticated')
    else:
        await bot.send_message(member, 'Three incorrect attempts. Try again later.')

if __name__ == '__main__':
    bot.run('token')
