import bottle
import datetime
import functools
import html.parser
import json
import os
import re
import time

from . import model


ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(ROOT_DIR, 'db.sqlite3')
STATIC_DIR = os.path.join(ROOT_DIR, 'static')

app = bottle.Bottle()
bottle.TEMPLATE_PATH.append(os.path.join(ROOT_DIR, 'views'))


ALLOWED_TAGS = set([
    'b', 'a', 'i', 'u', 'img'
])


def db_required(function):
    """
    Make the database connection available to the function as its first
    parameter.
    """
    @functools.wraps(function)
    def decorated(*args, **kwargs):
        with model.connect(DB_PATH) as connection:
            db_logic = model.DBLogic(connection)
            db_logic.initialize_db()
            return function(db_logic, *args, **kwargs)
    return decorated


def login_required(function):
    """
    Verify the login and return a login page if failed.
    Additionally, make the username and database connection available to the
    function as its first two parameters.
    """
    @db_required
    @functools.wraps(function)
    def decorated(db_logic, *args, **kwargs):
        login_cookie = bottle.request.get_cookie('login')
        login = db_logic.validate_login(login_cookie)
        if not login:
            return bottle.template('login')
        return function(login, db_logic, *args, **kwargs)
    return decorated


@app.post('/login')
@db_required
def login(db_logic):
    ok, cookie = db_logic.login(
        bottle.request.POST.get('username'),
        bottle.request.POST.get('password'),
    )
    if ok:
        bottle.response.set_cookie('login', cookie)
    return bottle.redirect('/')


@app.get('/logout')
def logout():
    bottle.response.delete_cookie('login')
    return bottle.redirect('/')


def format_timestamp(timestamp):
    date = datetime.datetime.fromtimestamp(int(timestamp))
    return date.strftime('%d.%m.%Y %H:%M:%S')


@app.get('/list_messages')
@login_required
def list_messages(username, db_logic):
    channel = bottle.request.GET['channel']
    channel_id = db_logic.get_channel_id(channel)
    if channel_id is None:  # Channel not found
        return json.dumps([])
    last_id = int(bottle.request.GET['last_id'])
    return json.dumps([
        {
            'author': author,
            'id': message_id,
            'date': format_timestamp(timestamp),
            'text': message,
        }
        for message_id, author, timestamp, message
        in db_logic.list_messages(last_id, channel_id)
    ])


@app.get('/list_channels')
@login_required
def list_channels(username, db_logic):
    return json.dumps(db_logic.get_channels())


@app.get('/')
@login_required
def index(username, db_logic):
    name = db_logic.get_user_name(username)
    return bottle.template('index', name=name, username=username)


class MyHTMLValidator(html.parser.HTMLParser):
    def validate_link(self, link):
        if not link.startswith('http://') and not link.startswith('https://'):
            raise ValueError('Disallowed href ' + link)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = {key.lower(): val for key, val in dict(attrs).items()}

        if tag not in ALLOWED_TAGS:
            raise ValueError('Disallowed HTML tag ' + tag)

        for attr in ['src', 'href']:
            if attr in attrs:
                self.validate_link(attrs[attr])


def validate_html(html):
    try:
        validator = MyHTMLValidator()
        validator.feed(html)
        return "OK"
    except Exception as e:
        return 'Error: %s' % str(e)


def handle_message(db_logic, username, message, channel):
    if channel == '#system':
        return 'Why? We really asked you not to post here :('

    if message.startswith('/'):
        action = message.split(' ', 1)[0][1:]
        rest = message[len(action) + 2:]
        result = None
        if action == 'join':
            new_channel = rest
            if not new_channel.startswith('#'):
                result = 'Channel names should start with "#"'
            elif new_channel == '#system':
                result = 'All your base are belong to us (really, stop trying)'
            else:
                db_logic.add_channel(new_channel)
                return new_channel
        elif action == 'math':
            equation = rest
            legal_chars = set(' \t\n\r0123456789+-*/()')
            result = 'Illegal exercise'
            if set(equation).issubset(legal_chars):
                try:
                    result = '<code>%s = <strong>%s</strong></code>' % (
                        equation, eval(equation)
                    )
                except:
                    pass
        elif action == 'whois':
            username = rest
            if not re.match('^[a-zA-Z_0-9]+$', username):
                result = 'Invalid username'
            else:
                name = db_logic.get_user_name(username)
                result = '%s is <mark>%s</mark>' % (username, name)
        elif action == 'joke':
            result = 'Funny is not yet implemented'
        elif action == 'rename':
            if not ' ' in rest:
                result = 'Bad rename format'
            else:
                user, name = tuple(rest.split(' ', 1))
                user_id = db_logic.get_user_id(user)
                if user_id is None:
                    result = 'Invalid user'
                else:
                    db_logic.rename_user(user_id, name)
                    result = 'Renamed %s' % user
        elif action == '?' or action == 'help':
            result = '<code>%s</code>' % '<br />'.join([
                '/join [channel]',
                '/math [expression]',
                '/whois [username]',
                '/rename [username] [new_fullname]',
                '/joke',
                '/?',
            ])
        else:
            result = 'Unknown action'
        if result:
            db_logic.add_message('system', channel, result)
        return "OK"
    else:
        validation_status = validate_html(message)
        if validation_status == 'OK':
            db_logic.add_message(username, channel, message)
        return validation_status


@app.post('/post')
@login_required
def post(username, db_logic):
    message = bottle.request.POST['message']
    channel = bottle.request.POST['channel']
    return json.dumps(handle_message(db_logic, username, message, channel))


@app.get('/static/<filename:path>')
def static_resources(filename):
    return bottle.static_file(filename, root=STATIC_DIR)


@app.get('/reset')
def reset():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    bottle.response.delete_cookie('login')
    return bottle.redirect('/')


def run():
    app.run(host='0.0.0.0', port=8000)


if __name__ == '__main__':
    run()
