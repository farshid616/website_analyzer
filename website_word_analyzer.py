#!/usr/bin/env python3
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from aiomysql import create_pool
import bcrypt
import os.path
import re
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.locks
import tornado.options
import tornado.web
import urllib.request
from bs4 import BeautifulSoup
from bs4.element import Comment
import operator
from Crypto import Random
from Crypto.PublicKey import RSA
import base64
from wit import Wit
from operator import itemgetter
from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("db_host", default="127.0.0.1", help="website database host")
define("db_port", default=3306, help="website database port")
define("db_database", default="octopus", help="website database name")
define("db_user", default="octopus", help="website database user")
define("db_password", default="mysql", help="website database password")


class NoResultError(Exception):
    pass


async def maybe_create_tables(db):
    try:
        async with db.cursor() as cur:
            await cur.execute("SELECT COUNT(*) FROM words LIMIT 1")
            await cur.fetchone()
    except:
        with open('schema.sql') as f:
            schema = f.read()
        async with db.cursor() as cur:
            await cur.execute(schema)
            pass


class Application(tornado.web.Application):
    def __init__(self, db):
        self.db = db
        handlers = [
            (r"/", HomeHandler),
            (r"/admin", AdminHandler),
            (r"/auth/create", AuthCreateHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            blog_title=u"Web Analyzer",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Entry": EntryModule},
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def row_to_obj(self, row, cur):
        """Convert a SQL row to an object supporting dict and attribute access."""
        obj = tornado.util.ObjectDict()
        for val, desc in zip(row, cur.description):
            obj[desc[0]] = val
        return obj

    async def execute(self, stmt, *args):
        """Execute a SQL statement.

        Must be called with ``await self.execute(...)``
        """
        async with self.application.db.cursor() as cur:
            await cur.execute(stmt, args)
            await self.application.db.commit()

    async def query(self, stmt, *args):
        """Query for a list of results.

        Typical usage::

            results = await self.query(...)

        Or::

            for row in await self.query(...)
        """
        async with self.application.db.cursor() as cur:
            await cur.execute(stmt, args)
            return [self.row_to_obj(row, cur)
                    for row in await cur.fetchall()]

    async def queryone(self, stmt, *args):
        """Query for exactly one result.

        Raises NoResultError if there are no results, or ValueError if
        there are more than one.
        """
        results = await self.query(stmt, *args)
        if len(results) == 0:
            raise NoResultError()
        elif len(results) > 1:
            raise ValueError("Expected 1 result, got %d" % len(results))
        return results[0]

    async def prepare(self):
        user_id = self.get_secure_cookie("octopus_admin")
        if user_id:
            self.current_user = await self.query("SELECT * FROM admins WHERE id = %s",
                                                    int(user_id))
            pass

    async def any_admin_exists(self):
        return bool(await self.query("SELECT * FROM admins LIMIT 1"))

    async def word_exists(self, target_word):
        return bool(await self.query("SELECT * FROM words WHERE word = %s", target_word.decode()))


class HomeHandler(BaseHandler):
    def get(self):
        self.render("home.html", entries="")

    async def post(self):
        website = self.get_argument("url")
        try:
            html = urllib.request.urlopen(website).read()
            text = text_from_html(html)
            div = re.split(' +', text)
            div2 = []
            for i in div:
                div2.append(re.sub('([^A-Za-z])+', '', i))
            for j in div2:
                if j is '':
                    div2.remove(j)
            di = {}
            for e in div2:
                di[e] = div2.count(e)
            sorted_ = sorted(di.items(), key=operator.itemgetter(1), reverse=True)
            privatekey, publickey = generate_keys()
            for key, val in sorted_[:100]:
                encrypted_msg = encrypt_message(key, publickey)
                hashed_word = await tornado.ioloop.IOLoop.current().run_in_executor(
                    None, bcrypt.hashpw, tornado.escape.utf8(key), bcrypt.gensalt())
                if await self.word_exists(encrypted_msg):
                    await self.execute("UPDATE words SET total = %s WHERE word = %s ", int(val), encrypted_msg.decode())
                else:
                    await self.execute("INSERT INTO words (hashed_word, word, total) VALUES (%s, %s, %s)",
                                       tornado.escape.to_unicode(hashed_word), encrypted_msg, int(val))
            hashed_url = await tornado.ioloop.IOLoop.current().run_in_executor(
                None, bcrypt.hashpw, tornado.escape.utf8(website), bcrypt.gensalt())
            sentiment_result = get_sentiment(' '.join(div2[:20]))
            await self.execute(
                "INSERT INTO sentiment (hashed_url, url, sentiment)"
                "VALUES (%s, %s, %s)",
                tornado.escape.to_unicode(hashed_url), website, sentiment_result)
            self.render("home.html", entries=sorted_[:100])
        except:
            self.render("home.html", entries="")



def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True


def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)


def generate_keys():
    # RSA modulus length must be a multiple of 256 and >= 1024
    try:
        f = open('mykey.pem', 'r')
        privatekey = RSA.importKey(f.read())
        f.close()
        publickey = privatekey.publickey()
    except:
        modulus_length = 256
        privatekey = RSA.generate(modulus_length, Random.new().read)
        publickey = privatekey.publickey()
        f = open('mykey.pem', 'w')
        privatekey.exportKey('PEM')
        f.write(str(privatekey.exportKey('PEM')))
        f.close()
    return privatekey, publickey


def encrypt_message(a_message, publickey):
    encrypted_msg = publickey.encrypt(a_message.encode('utf-8'), 32)[0]
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)  # base64 encoded strings are database friendly
    return encoded_encrypted_msg


def decrypt_message(encoded_encrypted_msg, privatekey):
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg


def get_sentiment(text):
    client = Wit("B6WBHQST6FHDCLWXLJP3SQD2YNIRPAIL")
    resp = client.message(text)
    try:
        return resp['entities']['sentiment'][0]['value']
    except:
        return None


class AdminHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        privatekey, publickey = generate_keys()
        words = await self.query("SELECT * FROM words")
        for i in words:
            i['word'] = decrypt_message(i['word'], privatekey)
        words = sorted(words, key=itemgetter('total'), reverse=True)
        sentiments = await self.query("SELECT * FROM sentiment")
        self.render("admin.html", words=words, sentiments=sentiments)


class AuthCreateHandler(BaseHandler):
    def get(self):
        self.render("create_user.html")

    async def post(self):
        if await self.any_admin_exists():
            raise tornado.web.HTTPError(400, "author already created")
        hashed_password = await tornado.ioloop.IOLoop.current().run_in_executor(
            None, bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt())
        await self.execute("INSERT INTO admins (email, name, hashed_password) VALUES (%s, %s, %s)",
            self.get_argument("email"), self.get_argument("name"),
            tornado.escape.to_unicode(hashed_password))
        admin = await self.queryone("SELECT * FROM admins WHERE email = %s",
                                    self.get_argument("email"))
        self.set_secure_cookie("octopus_admin", str(admin.id))
        self.redirect(self.get_argument("next", "/"))


class AuthLoginHandler(BaseHandler):
    async def get(self):
        # If there are no authors, redirect to the account creation page.
        if not await self.any_admin_exists():
            self.redirect("/auth/create")
        else:
            self.render("login.html", error=None)

    async def post(self):
        try:
            admin = await self.queryone("SELECT * FROM admins WHERE email = %s",
                                         self.get_argument("email"))
        except NoResultError:
            self.render("login.html", error="email not found")
            return
        hashed_password = await tornado.ioloop.IOLoop.current().run_in_executor(
            None, bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(admin.hashed_password))
        hashed_password = tornado.escape.to_unicode(hashed_password)
        if hashed_password == admin.hashed_password:
            self.set_secure_cookie("octopus_admin", str(admin.id))
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("octopus_admin")
        self.redirect(self.get_argument("next", "login"))


class EntryModule(tornado.web.UIModule):
    def render(self, entry):
        return self.render_string("modules/entry.html", entry=entry)


async def main():
    tornado.options.parse_command_line()

    # Create the global connection pool.
    async with create_pool(
            host=options.db_host,
            port=options.db_port,
            user=options.db_user,
            password=options.db_password,
            db=options.db_database,
            unix_socket="/var/run/mysqld/mysqld.sock") as pool:
        async with pool.acquire() as db:
            await maybe_create_tables(db)
            app = Application(db)
            app.listen(options.port)
        shutdown_event = tornado.locks.Event()
        await shutdown_event.wait()


if __name__ == "__main__":
    tornado.ioloop.IOLoop.current().run_sync(main)
