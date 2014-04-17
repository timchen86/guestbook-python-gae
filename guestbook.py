import cgi
import json
import hashlib
import Cookie
import email
import time
import base64
import hmac
import os
import urllib
import webapp2
import jinja2

import logging
logger = logging.getLogger(__name__)

from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db

from globals import FACEBOOK_APP_ID
from globals import FACEBOOK_APP_SECRET 


class User(db.Model):
  id = db.StringProperty(required=True)
  name = db.StringProperty(required=True)
  access_token = db.StringProperty(required=True)
  profile_url = db.StringProperty(required=True)

class Guestbook(db.Model):
  user  = db.ReferenceProperty(User, collection_name='guestbook')
  message = db.StringProperty(multiline=True)
  date = db.DateTimeProperty(auto_now_add=True)

class BaseHandler(webapp2.RequestHandler):
    @property
    def current_user(self):
        """Returns the logged in Facebook user, or None if unconnected."""
        if not hasattr(self, "_current_user"):
            self._current_user = None
            user_id = parse_cookie(self.request.cookies.get("fb_user"))
            if user_id:
                self._current_user = User.get_by_key_name(user_id)
        return self._current_user


class LoginHandler(BaseHandler):
    def get(self):
        verification_code = self.request.get("code")
        args = dict(client_id=FACEBOOK_APP_ID,
                    redirect_uri=self.request.path_url)
        if self.request.get("code"):
            args["client_secret"] = FACEBOOK_APP_SECRET
            args["code"] = self.request.get("code")
            response = cgi.parse_qs(urllib.urlopen(
                "https://graph.facebook.com/oauth/access_token?" +
                urllib.urlencode(args)).read())
            access_token = response["access_token"][-1]

            # Download the user profile and cache a local instance of the
            # basic profile info
            profile = json.load(urllib.urlopen(
                "https://graph.facebook.com/me?" +
                urllib.urlencode(dict(access_token=access_token))))
            user = User(key_name=str(profile["id"]), id=str(profile["id"]),
                        name=profile["name"], access_token=access_token,
                        profile_url=profile["link"])
            user.put()
            set_cookie(self.response, "fb_user", str(profile["id"]),
                       expires=time.time() + 30 * 86400)
            self.redirect("/")
        else:
            self.redirect(
                "https://graph.facebook.com/oauth/authorize?" +
                urllib.urlencode(args))


class LogoutHandler(BaseHandler):
    def get(self):
        set_cookie(self.response, "fb_user", "", expires=time.time() - 86400)
        self.redirect("/")



class MainPage(BaseHandler):
  def get(self):
    guestbook_q = Guestbook.all().order('-date')
    guestbooks = guestbook_q.fetch(10)

    current_user=self.current_user

    if current_user != None:
      user_name = current_user.name
      url = "/logout"
      url_linktext = 'Logout'
    else:
      user_name = "Anonymous"
      url = "/login"
      url_linktext = 'Login'

    template = jinja_environment.get_template('index.html')

    self.response.out.write(template.render(dict(
        guestbooks=guestbooks,
        user_name=user_name,
        url=url,
        url_linktext=url_linktext
    )))


class SignHandler(BaseHandler):
  def post(self):
    guestbook = Guestbook()

    guestbook.user = self.current_user
    guestbook.message = self.request.get('message')
    if guestbook.message != "":
        guestbook.put()

    time.sleep(0.1)
    self.redirect('/')

application = webapp2.WSGIApplication(
                                     [('/', MainPage),
                                      ('/logout', LogoutHandler),
                                      ('/login', LoginHandler),
                                      ('/sign', SignHandler)],
                                     debug=True)

def cookie_signature(*parts):
    """Generates a cookie signature.

    We use the Facebook app secret since it is different for every app (so
    people using this example don't accidentally all use the same secret).
    """
    hash = hmac.new(FACEBOOK_APP_SECRET, digestmod=hashlib.sha1)
    for part in parts:
        hash.update(part)
    return hash.hexdigest()

def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value:
        return None
    parts = value.split("|")
    if len(parts) != 3:
        return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None

def set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain:
        cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    #response.headers._headers.append(("Set-Cookie", cookie.output()[12:]))
    response.headers.add_header("Set-Cookie", cookie.output()[12:])


jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__))
)


def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
