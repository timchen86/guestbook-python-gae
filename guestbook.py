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

import logging
logger = logging.getLogger(__name__)

from google.appengine.api import users
#from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.ext.webapp import template

FACEBOOK_APP_ID = "00000000000000"
FACEBOOK_APP_SECRET = "0000000000000"


class User(db.Model):
  #content = db.StringProperty(multiline=True)
  fbid = db.StringProperty(required=False)
  fbname = db.StringProperty(required=False)
  fbtoken = db.StringProperty(required=False)
  fbphoto_url = db.StringProperty()

class Guestbook(db.Model):
  user  = db.ReferenceProperty(User, collection_name='guestbook')
  message = db.StringProperty(multiline=True)

  date = db.DateTimeProperty(auto_now_add=True)
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
            user = User(key_name=str(profile["id"]), fbid=str(profile["id"]),
                        fbname=profile["name"], fbtoken=access_token,
                        fbphoto_url=profile["link"])
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


class MainPage(BaseHandler):
  def get(self):
    guestbook_q = Guestbook.all().order('-date')
    guestbooks = guestbook_q.fetch(10)


    current_user=self.current_user

    if current_user != None:
      #url = users.create_logout_url(self.request.uri)
      url = "/logout"
      url_linktext = 'Logout'
      #photo_url="http://graph.facebook.com/%s/picture?type=square" % current_user.fbid
    else:
      #url = users.create_login_url(self.request.uri)
      url = "/login"
      url_linktext = 'Login'
      #photo_url="http://d22r54gnmuhwmk.cloudfront.net/app-assets/global/default_user_icon-0f83709782d4d6ab03c776297789ce69.jpg"



    template_values = {
      'guestbooks': guestbooks,
      'url': url,
      'url_linktext': url_linktext,
      #'photo_url': photo_url
      }

    path = os.path.join(os.path.dirname(__file__), 'index.html')
    self.response.out.write(template.render(path, template_values))
    

class GuestbookHandler(BaseHandler):
  def post(self):

    logging.info(self.request)
    gb = Guestbook()
    
    if self.current_user:
      gb.user = self.current_user
      gb.message = self.request.get('content')
      gb.put()

    
    time.sleep(0.1)
    self.redirect('/')

application = webapp2.WSGIApplication(
                                     [('/', MainPage),
                                      ('/logout', LogoutHandler),
                                      ('/login', LoginHandler),
                                      ('/sign', GuestbookHandler)],
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


def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
