import bcrypt
import logging

from sqlalchemy.exc import DBAPIError

from virksomheden.models.mymodel import User

from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy

from .models import User


class MyAuthenticationPolicy(AuthTktAuthenticationPolicy):
    def authenticated_userid(self, request):
        user = request.user
        if user is not None:
            return user.id

def get_user(request):
    user_id = request.unauthenticated_userid
    if user_id is not None:
        user = request.dbsession.query(User).get(user_id)
        return user

def includeme(config):
    settings = config.get_settings()
    authn_policy = MyAuthenticationPolicy(
        settings['auth.secret'],
        hashalg='sha512',
    )
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.add_request_method(get_user, 'user', reify=True)

LOG = logging.getLogger(__name__)


def hash_password(pw):
    pwhash = bcrypt.hashpw(pw.encode('utf8'), bcrypt.gensalt())
    return pwhash.decode()


def check_password(pw, hashed_pw):
    try:
        LOG.info("hashed_pw: %s", hashed_pw)
        expected_hash = hashed_pw.encode()
        LOG.info("Expected: %s", expected_hash)
        result = bcrypt.checkpw(pw.encode('utf8'), expected_hash)
        LOG.info('Password check result: %s', result)
        return result
    except ValueError as e:
        LOG.error("Password check error: %s", e)
        return False

def find_user(request, name):
    """Lookup user in database."""
    try:
        query = request.dbsession.query(User)
        user = query.filter(User.name == name).first()
        LOG.info('Found us2er: %s', name)
        return user
    except DBAPIError:
        LOG.warn('User %s not found.', name)
        return None

"""
def get_user(request, name):
    ""Get password for user.""
    user = find_user(request, name)
    if user:
        return user.password

    return None
"""


def groupfinder(userid, request):
    LOG.info('Groupfinder user %s', userid)
    permissions = ['view']
    user = find_user(request, userid)
    if user:
        permissions.append('edit')

    return permissions
