from pyramid.response import Response
from pyramid.view import view_config


from ..models import User

from pyramid.httpexceptions import (
    HTTPFound,
    HTTPForbidden,
)

from pyramid.security import (
    remember,
    forget,
)

from pyramid.view import (
    view_config,
    view_defaults,
    forbidden_view_config,
)

from virksomheden.security import (
    get_user,
    check_password,
    hash_password,
)

import logging

LOG = logging.getLogger(__name__)


@view_config(route_name='home', renderer='../templates/index.jinja2')
def home(request):
    return {}


@view_config(route_name='signin', renderer='../templates/signin.jinja2')
def login(request):
    LOG.info("Handling request: %s", request)
    login_url = request.route_url('signin')
    came_from = request.params.get('came_from', request.referrer)
    if came_from == login_url:
        referrer = '/'  # never use login form itself as came_from
    message = ''
    login = ''
    password = ''
    LOG.info('came_from: %s', came_from)
    if request.method == "POST":
        LOG.info("Params: %s", request.params)
    # if 'form.submitted' in request.params:
        LOG.info('submitted')
        login = request.params['username']
        password = request.params['password']
        user = request.dbsession.query(User).filter_by(name=login).first()
        if user:
            if check_password(password, user.password):
                LOG.info('Login successful, redirect to %s', came_from)
                headers = remember(request, user.id)
                return HTTPFound(location=came_from, headers=headers)
        message = 'Failed login'

    return dict(
        name='Login',
        message=message,
        url=request.route_url('signin'),  # request.application_url + '/login',
        came_from=came_from,
        login=login,
    )


@forbidden_view_config()
def forbidden_view(request):
    next_url = request.route_url('signin', _query={'came_from': request.url})
    return HTTPFound(location=next_url)


@view_config(route_name='signout')
def logout(request):
    headers = forget(request)
    url = request.route_url('home')
    return HTTPFound(location=url, headers=headers)


@view_config(route_name='register', renderer='../templates/register.jinja2')
def register(request):
    if request.method == "POST":
        username = request.params['username']
        password = request.params['password']
        email = request.params['email']

        # TODO: Check that username does not exist

        user = User()
        user.name = username
        user.password = hash_password(password)

        request.dbsession.add(user)
        return HTTPFound(request.route_path('signin'))

    return {}


@view_config(route_name='magasiner', renderer='../templates/magasiner.jinja2')
def magasiner(request):
    """Show magasines."""
    user = request.user

    if user is None:
        raise HTTPForbidden

    return {}

@view_config(route_name='artikler', renderer='../templates/artikler.jinja2')
def articles(request):
    """Show articles."""
    return {}

@view_config(route_name='kontakt', renderer='../templates/kontakt.jinja2')
def contact(request):
    """Show contact information."""

    ## TODO: SEND QUESTION TO MAIL ADDRESS

    return {}

@view_config(route_name='om', renderer='../templates/om.jinja2')
def about(request):
    """Show info."""
    return {}

@view_config(route_name='is', renderer='../templates/is.jinja2')
def isen(request):
    """Show info."""
    return {}
