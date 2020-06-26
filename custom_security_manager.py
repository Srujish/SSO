from flask import redirect, g, flash, request, session, current_app, url_for, make_response, Response
from flask_appbuilder.security.views import UserDBModelView, AuthDBView,AuthLDAPView,AuthView,AuthOIDView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
from flask_appbuilder.security.forms import LoginForm_db
from urllib.parse import quote
from flask_appbuilder._compat import as_unicode
from superset import app
import requests
import json
from urllib.parse import urlparse
from posixpath import basename, dirname



class SSOSessionClient:
    def __init__(self, sso_app_host, sso_app_port, sso_app_name):
        self.sso_app_host = sso_app_host
        self.sso_app_port = sso_app_port
        self.sso_app_name = sso_app_name

    def get_sso_session_app_url(self):
        return 'http://' + self.sso_app_host + ':' + str(self.sso_app_port) + '/' + self.sso_app_name

    def create_sso_session(self, app_name, username):
        try: 
            files = {'applicationName': app_name, 'username': username}
            response = requests.post(self.get_sso_session_app_url(), files=files)
            response.raise_for_status()
            return json.loads(response.text)
        except Exception as e:
            return str(e)

    def get_sso_session(self, sso_session_id):
        sso = {'username': 'Nouser'}
        try:
            response = requests.get(self.get_sso_session_app_url() + '/' + sso_session_id )
            response.raise_for_status()
            return json.loads(response.text)
        except Exception as e:
            return sso

    def delete_sso_session(self, sso_session_id):
        try:
            response = requests.delete(self.get_sso_session_app_url() + '/' + sso_session_id)
            response.raise_for_status()
            return json.loads(response.text)
        except Exception as e:
            return str(e)




class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):

        

        """sso starts"""

        sso_app_host = self.appbuilder.app.config["SSO_HOST"]
        sso_app_port = self.appbuilder.app.config["SSO_PORT"] 
        sso_app_name = self.appbuilder.app.config["SSO_NAME"]
        client = SSOSessionClient(sso_app_host, sso_app_port , sso_app_name )

        
        name = request.cookies.get('sso')       
 
        if name is not None:


            client = SSOSessionClient(sso_app_host, sso_app_port , sso_app_name )
            sso_id = client.get_sso_session(name)
            username = sso_id['username']

            user = self.appbuilder.sm.find_user(username=username)



            if user is not None:
                

                                
                login_user(user, remember=False)

                arg = request.args
                dashboard_id = request.args.get('next')

               

                if dashboard_id is not None: 
                    parse_object = urlparse(dashboard_id)
                    s=parse_object.path
                    s=s.split('/')[-2] 
                    return redirect("/superset/dashboard/{}".format(s))


                return redirect("/superset/welcome")

        """sso ends"""


        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            user = self.appbuilder.sm.auth_user_ldap(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login)
            login_user(user, remember=False)

            sso_app_host = self.appbuilder.app.config["SSO_HOST"]
            sso_app_port = self.appbuilder.app.config["SSO_PORT"] 
            sso_app_name = self.appbuilder.app.config["SSO_NAME"]
            sso_api_name = self.appbuilder.app.config["SSO_API_NAME"]
            sso_domain = self.appbuilder.app.config["SSO_DOMAIN_NAME"]

            response = make_response(redirect(self.appbuilder.get_url_for_index))
            client = SSOSessionClient(sso_app_host, sso_app_port, sso_app_name )
            postResponse = client.create_sso_session(sso_api_name , user.username )
            cook = postResponse['id']



            if response is not None:

                response.set_cookie('sso', value=cook , domain = sso_domain )
                return response 

            

            return redirect(self.appbuilder.get_url_for_index)

        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )

    @expose("/logout/")
    def logout(self):

        sso_app_host = self.appbuilder.app.config["SSO_HOST"]
        sso_app_port = self.appbuilder.app.config["SSO_PORT"]
        sso_app_name = self.appbuilder.app.config["SSO_NAME"]
        sso_domain = self.appbuilder.app.config["SSO_DOMAIN_NAME"]


        name = request.cookies.get('sso')
        if name is not None:

            client = SSOSessionClient(sso_app_host, sso_app_port, sso_app_name )
            client.delete_sso_session(name)

            res = app.make_response(redirect(self.appbuilder.get_url_for_index))
    #

            
            res.set_cookie('sso', expires=0,path='/',domain=sso_domain)

            logout_user()
            return res
        logout_user()

        
        return redirect(self.appbuilder.get_url_for_index)

class CustomSecurityManager(SupersetSecurityManager):
    authldapview = CustomAuthDBView
    #authdbview  = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)

         