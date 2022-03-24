#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Backend para Altenticação.
Backend para Altenticação ao server LDAP com usuarios app.
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

__author__ = "Erivando Sena"
__copyright__ = "Copyright 2021, Projetos em Python 3"
__credits__ = ["docs.djangoproject.com","Erivando"]
__license__ = "GPLv3"
__version__ = "1.0.0"
__maintainer__ = "Erivando"
__email__ = "erivandosena@gmail.com"
__status__ = "Production"

"""Pacote
   Backend para Altenticação LDAP em Users App Django
"""

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from appweb.auth_ldap_service import get_ldap_user
import hashlib
from django.conf import settings

class LdapAuthentication(ModelBackend):
    """Classe Backend para Altenticação LDAP"""

    def authenticate(self, request=None, **kwargs):
        for key, value in kwargs.items():
            if key == "username":
                username=value
            if key == "password":
                password=value
                
        # Obtem credenciais de hash de senha
        hash_object = hashlib.md5(password.encode())
        md5_hash = hash_object.hexdigest()

        login_valid = (settings.ADMIN_LOGIN == username)
        pwd_valid = (settings.ADMIN_PASSWORD == md5_hash)
        
        if login_valid and pwd_valid:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = self.cria_user(username, md5_hash)
            return user

        # Obter as informações do usuário no LDAP se ele puder ser autenticado.
        usuario_ldap = get_ldap_user(username, password)
        
        if usuario_ldap is None:
            return None
        try:
            user = User.objects.get(username=usuario_ldap)
        except User.DoesNotExist:
            user = self.cria_user(usuario_ldap, md5_hash)
        return user
    
    def cria_user(self, usuario=None, senha=None):
        if usuario and usuario == "administrador":
            user = User(username=usuario,
                        email=settings.ADMIN_EMAIL,
                        password=settings.ADMIN_PASSWORD,
                        first_name='Super',
                        last_name='Usuário',
                        is_staff=True,
                        is_superuser=True)
        else:
            user = User(username=usuario, password=senha)
        user.save()

        return user
