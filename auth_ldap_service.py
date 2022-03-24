#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Service para conexão.
Serviço de conexão ao server LDAP com usuarios app.
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
__credits__ = ["ldap3.readthedocs.io","Erivando"]
__license__ = "GPLv3"
__version__ = "1.0.0"
__maintainer__ = "Erivando"
__email__ = "erivandosena@gmail.com"
__status__ = "Production"

"""Pacote
   serviço para conexão com servidor LDAP
"""

from ldap3 import Server, Connection, ALL, SIMPLE, SYNC, SUBTREE
import traceback
import sys
from decouple import config

LDAP_SERVER = config('LDAP_SERVER')
LDAP_PORT = config('LDAP_PORT', cast=int)
LDAP_SSL = config('LDAP_SSL', cast=bool)
LDAP_USER_CN = config('LDAP_USER_CN')
LDAP_USER_PASSWORD = config('LDAP_USER_PASSWORD')
LDAP_BASE_DC = config('LDAP_BASE_DC')
LDAP_BASE_DN = config('LDAP_BASE_DN', 'ou=people,%s') % LDAP_BASE_DC
LDAP_AUTO_BIND = config('LDAP_AUTO_BIND', cast=bool)
LDAP_CHECK_NAMES = config('LDAP_CHECK_NAMES', cast=bool)
LDAP_RAISE_EXCEPTIONS = config('LDAP_RAISE_EXCEPTIONS', cast=bool)

# Verifica a autenticação do usuário no LDAP e retorna informações.
def get_ldap_user(usuario, senha):
    servidor_ldap = Server(host=LDAP_SERVER, port=int(LDAP_PORT), use_ssl=LDAP_SSL, get_info=ALL)
    
    try:
        with Connection(servidor_ldap, 
                        authentication=SIMPLE, 
                        user=LDAP_USER_CN, 
                        password=LDAP_USER_PASSWORD, 
                        check_names=LDAP_CHECK_NAMES, 
                        client_strategy=SYNC, 
                        auto_bind=LDAP_AUTO_BIND, 
                        raise_exceptions=LDAP_RAISE_EXCEPTIONS) as connection:

            if connection.search(search_base=LDAP_BASE_DN, search_filter='(&(uid=%s))' % usuario, search_scope=SUBTREE, attributes=['cn','sn']):
                if len(connection.entries) >= 1 :
                    uid = connection.entries[0].entry_dn
                    uid_cn = connection.entries[0].cn
                    
                    if uid_cn:
                        # Tenta vincular o usuário ao LDAP
                        with Connection(servidor_ldap, user = uid , password = senha, auto_bind = LDAP_AUTO_BIND) as conn:
                            if conn.result["description"] == 'success':
                                return uid_cn
                            else:
                                return None 
                    else:
                        return None 
                else:
                    connection.unbind()
                    return None
            else:
                return None 

    except Exception as e:
        print('Erro: ', e, 'Rastreamento: ', traceback.format_exception(*sys.exc_info()))
        return None
