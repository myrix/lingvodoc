# 
# NOTE
#
# See information on how tests are organized and how they should work in the tests' package __init__.py file
# (currently lingvodoc/tests/__init__.py).
#

import unittest
import transaction

from pyramid import testing
from lingvodoc.models import DBSession

from pyramid.httpexceptions import (
    HTTPNotFound,
    HTTPOk,
    HTTPBadRequest,
    HTTPConflict,
    HTTPInternalServerError,
    HTTPUnauthorized,
    HTTPFound,
    HTTPForbidden
)
from pyramid.paster import (
    get_appsettings,
    setup_logging,
    )

from subprocess import PIPE, Popen
from configparser import ConfigParser

import os
import pdb
import pytest
import sys


# Assuming that required .ini-file is in the parent directory of the
# 'tests' package --- i.e., package of this module.
alembic_ini_path = os.path.join(
  os.path.dirname(__file__), '..', 'alembictests.ini')

parser = ConfigParser()
parser.read(alembic_ini_path)
alembic_conf = dict()
for k, v in parser.items('alembic'):
    alembic_conf[k] = v
dbname = alembic_conf['sqlalchemy.url']

from lingvodoc.scripts.initializedb import data_init


def debug_print(debug_flag, mssg):
    if debug_flag:
        for entry in mssg:
            print(entry)


def new_dict(d, key_set, stop_words=list(), debug_flag=False):
    new_d = dict()
    empty_lst = [None, {}, [], ()]
    empty_lst += [str(o) for o in empty_lst]
    for key in d:
        if key not in stop_words:
            # debug_print(debug_flag, ['key', key])
            el = d[key]
            if el not in empty_lst:
                new_d[key] = el  # deepcopy(el)
                key_set.add(key)
    return new_d


def is_equal(el1, el2, stop_words=list(), set_like=False, debug_flag=False):
    t1, t2 = type(el1), type(el2)
    if t1 != t2:
        debug_print(debug_flag, ['diff types', t1, t2])
        return False
    if t1 == dict:
        if not dict_diff(el1,el2, stop_words, set_like, debug_flag):
            debug_print(debug_flag, ['diff dicts', el1, el2])
            return False
    elif t1 == list:
        if not list_diff(el1,el2, stop_words, set_like, debug_flag):
                debug_print(debug_flag, ['diff lists', el1, el2, 'setlike: %s' % set_like])
                return False
    elif el1 != el2:
        debug_print(debug_flag, ['diff elements', el1, el2])
        return False
    return True


def list_diff(l1, l2, stop_words=list(), set_like=False, debug_flag=False):
    if len(l1) != len(l2):
        return False
    if not set_like:
        for i in range(len(l1)):
            if not is_equal(l1[i], l2[i], stop_words, set_like, debug_flag):
                debug_print(debug_flag, ['diff lists'])
                return False
    else:
        for el1 in l1:
            no_same_el = True
            for el2 in l2:
                if is_equal(el1, el2, stop_words, set_like):
                    no_same_el = False
            if no_same_el:
                return False
    return True


def dict_diff(d1, d2, stop_words=list(), set_like=False, debug_flag=False):
    keyset = set()
    nd1 = new_dict(d1, keyset, stop_words, debug_flag)
    nd2 = new_dict(d2, keyset, stop_words, debug_flag)
    debug_print(debug_flag, ['keyset:', keyset, 'new dicts:', nd1, nd2])
    for key in keyset:
        el1, el2 = nd1.get(key), nd2.get(key)
        if not is_equal(el1, el2, stop_words, set_like, debug_flag):
            return False
    return True


class DummyWs(object):

    def shutdown(self=None):  # that is really bad. really
        pass


class MyTestCase(unittest.TestCase):
    """
    Common parent class for Lingvodoc API test cases.
    """

    server_is_up = False

    @classmethod
    def set_server_is_up(cls, sip):
        MyTestCase.server_is_up = sip

    @classmethod
    def get_server_is_up(cls):
        return MyTestCase.server_is_up

    def setUp(self):

        self.config = testing.setUp()

        import webtest.http
        from pyramid import paster
        from sqlalchemy import create_engine
        engine = create_engine(dbname)

        myapp = paster.get_app(alembic_ini_path)
        if not self.get_server_is_up():
            self.ws = webtest.http.StopableWSGIServer.create(myapp, port=6543, host="0.0.0.0")  # todo: change to pserve
            self.ws.wait()
            self.set_server_is_up(True)
        self.app = webtest.TestApp(myapp)

        DBSession.configure(bind=engine)
        bashcommand = "alembic -c %s upgrade head" % alembic_ini_path

        args = bashcommand.split()
        pathdir = os.path.dirname(os.path.realpath(__file__))
        pathdir = pathdir[:(len(pathdir) - 6)]
        my_env = os.environ
        proc = Popen(args, cwd=pathdir, env=my_env)
        proc.communicate()

        accounts = get_appsettings(alembic_ini_path, 'accounts')
        data_init(transaction.manager, accounts)

    def tearDown(self):

        DBSession.remove()

        bashcommand = "alembic -c %s downgrade base" % alembic_ini_path
        args = bashcommand.split()
        pathdir = os.path.dirname(os.path.realpath(__file__))
        pathdir = pathdir[:(len(pathdir) - 6)]
        my_env = os.environ
        proc = Popen(args, cwd=pathdir, env=my_env)
        proc.communicate()

        testing.tearDown()

    def assertEqual(self, d1, d2, msg=None, stop_words=list(), set_like=True, debug_flag=False):
        if type(d1) == dict and type(d2) == dict:
            self.assertEqual(dict_diff(d1, d2, stop_words=stop_words, set_like=set_like, debug_flag=debug_flag), True, msg)
        else:
            if type(d1) == list and type(d2) == list:
                self.assertEqual(list_diff(d1, d2, stop_words=stop_words, set_like=set_like, debug_flag=debug_flag), True, msg)
            else:
                unittest.TestCase.assertEqual(self, d1, d2)

    def assertDictEqual(self, d1, d2, msg=None, stop_words=list(), set_like=False, debug_flag=False):
        self.assertEqual(dict_diff(d1, d2, stop_words=stop_words, set_like=set_like, debug_flag=debug_flag), True, msg)

    def assertListEqual(self, l1, l2, msg=None, stop_words=list(), set_like=False, debug_flag=False):
        self.assertEqual(list_diff(l1, l2, stop_words=stop_words, set_like=set_like, debug_flag=debug_flag), True, msg)

    def signup_common(self, username='test', prev_log = 'test'):
        email = username + '@test.com'
        response = self.app.post('/signup', params={'login': username,
                                                         'password': 'pass',
                                                         'name': 'test',
                                                         'email': email,
                                                         'day': '1',
                                                         'month': '1',
                                                         'year': '1970'})
        response = self.app.post('/logout')
        response = self.app.post('/login', params={'login': username,
                                                   'password': 'pass'})
        response = self.app.get('/user')
        user_id = response.json['id']

        response = self.app.post('/logout')
        response = self.app.post('/login', params={'login': prev_log,
                                                   'password': 'pass'})
        return user_id

    def login_common(self, username='test'):
        response = self.app.post('/login', params={'login': username,
                                                   'password': 'pass'})

    def create_language(self, translation_string, par_ids={'client_id': None, 'object_id': None}):

        response = self.app.post_json('/language', params={'translation_string': translation_string,
                                                           'parent_client_id': par_ids['client_id'],
                                                           'parent_object_id': par_ids['object_id']})
        ids = response.json
        return ids

    def dictionary_change_state(self, dict_ids, state):
            response = self.app.put_json('/dictionary/%s/%s/state' % (dict_ids['client_id'], dict_ids['object_id']),
                                         params={'status':state})

    def perspective_change_state(self, dict_ids, persp_ids, state):
            response = self.app.put_json('/dictionary/%s/%s/perspective/%s/%s/state'
                                         % (dict_ids['client_id'],dict_ids['object_id'],
                                            persp_ids['client_id'], persp_ids['object_id']),
                                         params={'status':state})

    def create_dictionary(self, translation_string, par_ids, state=None):
            response = self.app.post_json('/dictionary', params={'translation_string': translation_string,
                                                               'parent_client_id': par_ids['client_id'],
                                                               'parent_object_id': par_ids['object_id']})
            ids = response.json
            if state:
                self.dictionary_change_state(ids, state)
            return ids

    def create_perspective(self, translation_string, par_ids, state=None, is_template=False):
            response = self.app.post_json('/dictionary/%s/%s/perspective' % (par_ids['client_id'],par_ids['object_id']),
                                          params={'translation_string': translation_string, 'is_template': is_template})
            ids = response.json
            response = self.app.get('/dictionary/%s/%s/perspective/%s/%s' % (par_ids['client_id'],par_ids['object_id'],
                                                                             ids['client_id'], ids['object_id']))
            first_view = response.json
            if state:
                self.perspective_change_state(par_ids,ids,state)
            return ids

    def add_l1e(self, dict_ids, persp_ids, lex_ids, content='content', entity_type='Word', data_type='text'):

        response = self.app.post_json('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/%s/%s/leveloneentity'
                                      % (dict_ids['client_id'],
                                         dict_ids['object_id'],
                                         persp_ids['client_id'],
                                         persp_ids['object_id'],
                                         lex_ids['client_id'],
                                         lex_ids['object_id']),
                                      params={'entity_type':entity_type,
                                              'data_type':data_type,
                                              'content': content,
                                              'locale_id': 1})
        l1e_ids = response.json
        return l1e_ids

    def add_grouping(self, first_lex, second_lex, tag=None):
        params = {'connections': [first_lex, second_lex], 'entity_type':'Etymology'}
        if tag:
            params['tag'] = tag
        response = self.app.post_json('/group_entity', params=params)

    def dict_convert(self, filename='test.sqlite', user_id=None):
        from time import sleep
        if user_id is None:
            user_id = self.signup_common()
        self.login_common()
        response = self.app.post_json('/dictionaries', params={'user_created': [user_id]})
        first_dicts = response.json['dictionaries']
        first_len = len(response.json['dictionaries'])
        root_ids = self.create_language('Корень')
        response = self.app.post('/blob', params = {'data_type':'dialeqt_dictionary'},
                                 upload_files=([('blob', filename)]))
        blob_ids = response.json
        response = self.app.post_json('/convert', params={'blob_client_id': blob_ids['client_id'],
                                                         'blob_object_id': blob_ids['object_id'],
                                                          'parent_client_id':root_ids['client_id'],
                                                          'parent_object_id':root_ids['object_id']})
        not_found = True
        for i in range(3):
            response = self.app.post_json('/dictionaries', params={'user_created': [user_id]})
            if len(response.json['dictionaries']) > first_len:
                not_found = False
                break
            sleep(10)
        if not_found:
            self.assertEqual('error', 'converting dictionary was not found')

        sorted_ids = response.json['dictionaries'][:]
        sorted_ids = sorted(sorted_ids, key=lambda x: (x['client_id'], x['object_id']))
        dict_ids = sorted_ids[-1]

        for i in range(3):
            response = self.app.get('/dictionary/%s/%s/perspectives' % (dict_ids['client_id'], dict_ids['object_id']))
            if response.json['perspectives']:
                not_found = False
                break
            sleep(10)
        if not_found:
            self.assertEqual('error', 'converting perspective was not found')
        persp_ids = response.json['perspectives'][0]

        for i in range(20):
            response = self.app.get('/dictionary/%s/%s/state' %
                                    (dict_ids['client_id'],
                                     dict_ids['object_id']))
            # response = self.app.get('/dictionary/%s/%s/state' % (dict_ids['client_id'], dict_ids['object_id']))
            if response.json['status'].lower() == 'Converting 100%'.lower():
                break

            sleep(60)
            response = self.app.get('/dictionary/%s/%s/state' %
                                    (dict_ids['client_id'],
                                     dict_ids['object_id']))
        return dict_ids, persp_ids


@pytest.mark.skip(reason = 'Unconverted test from the previous version.')
class TestBig(MyTestCase):

    def one_big_test(self):
        # test impossibility to create language without login
        response = self.app.post_json('/language', params={'translation_string': 'test'},
                                     status=HTTPForbidden.code)
        self.assertEqual(response.status_int, HTTPForbidden.code)
        # test signup & login
        user_id = self.signup_common()
        self.login_common()
        # test creating language
        lang_name = 'test_lang'
        par_ids = self.create_language(lang_name)
        # test view all languages

        response = self.app.get('/languages')

        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'languages':
                              [{'translation': 'Russian language',
                                'client_id': 1, 'translation_string': 'Russian language',
                                'object_id': 1, 'locale_exist': True},
                               {'translation': 'English language', 'client_id': 1,
                                'translation_string': 'English language',
                                'object_id': 2, 'locale_exist': True},
                               {'translation': 'Finnish language', 'client_id': 1,
                                'translation_string': 'Finnish language', 'object_id': 3,
                                'locale_exist': True},
                               {'translation': 'French language', 'client_id': 1,
                                'translation_string': 'French language', 'object_id': 4,
                                'locale_exist': True},
                               {'translation': 'German language', 'client_id': 1,
                                'translation_string': 'German language',
                                'object_id': 5, 'locale_exist': True},
                               {'translation': lang_name, 'client_id': par_ids['client_id'],
                                'translation_string': lang_name,
                                'object_id': par_ids['object_id'], 'locale_exist': False}]}
        self.assertDictEqual(response.json, correct_answer) #, stop_words=['client_id', 'object_id']
        firstlang = response.json['languages'][0]
        firstlangids = {'client_id': firstlang['client_id'], 'object_id': firstlang['object_id']}
        # test all params when editing language
        response = self.app.put_json('/language/%s/%s' % (par_ids['client_id'], par_ids['object_id']),
                                     params={'translation':'new_translation',
                                             'parent_client_id':firstlangids['client_id'],
                                             'parent_object_id':firstlangids['object_id']})
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/language/%s/%s' % (par_ids['client_id'], par_ids['object_id']))
        correct_answer = {'client_id': par_ids['client_id'],
                          'object_id': par_ids['object_id'],
                          'locale_exist': False,
                          'translation': 'new_translation',
                          'parent_client_id': firstlangids['client_id'],
                          'translation_string': lang_name,
                          'parent_object_id': firstlangids['object_id']}
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)
        # test all params when creating language
        response = self.app.post_json('/language', params={'translation_string': 'test_child',
                                                           'parent_client_id': par_ids['client_id'],
                                                           'parent_object_id': par_ids['object_id']})
        self.assertEqual(response.status_int, HTTPOk.code)
        ids2 = response.json
        response = self.app.get('/language/%s/%s' % (ids2['client_id'], ids2['object_id']))
        correct_answer = {'client_id': ids2['client_id'], 'object_id': ids2['object_id'],
                          'locale_exist': False, 'translation': 'test_child',
                          'parent_client_id': par_ids['client_id'],
                          'translation_string': 'test_child',
                          'parent_object_id': par_ids['object_id']}
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)
        # test creating dictionary

        dict_name = 'test_dict'
        dict_ids = self.create_dictionary(dict_name, par_ids)
        # test edit dictionary
        response = self.app.put_json('/dictionary/%s/%s' % (dict_ids['client_id'], dict_ids['object_id']),
                                     params={'translation':'new_translation',
                                             'parent_client_id':firstlangids['client_id'],
                                             'parent_object_id':firstlangids['object_id']})
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/dictionary/%s/%s' % (dict_ids['client_id'], dict_ids['object_id']))
        correct_answer = {'client_id': dict_ids['client_id'],
                          'object_id': dict_ids['object_id'],
                          'additional_metadata': '[]',
                          'translation': 'new_translation',
                          'parent_client_id': firstlangids['client_id'],
                          'translation_string': dict_name,
                          'parent_object_id': firstlangids['object_id'],
                          'status': 'WiP'}
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.put_json('/dictionary/%s/%s' % (dict_ids['client_id'], dict_ids['object_id']),
                                     params={'translation':'new_translation',
                                             'parent_client_id':par_ids['client_id'],
                                             'parent_object_id':par_ids['object_id']})
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/dictionary/%s/%s' % (dict_ids['client_id'], dict_ids['object_id']))
        correct_answer = {'client_id': dict_ids['client_id'],
                          'object_id': dict_ids['object_id'],
                          'additional_metadata': '[]',
                          'translation': 'new_translation',
                          'parent_client_id': par_ids['client_id'],
                          'translation_string': dict_name,
                          'parent_object_id': par_ids['object_id'],
                          'status': 'WiP'}
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)

        # test view dictionary state
        response = self.app.get('/dictionary/%s/%s/state' % (dict_ids['client_id'], dict_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, {'status': 'WiP'})
        # test edit dictionary state
        self.dictionary_change_state(dict_ids, 'test state')
        persp_name = 'test_persp'
        # test creating perspective
        persp_ids = self.create_perspective(persp_name, dict_ids)
        # test perspective edit

        dict2_name = 'test_dict_2'
        dict_ids2 = self.create_dictionary(dict2_name, par_ids)
        response = self.app.put_json('/dictionary/%s/%s/perspective/%s/%s'
                                     % (dict_ids['client_id'],
                                        dict_ids['object_id'],
                                        persp_ids['client_id'], persp_ids['object_id']),
                                     params={'translation':'new_translation',
                                             'parent_client_id': dict_ids2['client_id'],
                                             'parent_object_id': dict_ids2['object_id'],
                                             'is_template': True})
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s' % (dict_ids['client_id'], dict_ids['object_id'],
                                                                         persp_ids['client_id'], persp_ids['object_id']))
        correct_answer = {'translation': 'new_translation', 'parent_client_id': 5, 'object_id': 7, 'client_id': 5, 'translation_string': 'test_persp', 'status': 'WiP', 'marked_for_deletion': False, 'is_template': True, 'parent_object_id': 9, 'additional_metadata': '{}'}
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)
        # return old parent to perspective
        response = self.app.put_json('/dictionary/%s/%s/perspective/%s/%s'
                                     % (dict_ids2['client_id'],
                                        dict_ids2['object_id'],
                                        persp_ids['client_id'],
                                        persp_ids['object_id']),
                                     params={'parent_client_id': dict_ids['client_id'],
                                             'parent_object_id': dict_ids['object_id'],
                                             'is_template': True})
        self.assertEqual(response.status_int, HTTPOk.code)
        # test view perspective state
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/state'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, {'status': 'WiP'})
        # test edit perspective state
        self.perspective_change_state(dict_ids, persp_ids, 'test state')
        # test view perspective tree
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/tree'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)

        correct_answer = [{'parent_object_id': dict_ids['object_id'],
                           'parent_client_id': dict_ids['client_id'],
                           'object_id': persp_ids['object_id'],
                           'client_id': persp_ids['client_id'],
                           'translation_string': persp_name,
                           'is_template': True,
                           'status': 'test state',
                           'marked_for_deletion': False,
                           'translation': 'new_translation',
                           'type': 'perspective'},
                          {'additional_metadata': None,
                           'parent_object_id': par_ids['object_id'],
                           'parent_client_id': par_ids['client_id'],
                           'client_id': dict_ids['client_id'],
                           'translation_string': dict_name,
                           'object_id': dict_ids['object_id'],
                           'status': 'test state',
                           'translation': 'new_translation',
                           'type': 'dictionary'},
                          {'parent_object_id': firstlangids['object_id'],
                           'parent_client_id': firstlangids['client_id'],
                           'locale_exist': False,
                           'translation_string': lang_name,
                           'object_id': par_ids['object_id'],
                           'client_id': par_ids['client_id'],
                           'translation': 'new_translation', 'type': 'language'},
                          {'parent_object_id': None,
                           'parent_client_id': None,
                           'locale_exist': True,
                           'translation_string': 'Russian language',
                           'object_id': firstlangids['object_id'],
                           'client_id': firstlangids['client_id'],
                           'translation': 'Russian language',
                           'type': 'language'}]
        first_answ = response.json
        self.assertListEqual(first_answ, correct_answer)
        response = self.app.get('/perspective/%s/%s/tree' % (persp_ids['client_id'], persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertListEqual(first_answ, response.json)

        # testing perspective meta
        metadict = {'a':'b', 'c':{'d':'e'}}
        response = self.app.put_json('/dictionary/%s/%s/perspective/%s/%s/meta'
                                     % (dict_ids['client_id'],
                                        dict_ids['object_id'],
                                        persp_ids['client_id'],
                                        persp_ids['object_id']),
                                     params = metadict)
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/meta'
                                     % (dict_ids['client_id'],
                                        dict_ids['object_id'],
                                        persp_ids['client_id'],
                                        persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, metadict)

        metaupd = {'a': {'f': 'g'}, 'h': 'i', 'j': ['k', 'l', {'m': 'n', 'o': 'p'}]}
        response = self.app.put_json('/dictionary/%s/%s/perspective/%s/%s/meta'
                                     % (dict_ids['client_id'],
                                        dict_ids['object_id'],
                                        persp_ids['client_id'],
                                        persp_ids['object_id']),
                                     params=metaupd)
        self.assertEqual(response.status_int, HTTPOk.code)
        metadict.update(metaupd)
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/meta'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, metadict)
        metadel = ['j', 'c']
        response = self.app.delete_json('/dictionary/%s/%s/perspective/%s/%s/meta'
                                        % (dict_ids['client_id'],
                                           dict_ids['object_id'],
                                           persp_ids['client_id'],
                                           persp_ids['object_id']),
                                        params=metadel)
        self.assertEqual(response.status_int, HTTPOk.code)
        for key in metadel:
            del metadict[key]
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/meta'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, metadict)

        # test roles
        response = self.app.get('/dictionary/%s/%s/roles'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'roles_users':
                              {'Can resign users from dictionary editors': [user_id],
                               'Can create perspectives': [user_id],
                               'Can merge dictionaries and perspectives': [user_id],
                               'Can delete dictionary': [user_id],
                               'Can create dictionary roles and assign collaborators': [user_id],
                               'Can get dictionary role list': [user_id],
                               'Can edit dictionary options': [user_id]},
                          'roles_organizations':
                              {'Can resign users from dictionary editors': [],
                               'Can create perspectives': [],
                               'Can merge dictionaries and perspectives': [],
                               'Can delete dictionary': [],
                               'Can create dictionary roles and assign collaborators': [],
                               'Can get dictionary role list': [],
                               'Can edit dictionary options': []}}
        self.assertDictEqual(response.json, correct_answer)

        user_id2 = self.signup_common('test2')
        user_id3 = self.signup_common('test3')
        params = {'roles_users':
                              {'Can resign users from dictionary editors': [user_id2],
                               'Can create perspectives': [user_id2],
                               'Can merge dictionaries and perspectives': [user_id3],
                               'Can create dictionary roles and assign collaborators': [user_id2],
                               'Can get dictionary role list': [user_id2],
                               'Can edit dictionary options': [user_id3]}}
        response = self.app.post_json('/dictionary/%s/%s/roles' % (dict_ids['client_id'],
                                                             dict_ids['object_id']), params=params)
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'roles_users':
                              {'Can resign users from dictionary editors': [user_id, user_id2],
                               'Can create perspectives': [user_id, user_id2],
                               'Can merge dictionaries and perspectives': [user_id, user_id3],
                               'Can delete dictionary': [user_id],
                               'Can create dictionary roles and assign collaborators': [user_id, user_id2],
                               'Can get dictionary role list': [user_id, user_id2],
                               'Can edit dictionary options': [user_id, user_id3]},
                          'roles_organizations':
                              {'Can resign users from dictionary editors': [],
                               'Can create perspectives': [],
                               'Can merge dictionaries and perspectives': [],
                               'Can delete dictionary': [],
                               'Can create dictionary roles and assign collaborators': [],
                               'Can get dictionary role list': [],
                               'Can edit dictionary options': []}}
        response = self.app.get('/dictionary/%s/%s/roles' % (dict_ids['client_id'],
                                                             dict_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)
        self.login_common('test2')
        # import pdb; pdb.set_trace()
        params = {'roles_users':
                              {'Can resign users from dictionary editors': [user_id3],
                               'Can create perspectives': [user_id3]}}
        response = self.app.post_json('/dictionary/%s/%s/roles' % (dict_ids['client_id'],
                                                             dict_ids['object_id']), params=params)
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'roles_users':
                              {'Can resign users from dictionary editors': [user_id, user_id2, user_id3],
                               'Can create perspectives': [user_id, user_id2, user_id3],
                               'Can merge dictionaries and perspectives': [user_id, user_id3],
                               'Can delete dictionary': [user_id],
                               'Can create dictionary roles and assign collaborators': [user_id, user_id2],
                               'Can get dictionary role list': [user_id, user_id2],
                               'Can edit dictionary options': [user_id, user_id3]},
                          'roles_organizations':
                              {'Can resign users from dictionary editors': [],
                               'Can create perspectives': [],
                               'Can merge dictionaries and perspectives': [],
                               'Can delete dictionary': [],
                               'Can create dictionary roles and assign collaborators': [],
                               'Can get dictionary role list': [],
                               'Can edit dictionary options': []}}
        response = self.app.get('/dictionary/%s/%s/roles' % (dict_ids['client_id'],
                                                             dict_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)

        self.login_common('test')

        params = {'roles_users':
                              {'Can create dictionary roles and assign collaborators': [user_id2],
                               'Can edit dictionary options': [user_id3]}}
        response = self.app.delete_json('/dictionary/%s/%s/roles' % (dict_ids['client_id'],
                                                                     dict_ids['object_id']), params=params)
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'roles_users':
                              {'Can resign users from dictionary editors': [user_id, user_id2, user_id3],
                               'Can create perspectives': [user_id, user_id2, user_id3],
                               'Can merge dictionaries and perspectives': [user_id, user_id3],
                               'Can delete dictionary': [user_id],
                               'Can create dictionary roles and assign collaborators': [user_id],
                               'Can get dictionary role list': [user_id, user_id2],
                               'Can edit dictionary options': [user_id]},
                          'roles_organizations':
                              {'Can resign users from dictionary editors': [],
                               'Can create perspectives': [],
                               'Can merge dictionaries and perspectives': [],
                               'Can delete dictionary': [],
                               'Can create dictionary roles and assign collaborators': [],
                               'Can get dictionary role list': [],
                               'Can edit dictionary options': []}}
        response = self.app.get('/dictionary/%s/%s/roles' % (dict_ids['client_id'],
                                                             dict_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.get('/users')
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'users': [{'login': 'admin', 'name': 'Администратор', 'id': 1,
                                     'intl_name': 'System Administrator'},
                                    {'login': 'test', 'name': 'test', 'id': 2, 'intl_name': 'test'},
                                    {'login': 'test2', 'name': 'test', 'id': 3, 'intl_name': 'test2'},
                                    {'login': 'test3', 'name': 'test', 'id': 4, 'intl_name': 'test3'}]}
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/fields'
                                % (1, 6, 1, 7))  # TODO: remove ids. use dictionaries list, probably.
        # todo: Or just create new db with new object_ids and find needed pairs of ids

        self.assertEqual(response.status_int, HTTPOk.code)
        fields = response.json
        response = self.app.post_json('/dictionary/%s/%s/perspective/%s/%s/fields'
                                      % (dict_ids['client_id'],
                                         dict_ids['object_id'],
                                         persp_ids['client_id'],
                                         persp_ids['object_id']),
                                      params=fields)

        self.assertEqual(response.status_int, HTTPOk.code)

        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/fields'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, fields, stop_words=['client_id', 'object_id'])

        response = self.app.post_json('/dictionary/%s/%s/perspective/%s/%s/lexical_entry'%
                                      (dict_ids['client_id'], dict_ids['object_id'],
                                       persp_ids['client_id'], persp_ids['object_id']), params={})
        self.assertEqual(response.status_int, HTTPOk.code)
        lex_ids = response.json

        response = self.app.post_json('/dictionary/%s/%s/perspective/%s/%s/lexical_entries'%
                                      (dict_ids['client_id'], dict_ids['object_id'],
                                       persp_ids['client_id'], persp_ids['object_id']), params={'count': 41})
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = [{} for o in range(41)]
        self.assertListEqual(response.json, correct_answer, stop_words=['object_id', 'client_id'])
        lexes_ids = response.json

        l1e_ids = self.add_l1e(dict_ids, persp_ids,lex_ids, content='testing level one entity')

        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/%s/%s/leveloneentity/%s/%s'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id'],
                                   lex_ids['client_id'],
                                   lex_ids['object_id'],
                                   l1e_ids['client_id'],
                                   l1e_ids['object_id'],))
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'client_id': l1e_ids['client_id'],
                          'parent_client_id': lex_ids['client_id'],
                          'parent_object_id': lex_ids['object_id'],
                          'object_id': l1e_ids['object_id'],
                          'entity_type': 'Word',
                          'level': 'leveloneentity',
                          'marked_for_deletion': False,
                          'locale_id': 1,
                          'content': 'testing level one entity'}
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.get('/leveloneentity/%s/%s'
                                % (l1e_ids['client_id'],
                                   l1e_ids['object_id'],))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.post_json('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/%s/%s/leveloneentity'
                                      '/%s/%s/leveltwoentity'
                                      % (dict_ids['client_id'],
                                         dict_ids['object_id'],
                                         persp_ids['client_id'],
                                         persp_ids['object_id'],
                                         lex_ids['client_id'],
                                         lex_ids['object_id'],
                                         l1e_ids['client_id'],
                                         l1e_ids['object_id']),
                                      params={'entity_type':'Word',
                                              'data_type':'text',
                                              'content': 'testing level two entity',
                                              'locale_id': 1})
        self.assertEqual(response.status_int, HTTPOk.code)

        l2e_ids = response.json
        self.assertDictEqual(response.json, {}, stop_words=['object_id', 'client_id'])

        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/%s/%s/leveloneentity'
                                '/%s/%s/leveltwoentity/%s/%s'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id'],
                                   lex_ids['client_id'],
                                   lex_ids['object_id'],
                                   l1e_ids['client_id'],
                                   l1e_ids['object_id'],
                                   l2e_ids['client_id'],
                                   l2e_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        # correct_answer = {'client_id': l2e_ids['client_id'],  # TODO: uncomment when fixed in refactoring
        #                   'parent_client_id': l1e_ids['client_id'],
        #                   'parent_object_id': l1e_ids['object_id'],
        #                   'object_id': l2e_ids['object_id'],
        #                   'entity_type': 'Word',
        #                   'level': 'leveltwoentity',
        #                   'marked_for_deletion': False,
        #                   'locale_id': 1,
        #                   'content': 'testing level two entity'}
        correct_answer = {'parent_client_id': l1e_ids['client_id'],
                          'parent_object_id': l1e_ids['object_id'],
                          'entity_type': 'Word',
                          'locale_id': 1,
                          'content': 'testing level two entity'}
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.get('/leveltwoentity/%s/%s'
                                % (l2e_ids['client_id'],
                                   l2e_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)

        response = self.app.get('/lexical_entry/%s/%s' %
                                (lex_ids['client_id'],
                                lex_ids['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        # print('RIGHT ANSWER:', response.json)
        correct_answer = {'lexical_entry': {'client_id': 13, 'object_id': 1, 'came_from': None, 'level': 'lexicalentry', 'published': False, 'parent_client_id': 5, 'contains': [{'client_id': 13, 'content': 'testing level one entity', 'locale_id': 1, 'level': 'leveloneentity', 'parent_client_id': 13, 'object_id': 1, 'entity_type': 'Word', 'contains': [{'client_id': 13, 'content': 'testing level two entity', 'locale_id': 1, 'level': 'leveltwoentity', 'parent_client_id': 13, 'object_id': 1, 'entity_type': 'Word', 'contains': None, 'additional_metadata': None, 'published': False, 'marked_for_deletion': False, 'parent_object_id': 1}], 'additional_metadata': None, 'published': False, 'marked_for_deletion': False, 'parent_object_id': 1}], 'parent_object_id': 1, 'marked_for_deletion': False}}

        self.assertDictEqual(response.json, correct_answer, stop_words=['client_id', 'object_id', 'parent_client_id', 'parent_object_id'], set_like=True)  # TODO: do not ignore everything. Some other equality check needs to be done
        same_answer = response.json
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/%s/%s'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id'],
                                   lex_ids['client_id'],
                                   lex_ids['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        # print('RIGHT ANSWER:', response.json)
        self.assertDictEqual(response.json, same_answer, set_like=True)



        grouping_lexes = lexes_ids[:6:]
        lexes_ids = lexes_ids[6::]
        grouping_contents = list()
        counter = 0
        for iter_lex_ids in grouping_lexes:
            content = 'grouping word ' + str(counter)
            grouping_contents.append(content)
            self.add_l1e(dict_ids, persp_ids, iter_lex_ids, content=content)
            counter += 1

        params = {'connections': [grouping_lexes[0], grouping_lexes[1]], 'entity_type':'Etymology'}
        response = self.app.post_json('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/connect' %
                                      (dict_ids['client_id'],
                                       dict_ids['object_id'],
                                       persp_ids['client_id'],
                                       persp_ids['object_id']),
                                      params=params)
        self.assertEqual(response.status_int, HTTPOk.code)
        # self.add_grouping(grouping_lexes[0], grouping_lexes[1])
        correct_answer = {'words': [{'lexical_entry': {'object_id': 2, 'contains': [{'additional_metadata': None, 'object_id': 2, 'parent_client_id': 11, 'published': False, 'locale_id': 1, 'level': 'leveloneentity', 'content': "grouping word {'object_id': 2, 'client_id': 11}", 'contains': None, 'parent_object_id': 2, 'client_id': 11, 'entity_type': 'Word', 'marked_for_deletion': False}, {'additional_metadata': None, 'object_id': 1, 'parent_client_id': 11, 'published': False, 'locale_id': None, 'level': 'groupingentity', 'content': 'Wed Feb 10 13:50:08 2016MNAZGRV22A', 'contains': None, 'parent_object_id': 2, 'client_id': 11, 'entity_type': 'Etymology', 'marked_for_deletion': False}], 'published': False, 'client_id': 11, 'level': 'lexicalentry', 'came_from': None, 'marked_for_deletion': False, 'parent_client_id': 5, 'parent_object_id': 1}}, {'lexical_entry': {'object_id': 3, 'contains': [{'additional_metadata': None, 'object_id': 3, 'parent_client_id': 11, 'published': False, 'locale_id': 1, 'level': 'leveloneentity', 'content': "grouping word {'object_id': 3, 'client_id': 11}", 'contains': None, 'parent_object_id': 3, 'client_id': 11, 'entity_type': 'Word', 'marked_for_deletion': False}, {'additional_metadata': None, 'object_id': 2, 'parent_client_id': 11, 'published': False, 'locale_id': None, 'level': 'groupingentity', 'content': 'Wed Feb 10 13:50:08 2016MNAZGRV22A', 'contains': None, 'parent_object_id': 3, 'client_id': 11, 'entity_type': 'Etymology', 'marked_for_deletion': False}], 'published': False, 'client_id': 11, 'level': 'lexicalentry', 'came_from': None, 'marked_for_deletion': False, 'parent_client_id': 5, 'parent_object_id': 1}}]}

        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/lexical_entry/%s/%s/connected'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id'],
                                   grouping_lexes[0]['client_id'],
                                   grouping_lexes[0]['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer, stop_words=['content', 'client_id', 'object_id', 'parent_client_id', 'parent_object_id'], set_like=True)  # TODO: do not ignore everything. Some other equality check needs to be done

        self.add_grouping(grouping_lexes[2], grouping_lexes[3])
        correct_answer = {'words': [{'lexical_entry': {'contains': [{'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'contains': None, 'object_id': 4, 'content': "grouping word {'object_id': 4, 'client_id': 11}", 'entity_type': 'Word', 'parent_object_id': 4, 'client_id': 11, 'level': 'leveloneentity', 'published': False, 'locale_id': 1}, {'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'contains': None, 'object_id': 3, 'content': 'Wed Feb 10 15:36:45 2016ZV06I8ZRYW', 'entity_type': 'Etymology', 'parent_object_id': 4, 'client_id': 11, 'level': 'groupingentity', 'published': False, 'locale_id': None}], 'parent_client_id': 5, 'parent_object_id': 1, 'client_id': 11, 'level': 'lexicalentry', 'object_id': 4, 'published': False, 'marked_for_deletion': False, 'came_from': None}}, {'lexical_entry': {'contains': [{'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'contains': None, 'object_id': 5, 'content': "grouping word {'object_id': 5, 'client_id': 11}", 'entity_type': 'Word', 'parent_object_id': 5, 'client_id': 11, 'level': 'leveloneentity', 'published': False, 'locale_id': 1}, {'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'contains': None, 'object_id': 4, 'content': 'Wed Feb 10 15:36:45 2016ZV06I8ZRYW', 'entity_type': 'Etymology', 'parent_object_id': 5, 'client_id': 11, 'level': 'groupingentity', 'published': False, 'locale_id': None}], 'parent_client_id': 5, 'parent_object_id': 1, 'client_id': 11, 'level': 'lexicalentry', 'object_id': 5, 'published': False, 'marked_for_deletion': False, 'came_from': None}}]}

        response = self.app.get('/lexical_entry/%s/%s/connected'
                                % (
                                   grouping_lexes[2]['client_id'],
                                   grouping_lexes[2]['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        # print(response.json)
        self.assertDictEqual(response.json, correct_answer, stop_words=['content', 'client_id', 'object_id', 'parent_client_id', 'parent_object_id'], set_like=True)

        self.add_grouping(grouping_lexes[3], grouping_lexes[4])
        correct_answer = {'words': [{'lexical_entry': {'published': False, 'came_from': None, 'object_id': 4, 'client_id': 11, 'level': 'lexicalentry', 'marked_for_deletion': False, 'parent_object_id': 1, 'parent_client_id': 5, 'contains': [{'entity_type': 'Word', 'parent_object_id': 4, 'content': "grouping word {'client_id': 11, 'object_id': 4}", 'published': False, 'locale_id': 1, 'object_id': 4, 'client_id': 11, 'level': 'leveloneentity', 'marked_for_deletion': False, 'additional_metadata': None, 'parent_client_id': 11, 'contains': None}, {'entity_type': 'Etymology', 'parent_object_id': 4, 'content': 'Wed Feb 10 15:49:45 20166TGFY3S1LX', 'published': False, 'locale_id': None, 'object_id': 3, 'client_id': 11, 'level': 'groupingentity', 'marked_for_deletion': False, 'additional_metadata': None, 'parent_client_id': 11, 'contains': None}]}}, {'lexical_entry': {'published': False, 'came_from': None, 'object_id': 5, 'client_id': 11, 'level': 'lexicalentry', 'marked_for_deletion': False, 'parent_object_id': 1, 'parent_client_id': 5, 'contains': [{'entity_type': 'Word', 'parent_object_id': 5, 'content': "grouping word {'client_id': 11, 'object_id': 5}", 'published': False, 'locale_id': 1, 'object_id': 5, 'client_id': 11, 'level': 'leveloneentity', 'marked_for_deletion': False, 'additional_metadata': None, 'parent_client_id': 11, 'contains': None}, {'entity_type': 'Etymology', 'parent_object_id': 5, 'content': 'Wed Feb 10 15:49:45 20166TGFY3S1LX', 'published': False, 'locale_id': None, 'object_id': 4, 'client_id': 11, 'level': 'groupingentity', 'marked_for_deletion': False, 'additional_metadata': None, 'parent_client_id': 11, 'contains': None}]}}, {'lexical_entry': {'published': False, 'came_from': None, 'object_id': 6, 'client_id': 11, 'level': 'lexicalentry', 'marked_for_deletion': False, 'parent_object_id': 1, 'parent_client_id': 5, 'contains': [{'entity_type': 'Word', 'parent_object_id': 6, 'content': "grouping word {'client_id': 11, 'object_id': 6}", 'published': False, 'locale_id': 1, 'object_id': 6, 'client_id': 11, 'level': 'leveloneentity', 'marked_for_deletion': False, 'additional_metadata': None, 'parent_client_id': 11, 'contains': None}, {'entity_type': 'Etymology', 'parent_object_id': 6, 'content': 'Wed Feb 10 15:49:45 20166TGFY3S1LX', 'published': False, 'locale_id': None, 'object_id': 5, 'client_id': 11, 'level': 'groupingentity', 'marked_for_deletion': False, 'additional_metadata': None, 'parent_client_id': 11, 'contains': None}]}}]}

        response = self.app.get('/lexical_entry/%s/%s/connected'
                                % (
                                   grouping_lexes[2]['client_id'],
                                   grouping_lexes[2]['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        # print(response.json)
        self.assertDictEqual(response.json, correct_answer, stop_words=['content', 'client_id', 'object_id', 'parent_client_id', 'parent_object_id'], set_like=True)

        self.add_grouping(grouping_lexes[1], grouping_lexes[4])
        correct_answer = {'words': [{'lexical_entry': {'level': 'lexicalentry', 'came_from': None, 'parent_client_id': 5, 'published': False, 'object_id': 2, 'contains': [{'level': 'leveloneentity', 'entity_type': 'Word', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 2, 'published': False, 'content': "grouping word {'object_id': 2, 'client_id': 11}", 'object_id': 2, 'contains': None, 'locale_id': 1}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 2, 'published': False, 'content': 'Wed Feb 10 15:54:08 2016KPBGYM63DB', 'object_id': 1, 'contains': None, 'locale_id': None}], 'marked_for_deletion': False, 'client_id': 11, 'parent_object_id': 1}}, {'lexical_entry': {'level': 'lexicalentry', 'came_from': None, 'parent_client_id': 5, 'published': False, 'object_id': 3, 'contains': [{'level': 'leveloneentity', 'entity_type': 'Word', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 3, 'published': False, 'content': "grouping word {'object_id': 3, 'client_id': 11}", 'object_id': 3, 'contains': None, 'locale_id': 1}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 3, 'published': False, 'content': 'Wed Feb 10 15:54:08 20167VF6IEU0O7', 'object_id': 6, 'contains': None, 'locale_id': None}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 3, 'published': False, 'content': 'Wed Feb 10 15:54:08 2016KPBGYM63DB', 'object_id': 2, 'contains': None, 'locale_id': None}], 'marked_for_deletion': False, 'client_id': 11, 'parent_object_id': 1}}, {'lexical_entry': {'level': 'lexicalentry', 'came_from': None, 'parent_client_id': 5, 'published': False, 'object_id': 6, 'contains': [{'level': 'leveloneentity', 'entity_type': 'Word', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 6, 'published': False, 'content': "grouping word {'object_id': 6, 'client_id': 11}", 'object_id': 6, 'contains': None, 'locale_id': 1}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 6, 'published': False, 'content': 'Wed Feb 10 15:54:08 2016KPBGYM63DB', 'object_id': 7, 'contains': None, 'locale_id': None}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 6, 'published': False, 'content': 'Wed Feb 10 15:54:08 20167VF6IEU0O7', 'object_id': 5, 'contains': None, 'locale_id': None}], 'marked_for_deletion': False, 'client_id': 11, 'parent_object_id': 1}}, {'lexical_entry': {'level': 'lexicalentry', 'came_from': None, 'parent_client_id': 5, 'published': False, 'object_id': 4, 'contains': [{'level': 'leveloneentity', 'entity_type': 'Word', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 4, 'published': False, 'content': "grouping word {'object_id': 4, 'client_id': 11}", 'object_id': 4, 'contains': None, 'locale_id': 1}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 4, 'published': False, 'content': 'Wed Feb 10 15:54:08 20167VF6IEU0O7', 'object_id': 3, 'contains': None, 'locale_id': None}], 'marked_for_deletion': False, 'client_id': 11, 'parent_object_id': 1}}, {'lexical_entry': {'level': 'lexicalentry', 'came_from': None, 'parent_client_id': 5, 'published': False, 'object_id': 5, 'contains': [{'level': 'leveloneentity', 'entity_type': 'Word', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 5, 'published': False, 'content': "grouping word {'object_id': 5, 'client_id': 11}", 'object_id': 5, 'contains': None, 'locale_id': 1}, {'level': 'groupingentity', 'entity_type': 'Etymology', 'parent_client_id': 11, 'marked_for_deletion': False, 'additional_metadata': None, 'client_id': 11, 'parent_object_id': 5, 'published': False, 'content': 'Wed Feb 10 15:54:08 20167VF6IEU0O7', 'object_id': 4, 'contains': None, 'locale_id': None}], 'marked_for_deletion': False, 'client_id': 11, 'parent_object_id': 1}}]}

        response = self.app.get('/lexical_entry/%s/%s/connected'
                                % (grouping_lexes[0]['client_id'],
                                   grouping_lexes[0]['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        # print(response.json)
        self.assertDictEqual(response.json, correct_answer, stop_words=['content', 'client_id', 'object_id', 'parent_client_id', 'parent_object_id'], set_like=True)
        some_lex = response.json['words'][0]
        # print('some lex:', some_lex)
        ge_ids = None
        ge = None
        tag = None
        for entry in some_lex['lexical_entry']['contains']:
            if 'word' not in entry['content']:
                ge_ids = {'client_id': entry['client_id'],'object_id': entry['object_id']}
                ge = entry
                tag = entry['content']
        if not ge_ids:
            self.assertEqual('Error:', 'No tag')
        combined_words = list()
        for lex in response.json['words']:
            for entry in lex['lexical_entry']['contains']:
                if entry['content'] == tag:
                    combined_words.append({'client_id': lex['lexical_entry']['client_id'],
                                           'object_id': lex['lexical_entry']['object_id']})
        response = self.app.get('/group_entity/%s/%s' % (ge_ids['client_id'], ge_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'entity_type': ge['entity_type'], 'tag': tag, 'connections':combined_words}
        self.assertDictEqual(response.json, correct_answer, set_like=True)
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/all_count'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))
        correct_answer = {'count': 42}
        self.assertEqual(response.status_int, HTTPOk.code)
        self.assertDictEqual(response.json, correct_answer)
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s/all'
                                % (dict_ids['client_id'],
                                   dict_ids['object_id'],
                                   persp_ids['client_id'],
                                   persp_ids['object_id']))

        self.assertEqual(response.status_int, HTTPOk.code)
        # self.assertDictEqual(response.json, correct_answer)  # TODO: change correct answer and uncomment
        # print(response.json)



        # response = self.app.post_json('/dictionary/%s/%s/roles' % (dict_ids['client_id'],dict_ids['object_id']))
        # self.assertEqual(response.status_int, HTTPOk.code)
        # correct_answer = {'roles_users':
        #                       {'Can resign users from perspective editors': [user_id],
        #                        'Can create perspectives': [user_id],
        #                        'Can merge dictionaries and perspectives': [user_id],
        #                        'Can delete dictionary': [user_id],
        #                        'Can create dictionary roles and assign collaborators': [user_id],
        #                        'Can get dictionary role list': [user_id],
        #                        'Can edit dictionary options': [user_id]},
        #                   'roles_organizations':
        #                       {'Can resign users from perspective editors': [],
        #                        'Can create perspectives': [],
        #                        'Can merge dictionaries and perspectives': [],
        #                        'Can delete dictionary': [],
        #                        'Can create dictionary roles and assign collaborators': [],
        #                        'Can get dictionary role list': [],
        #                        'Can edit dictionary options': []}}
        # self.assertDictEqual(response.json, correct_answer)

    #     _________________________________________________________________________
    #     _________________________________________________________________________
    #     Tests on delete
    #     _________________________________________________________________________

        lang_ids = self.create_language('test_lang_del')
        dict_ids = self.create_dictionary('test_dict_del', lang_ids)
        persp_ids = self.create_perspective('test_persp_del', dict_ids)

        response = self.app.delete('/dictionary/%s/%s/perspective/%s/%s' %
                                   (dict_ids['client_id'], dict_ids['object_id'],
                                    persp_ids['client_id'], persp_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/dictionary/%s/%s/perspective/%s/%s' %
                                   (dict_ids['client_id'], dict_ids['object_id'],
                                    persp_ids['client_id'], persp_ids['object_id']),
                                status=HTTPNotFound.code)
        self.assertEqual(response.status_int, HTTPNotFound.code)

        response = self.app.delete('/dictionary/%s/%s' % (dict_ids['client_id'], dict_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/dictionary/%s/%s' % (dict_ids['client_id'], dict_ids['object_id']),
                                status=HTTPNotFound.code)
        self.assertEqual(response.status_int, HTTPNotFound.code)

        response = self.app.delete('/language/%s/%s' % (lang_ids['client_id'], lang_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        response = self.app.get('/language/%s/%s' % (lang_ids['client_id'], lang_ids['object_id']),
                                status=HTTPNotFound.code)
        self.assertEqual(response.status_int, HTTPNotFound.code)

    #     _________________________________________________________________________
        # test logout
        self.create_language('test_logout')
        response = self.app.post('/logout')

        self.assertEqual(response.status_int, HTTPFound.code)
        response = self.app.post_json('/language', params={'translation_string': 'test_logout'},
                                     status=HTTPForbidden.code)
        self.assertEqual(response.status_int, HTTPForbidden.code)

    def test_dict_lang_tree(self):
        user_id = self.signup_common()
        self.login_common()
        root_ids = self.create_language('Корень')
        first_child = self.create_language('Первый ребенок', root_ids)
        second_child = self.create_language('Второй ребенок', root_ids)
        dict_root = self.create_dictionary('Словарь корня', root_ids, 'Published')
        dict_first = self.create_dictionary('Словарь первого ребенка', first_child, 'Published')
        dict_second = self.create_dictionary('Словарь второго ребенка', second_child, 'Published')
        persp_root = self.create_perspective('Root Perspective', dict_root, 'Published')
        persp_first = self.create_perspective('1st Perspective', dict_first, 'Published')
        persp_second = self.create_perspective('2nd Perspective', dict_second, 'Published')
        empty_lang = self.create_language('Пустой язык', first_child)
        many_dicts_lang = self.create_language('Язык с многими словарями', empty_lang)
        complete_emptyness = self.create_language('Абсолютная пустота', second_child)
        many_dicts = list()
        for i in range(10):
            many_dicts += [self.create_dictionary('Словарь №%s' % i, many_dicts_lang, 'Published')]
        many_persps = list()
        i = 0
        for dict_ids in many_dicts:
            i += 1
            many_persps += [self.create_perspective('Перспектива №%s' % i, dict_ids, 'Published')]
        response = self.app.post_json('/published_dictionaries', params = {})
        self.assertEqual(response.status_int, HTTPOk.code)
        # TODO: change from numbers to ids, returned in previous responses.
        correct_answer = {'dictionaries': [{'translation_string': 'Словарь корня', 'parent_object_id': 1, 'object_id': 7, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь корня', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь первого ребенка', 'parent_object_id': 3, 'object_id': 9, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь первого ребенка', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь второго ребенка', 'parent_object_id': 5, 'object_id': 11, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь второго ребенка', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №0', 'parent_object_id': 21, 'object_id': 25, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №0', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №1', 'parent_object_id': 21, 'object_id': 27, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №1', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №2', 'parent_object_id': 21, 'object_id': 29, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №2', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №3', 'parent_object_id': 21, 'object_id': 31, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №3', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №4', 'parent_object_id': 21, 'object_id': 33, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №4', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №5', 'parent_object_id': 21, 'object_id': 35, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №5', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №6', 'parent_object_id': 21, 'object_id': 37, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №6', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №7', 'parent_object_id': 21, 'object_id': 39, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №7', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №8', 'parent_object_id': 21, 'object_id': 41, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №8', 'parent_client_id': 5, 'client_id': 5}, {'translation_string': 'Словарь №9', 'parent_object_id': 21, 'object_id': 43, 'additional_metadata': None, 'status': 'Published', 'translation': 'Словарь №9', 'parent_client_id': 5, 'client_id': 5}]}
        self.assertDictEqual(response.json, correct_answer)
        response = self.app.post_json('/published_dictionaries', params = {'group_by_lang':True})
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = [{'translation_string': 'Корень', 'translation': 'Корень', 'locale_exist': False, 'dicts': [{'translation_string': 'Словарь корня', 'parent_client_id': 5, 'translation': 'Словарь корня', 'client_id': 5, 'status': 'Published', 'object_id': 7, 'parent_object_id': 1, 'additional_metadata': None}], 'client_id': 5, 'contains': [{'translation_string': 'Первый ребенок', 'translation': 'Первый ребенок', 'locale_exist': False, 'dicts': [{'translation_string': 'Словарь первого ребенка', 'parent_client_id': 5, 'translation': 'Словарь первого ребенка', 'client_id': 5, 'status': 'Published', 'object_id': 9, 'parent_object_id': 3, 'additional_metadata': None}], 'client_id': 5, 'contains': [{'translation_string': 'Пустой язык', 'translation': 'Пустой язык', 'locale_exist': False, 'dicts': [], 'client_id': 5, 'contains': [{'translation_string': 'Язык с многими словарями', 'translation': 'Язык с многими словарями', 'locale_exist': False, 'dicts': [{'translation_string': 'Словарь №0', 'parent_client_id': 5, 'translation': 'Словарь №0', 'client_id': 5, 'status': 'Published', 'object_id': 25, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №1', 'parent_client_id': 5, 'translation': 'Словарь №1', 'client_id': 5, 'status': 'Published', 'object_id': 27, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №2', 'parent_client_id': 5, 'translation': 'Словарь №2', 'client_id': 5, 'status': 'Published', 'object_id': 29, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №3', 'parent_client_id': 5, 'translation': 'Словарь №3', 'client_id': 5, 'status': 'Published', 'object_id': 31, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №4', 'parent_client_id': 5, 'translation': 'Словарь №4', 'client_id': 5, 'status': 'Published', 'object_id': 33, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №5', 'parent_client_id': 5, 'translation': 'Словарь №5', 'client_id': 5, 'status': 'Published', 'object_id': 35, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №6', 'parent_client_id': 5, 'translation': 'Словарь №6', 'client_id': 5, 'status': 'Published', 'object_id': 37, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №7', 'parent_client_id': 5, 'translation': 'Словарь №7', 'client_id': 5, 'status': 'Published', 'object_id': 39, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №8', 'parent_client_id': 5, 'translation': 'Словарь №8', 'client_id': 5, 'status': 'Published', 'object_id': 41, 'parent_object_id': 21, 'additional_metadata': None}, {'translation_string': 'Словарь №9', 'parent_client_id': 5, 'translation': 'Словарь №9', 'client_id': 5, 'status': 'Published', 'object_id': 43, 'parent_object_id': 21, 'additional_metadata': None}], 'client_id': 5, 'object_id': 21}], 'object_id': 19}], 'object_id': 3}, {'translation_string': 'Второй ребенок', 'translation': 'Второй ребенок', 'locale_exist': False, 'dicts': [{'translation_string': 'Словарь второго ребенка', 'parent_client_id': 5, 'translation': 'Словарь второго ребенка', 'client_id': 5, 'status': 'Published', 'object_id': 11, 'parent_object_id': 5, 'additional_metadata': None}], 'client_id': 5, 'object_id': 5}], 'object_id': 1}]
        self.assertListEqual(response.json, correct_answer)
        response = self.app.get('/perspectives')
        self.assertEqual(response.status_int, HTTPOk.code)
        correct_answer = {'perspectives': [{'is_template': True, 'translation_string': 'Lingvodoc desktop version', 'marked_for_deletion': False, 'translation': 'Lingvodoc desktop version', 'client_id': 1, 'additional_metadata': None, 'status': 'Service', 'object_id': 7, 'parent_client_id': 1, 'parent_object_id': 6}, {'is_template': True, 'translation_string': 'Regular dictionary', 'marked_for_deletion': False, 'translation': 'Regular dictionary', 'client_id': 1, 'additional_metadata': None, 'status': 'Service', 'object_id': 19, 'parent_client_id': 1, 'parent_object_id': 6}, {'is_template': True, 'translation_string': 'Morhological dictionary', 'marked_for_deletion': False, 'translation': 'Morhological dictionary', 'client_id': 1, 'additional_metadata': None, 'status': 'Service', 'object_id': 36, 'parent_client_id': 1, 'parent_object_id': 6}, {'is_template': False, 'translation_string': 'Root Perspective', 'marked_for_deletion': False, 'translation': 'Root Perspective', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 13, 'parent_client_id': 5, 'parent_object_id': 7}, {'is_template': False, 'translation_string': '1st Perspective', 'marked_for_deletion': False, 'translation': '1st Perspective', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 15, 'parent_client_id': 5, 'parent_object_id': 9}, {'is_template': False, 'translation_string': '2nd Perspective', 'marked_for_deletion': False, 'translation': '2nd Perspective', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 17, 'parent_client_id': 5, 'parent_object_id': 11}, {'is_template': False, 'translation_string': 'Перспектива №1', 'marked_for_deletion': False, 'translation': 'Перспектива №1', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 45, 'parent_client_id': 5, 'parent_object_id': 25}, {'is_template': False, 'translation_string': 'Перспектива №2', 'marked_for_deletion': False, 'translation': 'Перспектива №2', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 47, 'parent_client_id': 5, 'parent_object_id': 27}, {'is_template': False, 'translation_string': 'Перспектива №3', 'marked_for_deletion': False, 'translation': 'Перспектива №3', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 49, 'parent_client_id': 5, 'parent_object_id': 29}, {'is_template': False, 'translation_string': 'Перспектива №4', 'marked_for_deletion': False, 'translation': 'Перспектива №4', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 51, 'parent_client_id': 5, 'parent_object_id': 31}, {'is_template': False, 'translation_string': 'Перспектива №5', 'marked_for_deletion': False, 'translation': 'Перспектива №5', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 53, 'parent_client_id': 5, 'parent_object_id': 33}, {'is_template': False, 'translation_string': 'Перспектива №6', 'marked_for_deletion': False, 'translation': 'Перспектива №6', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 55, 'parent_client_id': 5, 'parent_object_id': 35}, {'is_template': False, 'translation_string': 'Перспектива №7', 'marked_for_deletion': False, 'translation': 'Перспектива №7', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 57, 'parent_client_id': 5, 'parent_object_id': 37}, {'is_template': False, 'translation_string': 'Перспектива №8', 'marked_for_deletion': False, 'translation': 'Перспектива №8', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 59, 'parent_client_id': 5, 'parent_object_id': 39}, {'is_template': False, 'translation_string': 'Перспектива №9', 'marked_for_deletion': False, 'translation': 'Перспектива №9', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 61, 'parent_client_id': 5, 'parent_object_id': 41}, {'is_template': False, 'translation_string': 'Перспектива №10', 'marked_for_deletion': False, 'translation': 'Перспектива №10', 'client_id': 5, 'additional_metadata': '{}', 'status': 'Published', 'object_id': 63, 'parent_client_id': 5, 'parent_object_id': 43}]}
        self.assertDictEqual(response.json, correct_answer)

    def test_user_blobs(self):
        import hashlib
        self.signup_common()
        self.login_common()
        first_hash = hashlib.md5(open("test_user_blobs.pdf", 'rb').read()).hexdigest()
        response = self.app.post('/blob', params = {'data_type':'pdf'},
                                 upload_files=([('blob', 'test_user_blobs.pdf')]))
        self.assertEqual(response.status_int, HTTPOk.code)
        blob_ids = response.json
        response = self.app.get('/blobs/%s/%s' % (blob_ids['client_id'],
                                                          blob_ids['object_id']))
        self.assertEqual(response.status_int, HTTPOk.code)
        file_response = self.app.get(response.json['content'])
        second_hash = hashlib.md5(file_response.body).hexdigest()
        self.assertEqual(first_hash, second_hash)

    def test_ids(self):
        import hashlib
        self.signup_common()
        self.login_common()
        ids = []
        for i in range(12):
            root_ids = self.create_language('Корень %i' % i)
            ids += [root_ids]
            ids += [self.create_dictionary('Словарь корня %i' % i, root_ids, 'Published')]
        correct = [{'object_id': 1, 'client_id': 5}, {'object_id': 3, 'client_id': 5}, {'object_id': 5, 'client_id': 5}, {'object_id': 7, 'client_id': 5}, {'object_id': 9, 'client_id': 5}, {'object_id': 11, 'client_id': 5}, {'object_id': 13, 'client_id': 5}, {'object_id': 15, 'client_id': 5}, {'object_id': 17, 'client_id': 5}, {'object_id': 19, 'client_id': 5}, {'object_id': 21, 'client_id': 5}, {'object_id': 23, 'client_id': 5}, {'object_id': 25, 'client_id': 5}, {'object_id': 27, 'client_id': 5}, {'object_id': 29, 'client_id': 5}, {'object_id': 31, 'client_id': 5}, {'object_id': 33, 'client_id': 5}, {'object_id': 35, 'client_id': 5}, {'object_id': 37, 'client_id': 5}, {'object_id': 39, 'client_id': 5}, {'object_id': 41, 'client_id': 5}, {'object_id': 43, 'client_id': 5}, {'object_id': 45, 'client_id': 5}, {'object_id': 47, 'client_id': 5}]
        self.assertListEqual(ids, correct, set_like=True)


class TestHelperFuncs(unittest.TestCase):

    def test_dict_diff_empty(self):
        d1 = {}
        d2 = {}
        self.assertEqual(dict_diff(d1, d2), True)

    def test_dict_diff_not_eq(self):
        d1 = {'a':'b'}
        d2 = {'b':'a'}
        self.assertNotEqual(dict_diff(d1, d2), True)

    def test_dict_diff_with_dicts_help(self):
        d1 =  {'b':'c','d':'e'}
        d2 = {'d':'e','b':'c'}
        self.assertEqual(dict_diff(d1, d2), True)

    def test_dict_diff_with_dicts(self):
        d1 = {'a': {'b':'c','d':'e'}}
        d2 = {'a':  {'d':'e','b':'c'}}
        self.assertEqual(dict_diff(d1, d2), True)

    def test_dict_diff_with_lists(self):
        d1 = {'a': {'b':'c','d':'e'}, 'f':['g', {'i':'j', 'k':'l', 'm':'n', 'o':'p'}, 'q']}
        d2 = {'a':  {'d':'e','b':'c'}, 'f':['g', {'i':'j', 'o':'p', 'k':'l', 'm':'n'}, 'q']}
        self.assertEqual(dict_diff(d1, d2), True)

    def test_dict_diff_with_lists_not_eq(self):
        d1 = {'a': {'b':'c','d':'e'}, 'f':['q', {'i':'j', 'k':'l', 'm':'n', 'o':'p'}, 'g']}
        d2 = {'a':  {'d':'e','b':'c'}, 'f':['g', {'i':'j', 'o':'p', 'k':'l', 'm':'n'}, 'q']}
        self.assertNotEqual(dict_diff(d1, d2), True)

    def test_dict_diff_not_eq_2(self):
        d1 = {'is_template': True, 'client_id': 3, 'parent_object_id': 1, 'object_id': 1, 'status': 'WiP', 'translation': 'new_translation', 'translation_string': 'test_persp', 'additional_metadata': '{}', 'marked_for_deletion': False, 'parent_client_id': 1}
        d2 = {'client_id': 3, 'object_id': 1,
                          'locale_exist': False, 'translation': 'new_translation',
                          'parent_client_id': 1,
                          'translation_string': 'test_child',
                          'parent_object_id': 1}
        self.assertNotEqual(dict_diff(d1, d2), True)

    def test_dict_diff_set_like(self):
        d1 = {'words': [{'lexical_entry': {'came_from': None, 'object_id': 2, 'parent_client_id': 5, 'client_id': 11, 'level': 'lexicalentry', 'contains': [{'marked_for_deletion': False, 'published': False, 'parent_object_id': 2, 'locale_id': None, 'parent_client_id': 11, 'contains': None, 'entity_type': 'Etymology', 'level': 'groupingentity', 'object_id': 1, 'additional_metadata': None, 'content': 'Wed Feb 10 14:26:14 2016G6599C1A8X', 'client_id': 11}, {'marked_for_deletion': False, 'published': False, 'parent_object_id': 2, 'locale_id': 1, 'parent_client_id': 11, 'contains': None, 'entity_type': 'Word', 'level': 'leveloneentity', 'object_id': 2, 'additional_metadata': None, 'content': "grouping word {'object_id': 2, 'client_id': 11}", 'client_id': 11}], 'published': False, 'marked_for_deletion': False, 'parent_object_id': 1}}, {'lexical_entry': {'came_from': None, 'object_id': 3, 'parent_client_id': 5, 'client_id': 11, 'level': 'lexicalentry', 'contains': [{'marked_for_deletion': False, 'published': False, 'parent_object_id': 3, 'locale_id': None, 'parent_client_id': 11, 'contains': None, 'entity_type': 'Etymology', 'level': 'groupingentity', 'object_id': 2, 'additional_metadata': None, 'content': 'Wed Feb 10 14:26:14 2016G6599C1A8X', 'client_id': 11}, {'marked_for_deletion': False, 'published': False, 'parent_object_id': 3, 'locale_id': 1, 'parent_client_id': 11, 'contains': None, 'entity_type': 'Word', 'level': 'leveloneentity', 'object_id': 3, 'additional_metadata': None, 'content': "grouping word {'object_id': 3, 'client_id': 11}", 'client_id': 11}], 'published': False, 'marked_for_deletion': False, 'parent_object_id': 1}}]}
        d2 = {'words': [{'lexical_entry': {'came_from': None, 'marked_for_deletion': False, 'parent_client_id': 5, 'parent_object_id': 1, 'level': 'lexicalentry', 'object_id': 2, 'published': False, 'contains': [{'contains': None, 'published': False, 'parent_object_id': 2, 'marked_for_deletion': False, 'locale_id': 1, 'parent_client_id': 11, 'entity_type': 'Word', 'level': 'leveloneentity', 'object_id': 2, 'additional_metadata': None, 'content': "grouping word {'object_id': 2, 'client_id': 11}", 'client_id': 11}, {'contains': None, 'published': False, 'parent_object_id': 2, 'marked_for_deletion': False, 'locale_id': None, 'parent_client_id': 11, 'entity_type': 'Etymology', 'level': 'groupingentity', 'object_id': 1, 'additional_metadata': None, 'content': 'Wed Feb 10 13:50:08 2016MNAZGRV22A', 'client_id': 11}], 'client_id': 11}}, {'lexical_entry': {'came_from': None, 'marked_for_deletion': False, 'parent_client_id': 5, 'parent_object_id': 1, 'level': 'lexicalentry', 'object_id': 3, 'published': False, 'contains': [{'contains': None, 'published': False, 'parent_object_id': 3, 'marked_for_deletion': False, 'locale_id': 1, 'parent_client_id': 11, 'entity_type': 'Word', 'level': 'leveloneentity', 'object_id': 3, 'additional_metadata': None, 'content': "grouping word {'object_id': 3, 'client_id': 11}", 'client_id': 11}, {'contains': None, 'published': False, 'parent_object_id': 3, 'marked_for_deletion': False, 'locale_id': None, 'parent_client_id': 11, 'entity_type': 'Etymology', 'level': 'groupingentity', 'object_id': 2, 'additional_metadata': None, 'content': 'Wed Feb 10 13:50:08 2016MNAZGRV22A', 'client_id': 11}], 'client_id': 11}}]}

        self.assertEqual(dict_diff(d1, d2, stop_words=['content'], set_like=True), True)

