import logging
import tempfile
from pyramid.view import view_config
from pyramid.httpexceptions import (
    HTTPOk,
    HTTPNotFound,
    HTTPError,
    HTTPBadRequest
)
import tempfile
from lingvodoc.scripts import elan_parser
from urllib import request


@view_config(route_name='convert_five_tiers_validate', renderer='json', request_method='POST')
def convert_dictionary(req):  # TODO: test
    log = logging.getLogger(__name__)
    try:
        eaf_url = req.json_body['eaf_url']
        result = False
        eaffile = request.urlopen(eaf_url)
    except HTTPError as e:
        req.response.status = HTTPError.code
        return {'error': str(e)}
    except KeyError as e:
        req.response.status = HTTPBadRequest.code
        return {'error': str(e)}
    with tempfile.NamedTemporaryFile() as temp:
        temp.write(eaffile.read())
        elan_check = elan_parser.ElanCheck(temp.name)
        elan_check.parse()
        if elan_check.check():
            result = True
        temp.flush()
    req.response.status = HTTPOk.code
    return {"is_valid": result}



