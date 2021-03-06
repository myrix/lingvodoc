__author__ = 'alexander'

from lingvodoc.models import (
    DBSession,
    Entity,
    Field,
    ObjectTOC
)

from pyramid.httpexceptions import (
    HTTPNotFound,
    HTTPOk,
    HTTPBadRequest
)
from pyramid.view import view_config
from lingvodoc.views.v2.delete import real_delete_entity

# TODO: completely broken!
@view_config(route_name='get_group_entity', renderer='json', request_method='GET')
def view_group_entity(request):
    response = dict()
    client_id = request.matchdict.get('client_id')
    object_id = request.matchdict.get('object_id')

    # entity = DBSession.query(GroupingEntity).filter_by(client_id=client_id, object_id=object_id).first()
    entity = None
    if entity:
        if not entity.marked_for_deletion:
            ent = dict()
            ent['entity_type'] = entity.entity_type
            ent['tag'] = entity.content
            entities2 = DBSession.query(Entity).join(Entity.field).filter(Entity.content == entity.content,
                                                                          Field.field.data_type == 'Grouping Tag',
                                                                          marked_for_deletion=False).all()
            # entities2 = list()
            objs = []
            for entry in entities2:
                obj = {'client_id': entry.parent_client_id, 'object_id': entry.parent_object_id}
                if obj not in objs:
                    objs += [obj]
            ent['connections'] = objs
            response = ent
            request.response.status = HTTPOk.code
            return response
    request.response.status = HTTPNotFound.code
    return {'error': str("No entities in the system")}


@view_config(route_name='get_group_entity', renderer='json', request_method='DELETE', permission='delete')
def delete_group_entity(request):  # TODO: test
    response = dict()
    client_id = request.matchdict.get('client_id')
    object_id = request.matchdict.get('object_id')
    req = request.json_body
    field_client_id = req['field_client_id']
    field_object_id = req['field_object_id']
    field = DBSession.query(Field).filter_by(client_id=field_client_id,
                                             object_id=field_object_id).first()
    if not field:
        request.response.status = HTTPNotFound.code
        return {'error': str("No such field in the system")}
    elif field.data_type != 'Grouping Tag':
        request.response.status = HTTPBadRequest.code
        return {'error': str("Wrong type of field")}

    entities = DBSession.query(Entity).filter_by(field_client_id=field_client_id,
                                                 field_object_id=field_object_id,
                                                 parent_client_id=client_id,
                                                 parent_object_id=object_id, marked_for_deletion=False).all()
    if entities:
        for entity in entities:
            if 'desktop' in request.registry.settings:
                real_delete_entity(entity, request.registry.settings)
            else:
                entity.marked_for_deletion = True
                objecttoc = DBSession.query(ObjectTOC).filter_by(client_id=entity.client_id,
                                                                 object_id=entity.object_id).one()
                objecttoc.marked_for_deletion = True
        request.response.status = HTTPOk.code
        return response
    request.response.status = HTTPNotFound.code
    return {'error': str("No such entity in the system")}
