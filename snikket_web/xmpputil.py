import base64
import binascii
import typing

import xml.etree.ElementTree as ET

from quart import abort
import quart.exceptions


TAG_XMPP_ERROR = "error"

NS_XMPP_ERROR_CONDITION = "urn:ietf:params:xml:ns:xmpp-stanzas"
TAG_XMPP_ERROR_ITEM_NOT_FOUND = "{{{}}}item-not-found".format(NS_XMPP_ERROR_CONDITION)
TAG_XMPP_ERROR_TEXT = "{{{}}}text".format(NS_XMPP_ERROR_CONDITION)

ERROR_CODE_MAP = {
    TAG_XMPP_ERROR_ITEM_NOT_FOUND: 404,
}

NS_PUBSUB = "http://jabber.org/protocol/pubsub"
TAG_PUBSUB = "{{{}}}pubsub".format(NS_PUBSUB)
TAG_PUBSUB_ITEM = "{{{}}}item".format(NS_PUBSUB)
TAG_PUBSUB_ITEMS = "{{{}}}items".format(NS_PUBSUB)

NS_USER_NICKNAME = "http://jabber.org/protocol/nick"
NODE_USER_NICKNAME = NS_USER_NICKNAME
TAG_USER_NICKNAME_NICK = "{{{}}}nick".format(NS_USER_NICKNAME)

NODE_USER_AVATAR_METADATA = "urn:xmpp:avatar:metadata"
NS_USER_AVATAR_METADATA = "urn:xmpp:avatar:metadata"
TAG_USER_AVATAR_METADATA = "{{{}}}metadata".format(NS_USER_AVATAR_METADATA)
TAG_USER_AVATAR_METADATA_INFO = "{{{}}}info".format(NS_USER_AVATAR_METADATA)

NODE_USER_AVATAR_DATA = "urn:xmpp:avatar:data"
NS_USER_AVATAR_DATA = "urn:xmpp:avatar:data"
TAG_USER_AVATAR_DATA = "{{{}}}data".format(NS_USER_AVATAR_DATA)


def split_jid(s):
    bare, sep, resource = s.partition("/")
    if not sep:
        resource = None
    localpart, sep, domain = bare.partition("@")
    if not sep:
        domain = localpart
        localpart = None
    return localpart, domain, resource


def raise_iq_error(err: ET.Element):
    err_condition_el = None
    err_text_el = None
    err_app_def_condition_el = None

    for el in err:
        if el.tag == TAG_XMPP_ERROR_TEXT:
            err_text_el = el
        elif el.tag.startswith("{{{}}}".format(NS_XMPP_ERROR_CONDITION)):
            err_condition_el = el
        else:
            err_app_def_condition_el = el

    print(err_text_el, err_condition_el, err_app_def_condition_el)

    abort(ERROR_CODE_MAP.get(err_condition_el.tag, 500),
          err_condition_el.tag)


def extract_iq_reply(tree: ET.Element,
                     require_tag: str = None) -> typing.Optional[ET.Element]:
    iq_type = tree.get("type")
    if iq_type == "error":
        error = tree.find(TAG_XMPP_ERROR)
        if error is not None:
            raise raise_iq_error(error)
        raise abort(500, "malformed reply")
    elif iq_type == "result":
        if len(tree) > 0:
            reply_el = tree[0]
            if require_tag and reply_el.tag != require_tag:
                raise abort(500, "unexpected reply")
            return reply_el
        if require_tag:
            raise abort(500, "unexpected reply")
        return None
    else:
        raise abort(500, "unsupported reply")


def make_password_change_request(jid, password):
    username, domain, _ = split_jid(jid)
    # XXX: this is due to a problem with mod_rest / mod_register in prosody:
    # it doesn’t recognize the password change stanza unless we send it to
    # the account JID.
    req = ET.Element("iq", to="{}@{}".format(username, domain), type="set")
    q = ET.SubElement(req, "query", xmlns="jabber:iq:register")
    ET.SubElement(q, "username").text = username
    ET.SubElement(q, "password").text = password
    return req


def make_pubsub_item_put_request(to, node, id_=None):
    req = ET.Element("iq", type="set", to=to)
    q = ET.SubElement(req, "pubsub", xmlns=NS_PUBSUB)
    publish = ET.SubElement(q, "publish", node=node)
    item = ET.SubElement(publish, "item")
    if id_ is not None:
        item.set("id", id_)
    return req, item


def make_nickname_set_request(to, nickname):
    req, item = make_pubsub_item_put_request(
        to,
        NODE_USER_NICKNAME,
    )
    ET.SubElement(item, "nick", xmlns=NS_USER_NICKNAME).text = nickname
    return req


def make_pubsub_item_request(to, node, id_=None):
    req = ET.Element("iq", type="get", to=to)
    q = ET.SubElement(req, "pubsub", xmlns=NS_PUBSUB)
    items = ET.SubElement(q, "items", node=node)
    if id_ is not None:
        ET.SubElement(items, "item", id=id_)
    else:
        items.set("max_items", "1")

    return req


def make_nickname_get_request(to):
    return make_pubsub_item_request(to, NODE_USER_NICKNAME)


def make_avatar_metadata_request(to):
    return make_pubsub_item_request(to, NODE_USER_AVATAR_METADATA)


def make_avatar_data_request(to, sha1):
    return make_pubsub_item_request(to, NODE_USER_AVATAR_DATA, id_=sha1)


def make_avatar_data_set_request(to, data, id_):
    req, item = make_pubsub_item_put_request(
        to,
        NODE_USER_AVATAR_DATA,
        id_=id_,
    )
    ET.SubElement(item, "data", xmlns=NS_USER_AVATAR_DATA).text = \
        base64.b64encode(data).decode("ascii")
    return req


def make_avatar_metadata_set_request(to, mimetype: str, id_: str, size: int,
                                     width: int = None,
                                     height: int = None):
    req, item = make_pubsub_item_put_request(
        to,
        NODE_USER_AVATAR_METADATA,
        id_=id_,
    )
    metadata_wrap = ET.SubElement(
        item,
        "metadata", xmlns=NS_USER_AVATAR_METADATA)

    attr = {
        "id": id_,
        "bytes": str(size),
        "type": mimetype,
    }
    if width is not None:
        attr["width"] = str(width)
    if height is not None:
        attr["height"] = str(height)

    ET.SubElement(metadata_wrap, "info", xmlns=NS_USER_AVATAR_METADATA, **attr)
    return req


def _require_child(t: ET.Element, tag: str) -> ET.Element:
    el = t.find(tag)
    if el is None:
        raise abort(500, "malformed reply")
    return el


def extract_pubsub_item_get_reply(iq_tree, payload_tag):
    try:
        pubsub = extract_iq_reply(iq_tree, TAG_PUBSUB)
    except quart.exceptions.NotFound:
        return None

    items = _require_child(pubsub, TAG_PUBSUB_ITEMS)
    if len(items) == 0:
        return None

    return _require_child(_require_child(items, TAG_PUBSUB_ITEM), payload_tag)


def extract_nickname_get_reply(iq_tree):
    nick = extract_pubsub_item_get_reply(iq_tree, TAG_USER_NICKNAME_NICK)
    if nick is None:
        return None
    return nick.text


def extract_avatar_metadata_get_reply(iq_tree):
    metadata = extract_pubsub_item_get_reply(iq_tree, TAG_USER_AVATAR_METADATA)
    if metadata is None:
        return None

    if len(metadata) != 1 or metadata[0].tag != TAG_USER_AVATAR_METADATA_INFO:
        # raise an error instead?
        return None

    info = metadata[0]
    attrs = info.attrib
    result = {
        "sha1": attrs["id"],
        "type": attrs.get("type", "image/png"),
    }

    def extract_optional(key, type_=int):
        try:
            result[key] = type_(attrs[key])
        except (KeyError, ValueError, TypeError):
            pass

    extract_optional("width")
    extract_optional("height")
    extract_optional("bytes")

    return result


def extract_avatar_data_get_reply(iq_tree):
    data = extract_pubsub_item_get_reply(iq_tree, TAG_USER_AVATAR_DATA)
    if data.text is None:
        return None
    return base64.b64decode(data.text)
