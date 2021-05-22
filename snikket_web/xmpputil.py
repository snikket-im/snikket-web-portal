import base64
import typing

import xml.etree.ElementTree as ET

from quart import abort
import quart.exceptions


TAG_XMPP_ERROR = "error"

NS_XMPP_ERROR_CONDITION = "urn:ietf:params:xml:ns:xmpp-stanzas"
TAG_XMPP_ERROR_ITEM_NOT_FOUND = \
    "{{{}}}item-not-found".format(NS_XMPP_ERROR_CONDITION)
TAG_XMPP_ERROR_TEXT = "{{{}}}text".format(NS_XMPP_ERROR_CONDITION)

ERROR_CODE_MAP = {
    TAG_XMPP_ERROR_ITEM_NOT_FOUND: 404,
}

NS_PUBSUB = "http://jabber.org/protocol/pubsub"
NS_PUBSUB_OWNER = "http://jabber.org/protocol/pubsub#owner"
TAG_PUBSUB = "{{{}}}pubsub".format(NS_PUBSUB)
TAG_PUBSUB_OWNER = "{{{}}}pubsub".format(NS_PUBSUB_OWNER)
TAG_PUBSUB_ITEM = "{{{}}}item".format(NS_PUBSUB)
TAG_PUBSUB_ITEMS = "{{{}}}items".format(NS_PUBSUB)
TAG_PUBSUB_CONFIGURE = "{{{}}}configure".format(NS_PUBSUB_OWNER)

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

NODE_VCARD = "urn:xmpp:vcard4"

NS_DATA_FORM = "jabber:x:data"
TAG_DATA_FORM_X = "{{{}}}x".format(NS_DATA_FORM)
TAG_DATA_FORM_FIELD = "{{{}}}field".format(NS_DATA_FORM)
TAG_DATA_FORM_VALUE = "{{{}}}value".format(NS_DATA_FORM)

FORM_NODE_CONFIG = "http://jabber.org/protocol/pubsub#node_config"
FORM_FIELD_PUBSUB_ACCESS_MODEL = "pubsub#access_model"


SimpleJID = typing.Tuple[typing.Optional[str], str, typing.Optional[str]]
T = typing.TypeVar("T")


def split_jid(s: str) -> SimpleJID:
    resource: typing.Optional[str]
    localpart: typing.Optional[str]
    bare, sep, resource = s.partition("/")
    if not sep:
        resource = None
    localpart, sep, domain = bare.partition("@")
    if not sep:
        domain = localpart
        localpart = None
    return localpart, domain, resource


def raise_iq_error(err: ET.Element) -> None:
    err_condition_el = None
    # err_text_el = None
    # err_app_def_condition_el = None

    for el in err:
        if el.tag == TAG_XMPP_ERROR_TEXT:
            # err_text_el = el
            continue
        elif el.tag.startswith("{{{}}}".format(NS_XMPP_ERROR_CONDITION)):
            err_condition_el = el
        # else:
        #     err_app_def_condition_el = el

    if err_condition_el is None:
        condition_tag = "undefined-condition"
    else:
        condition_tag = err_condition_el.tag

    # print(err_text_el, err_condition_el, err_app_def_condition_el)
    abort(ERROR_CODE_MAP.get(condition_tag, 500), condition_tag)


def extract_iq_reply(
        tree: ET.Element,
        require_tag: typing.Optional[str] = None,
        ) -> typing.Optional[ET.Element]:
    iq_type = tree.get("type")
    if iq_type == "error":
        error = tree.find(TAG_XMPP_ERROR)
        if error is not None:
            raise_iq_error(error)
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


def make_password_change_request(jid: str, password: str) -> ET.Element:
    username, domain, _ = split_jid(jid)
    # XXX: this is due to a problem with mod_rest / mod_register in prosody:
    # it doesn’t recognize the password change stanza unless we send it to
    # the account JID.
    req = ET.Element("iq", to="{}@{}".format(username, domain), type="set")
    q = ET.SubElement(req, "query", xmlns="jabber:iq:register")
    ET.SubElement(q, "username").text = username
    ET.SubElement(q, "password").text = password
    return req


def make_pubsub_item_put_request(
        to: str, node: str,
        id_: typing.Optional[str] = None,
        ) -> typing.Tuple[ET.Element, ET.Element]:
    req = ET.Element("iq", type="set", to=to)
    q = ET.SubElement(req, "pubsub", xmlns=NS_PUBSUB)
    publish = ET.SubElement(q, "publish", node=node)
    item = ET.SubElement(publish, "item")
    if id_ is not None:
        item.set("id", id_)
    return req, item


def make_nickname_set_request(to: str, nickname: str) -> ET.Element:
    req, item = make_pubsub_item_put_request(
        to,
        NODE_USER_NICKNAME,
    )
    ET.SubElement(item, "nick", xmlns=NS_USER_NICKNAME).text = nickname
    return req


def make_pubsub_item_request(
        to: str,
        node: str,
        id_: typing.Optional[str] = None,
        ) -> ET.Element:
    req = ET.Element("iq", type="get", to=to)
    q = ET.SubElement(req, "pubsub", xmlns=NS_PUBSUB)
    items = ET.SubElement(q, "items", node=node)
    if id_ is not None:
        ET.SubElement(items, "item", id=id_)
    else:
        items.set("max_items", "1")

    return req


def make_nickname_get_request(to: str) -> ET.Element:
    return make_pubsub_item_request(to, NODE_USER_NICKNAME)


def make_avatar_metadata_request(to: str) -> ET.Element:
    return make_pubsub_item_request(to, NODE_USER_AVATAR_METADATA)


def make_avatar_data_request(to: str, sha1: str) -> ET.Element:
    return make_pubsub_item_request(to, NODE_USER_AVATAR_DATA, id_=sha1)


def make_avatar_data_set_request(
        to: str,
        data: bytes,
        id_: str,
        ) -> ET.Element:
    req, item = make_pubsub_item_put_request(
        to,
        NODE_USER_AVATAR_DATA,
        id_=id_,
    )
    ET.SubElement(item, "data", xmlns=NS_USER_AVATAR_DATA).text = \
        base64.b64encode(data).decode("ascii")
    return req


def make_avatar_metadata_set_request(
        to: str,
        mimetype: str,
        id_: str,
        size: int,
        width: typing.Optional[int] = None,
        height: typing.Optional[int] = None,
        ) -> ET.Element:
    req, item = make_pubsub_item_put_request(
        to,
        NODE_USER_AVATAR_METADATA,
        id_=id_,
    )
    metadata_wrap = ET.SubElement(
        item,
        "metadata", xmlns=NS_USER_AVATAR_METADATA)

    attr: typing.MutableMapping[str, str] = {
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
        raise abort(500, "malformed reply: missing {}".format(tag))
    return el


def extract_pubsub_item_get_reply(
        iq_tree: ET.Element,
        payload_tag: str,
        ) -> typing.Optional[ET.Element]:
    try:
        pubsub = extract_iq_reply(iq_tree, TAG_PUBSUB)
    except quart.exceptions.NotFound:
        return None

    if pubsub is None:
        # no payload in IQ reply
        raise abort(500, "malformed reply")

    items = _require_child(pubsub, TAG_PUBSUB_ITEMS)
    if len(items) == 0:
        return None

    return _require_child(_require_child(items, TAG_PUBSUB_ITEM), payload_tag)


def extract_nickname_get_reply(iq_tree: ET.Element) -> typing.Optional[str]:
    nick = extract_pubsub_item_get_reply(iq_tree, TAG_USER_NICKNAME_NICK)
    if nick is None:
        return None
    return nick.text


def extract_avatar_metadata_get_reply(
        iq_tree: ET.Element,
        ) -> typing.Optional[typing.MutableMapping[str, typing.Any]]:
    metadata = extract_pubsub_item_get_reply(iq_tree, TAG_USER_AVATAR_METADATA)
    if metadata is None:
        return None

    if len(metadata) != 1 or metadata[0].tag != TAG_USER_AVATAR_METADATA_INFO:
        # raise an error instead?
        return None

    info = metadata[0]
    attrs = info.attrib
    result: typing.MutableMapping[str, typing.Optional[str]] = {
        "sha1": attrs["id"],
        "type": attrs.get("type", "image/png"),
    }

    def extract_optional(
            key: str,
            type_: typing.Callable[[str], typing.Any] = lambda x: int(x),
            ) -> None:
        try:
            result[key] = type_(attrs[key])
        except (KeyError, ValueError, TypeError):
            pass

    extract_optional("width")
    extract_optional("height")
    extract_optional("bytes")

    return result


def extract_avatar_data_get_reply(
        iq_tree: ET.Element,
        ) -> typing.Optional[bytes]:
    data = extract_pubsub_item_get_reply(iq_tree, TAG_USER_AVATAR_DATA)
    if data is None or data.text is None:
        return None
    return base64.b64decode(data.text)


def make_pubsub_node_config_put_request(
        to: str, node: str,
        id_: typing.Optional[str] = None,
        ) -> typing.Tuple[ET.Element, ET.Element]:
    req = ET.Element("iq", type="set", to=to)
    q = ET.SubElement(req, "pubsub", xmlns=NS_PUBSUB_OWNER)
    configure = ET.SubElement(q, "configure", node=node)
    form = ET.SubElement(configure, "x",
                         xmlns=NS_DATA_FORM,
                         type="submit")
    form_type = ET.SubElement(form, "field", var="FORM_TYPE", type="hidden")
    ET.SubElement(form_type, "value").text = FORM_NODE_CONFIG
    return req, form


def make_pubsub_node_config_get_request(
        to: str, node: str,
        ) -> ET.Element:
    req = ET.Element("iq", type="get", to=to)
    q = ET.SubElement(req, "pubsub", xmlns=NS_PUBSUB_OWNER)
    ET.SubElement(q, "configure", node=node)
    return req


def add_form_field(
        form: ET.Element,
        var: str,
        values: typing.Union[str, typing.Collection[str]],
        type_: typing.Optional[str] = None,
        ) -> ET.Element:
    if isinstance(values, str):
        values = [values]
    field = ET.SubElement(form, "field", var=var)
    if type_ is not None:
        field.set("type", type_)
    for v in values:
        ET.SubElement(field, "value").text = v
    return field


def make_pubsub_access_model_put_request(
        to: str,
        node: str,
        new_access_model: str,
        ) -> ET.Element:
    req, form = make_pubsub_node_config_put_request(to, node)
    add_form_field(form, FORM_FIELD_PUBSUB_ACCESS_MODEL, new_access_model)
    return req


def extract_pubsub_node_config_get_reply(
        iq_tree: ET.Element,
        ) -> typing.Mapping[str, typing.Sequence[str]]:
    payload = extract_iq_reply(iq_tree)
    if payload is None:
        raise ValueError("invalid reply")
    form = _require_child(_require_child(payload, TAG_PUBSUB_CONFIGURE),
                          TAG_DATA_FORM_X)
    result: typing.MutableMapping[str, typing.List[str]] = {}
    for child in form.findall(TAG_DATA_FORM_FIELD):
        var = child.get("var")
        if var is None:
            continue
        values = [value_tag.text or ""
                  for value_tag in child.findall(TAG_DATA_FORM_VALUE)]
        result[var] = values

    return result
