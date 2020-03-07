import typing

import xml.etree.ElementTree as ET

from quart import abort
import quart.exceptions


TAG_XMPP_ERROR = "error"

NS_XMPP_ERROR_CONDITION = "urn:ietf:params:xml:ns:xmpp-stanzas"
TAG_XMPP_ERROR_ITEM_NOT_FOUND = "{{{}}}item-not-found".format(NS_XMPP_ERROR_CONDITION)
TAG_XMPP_ERROR_TEXT =  "{{{}}}text".format(TAG_XMPP_ERROR_ITEM_NOT_FOUND)

ERROR_CODE_MAP = {
    TAG_XMPP_ERROR_ITEM_NOT_FOUND: 404,
}

NS_PUBSUB = "http://jabber.org/protocol/pubsub"
TAG_PUBSUB = "{{{}}}pubsub".format(NS_PUBSUB)
TAG_PUBSUB_ITEM = "{{{}}}item".format(NS_PUBSUB)
TAG_PUBSUB_ITEMS = "{{{}}}items".format(NS_PUBSUB)

NS_USER_NICKNAME = "http://jabber.org/protocol/nick"
TAG_USER_NICKNAME_NICK = "{{{}}}nick".format(NS_USER_NICKNAME)


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
    return ET.tostring(req)


def make_nickname_set_request(to, nickname):
    req = ET.Element("iq", type="set", to=to)
    q = ET.SubElement(req, "pubsub", xmlns="http://jabber.org/protocol/pubsub")
    publish = ET.SubElement(q, "publish", node="http://jabber.org/protocol/nick")
    item = ET.SubElement(publish, "item")
    ET.SubElement(
        item,
        "nick",
        xmlns="http://jabber.org/protocol/nick"
    ).text = nickname

    return ET.tostring(req)


def make_nickname_get_request(to):
    req = ET.Element("iq", type="get", to=to)
    q = ET.SubElement(req, "pubsub", xmlns="http://jabber.org/protocol/pubsub")
    items = ET.SubElement(q, "items", node="http://jabber.org/protocol/nick", max_items="1")

    return ET.tostring(req)


def _require_child(t: ET.Element, tag: str) -> ET.Element:
    el = t.find(tag)
    if el is None:
        raise abort(500, "malformed reply")
    return el


def extract_nickname_get_reply(iq_tree):
    try:
        pubsub = extract_iq_reply(iq_tree, TAG_PUBSUB)
    except quart.exceptions.NotFound:
        return None

    items = _require_child(pubsub, TAG_PUBSUB_ITEMS)
    if len(items) == 0:
        return None

    item = _require_child(items, TAG_PUBSUB_ITEM)
    nick = _require_child(item, TAG_USER_NICKNAME_NICK)
    return nick.text
