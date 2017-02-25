#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : app.py
# @Author : 戴喜军 <daixijun1990@gmail.com>
# @Date   : 2017-02-25 16:17:46
import time
from flask import Flask, request, make_response, redirect, jsonify
import hashlib
from lxml import etree
from weixin.client import WeixinAPI
from weixin.oauth2 import OAuth2AuthExchangeError

APP_ID = ''
APP_SECRET = ''
APP_TOKEN = ''
REDIRECT_URI = 'http://weixin.linuxyunwei.com/authorization'

app = Flask(__name__)


TEXT_MSG_TPL = \
u"""
<xml>
<ToUserName><![CDATA[%s]]></ToUserName>
<FromUserName><![CDATA[%s]]></FromUserName>
<CreateTime>%s</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[Hello]]></Content>
<FuncFlag>0</FuncFlag>
</xml>
"""



@app.route('/', methods=['GET', 'POST'])
def wechat_auth():
    if request.method == 'GET':
        token = APP_TOKEN
        query = request.args
        signature = query.get('signature', '')
        timestamp = query.get('timestamp', '')
        nonce = query.get('nonce', '')
        echostr = query.get('echostr', '')
        s = [timestamp, nonce, token]
        s.sort()
        s = ''.join(s)
        if hashlib.sha1(s).hexdigest() == signature:
            return make_response(echostr)
    else:
        rec = request.data
        xml_rec = etree.fromstring(rec)
        event = None
        msgtype = xml_rec.find('MsgType').text
        if msgtype == 'event':
            event = xml_rec.find('Event').text
        toUser = xml_rec.find('ToUserName').text
        fromUser = xml_rec.find('FromUserName').text
        cont = xml_rec.find('Content').text
        CreateTime = str(int(time.time()))
        # CreateTime = xml_rec.find('CreateTime').text

        # print toUser, fromUser, msgtype, cont
        text = TEXT_MSG_TPL % (fromUser, toUser, CreateTime)
        response = make_response(text)
        response.content_type = 'application/xml'
        return response


@app.route("/authorization")
def authorization():
    code = request.args.get('code')
    api = WeixinAPI(appid=APP_ID,
                    app_secret=APP_SECRET,
                    redirect_uri=REDIRECT_URI)
    auth_info = api.exchange_code_for_access_token(code=code)
    api = WeixinAPI(access_token=auth_info['access_token'])
    resp = api.user(openid=auth_info['openid'])
    return jsonify(resp)


@app.route("/login")
def login():
    api = WeixinAPI(appid=APP_ID,
                    app_secret=APP_SECRET,
                    redirect_uri=REDIRECT_URI)
    redirect_uri = api.get_authorize_login_url(scope=("snsapi_login",))
    return redirect(redirect_uri)


if __name__ == '__main__':
    app.run(debug=True)
