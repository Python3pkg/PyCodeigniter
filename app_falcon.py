#!/usr/bin/env python
# -*- coding:utf8 -*-
import falcon
import json
from codeigniter import CI_Application
ciapp=CI_Application(r'./')
from wsgiref.simple_server import make_server
import cgi

class MultipartMiddleware(object):
    def __init__(self, parser=None):
        self.parser = cgi.FieldStorage

    def parse(self, stream, environ, keep_blank_values=1):
        return self.parser(fp=stream,
                           environ=environ,
                           keep_blank_values=keep_blank_values)

    def process_request(self, req, resp, **kwargs):

        if not req.content_type in  ['multipart/form-data','application/x-www-form-urlencoded']:
            return
        form = self.parse(stream=req.env['wsgi.input'], environ=req.env)
        for key in form:
            field = form[key]
            if not getattr(field, 'filename', False):
                field = form.getvalue(key, None)
            req._params[key] = field

def dispatch(req,resp):
    resp.status = falcon.HTTP_200
    resp.body=None
    paths=filter(lambda x: x!='',req.path.split('/'))
    ctrl_name='index'
    func_name='index'
    if len(paths)>=2:
        ctrl_name=paths[0]
        func_name=paths[1]
    elif len(paths)==1:
        func_name=paths[0]
    ctrl=ciapp.loader.ctrl(ctrl_name)
    if ctrl==None or not hasattr(ctrl,func_name):
        resp.status=falcon.HTTP_404
        resp.body="Not Found"
    else:
        try:
            ciapp.local.env=req.env
            content=getattr(ctrl,func_name)(req,resp)
            if  resp.body==None:
                if isinstance(content,unicode):
                    resp.body=unicode.encode(content,'utf-8','ignore')
                elif isinstance(content,str):
                    resp.body=content
                else:
                    resp.body=json.dumps(content)
        except Exception as er:
            resp.status=falcon.HTTP_500
            resp.body='Internal  Error'
            print(er)

app = falcon.API(middleware=[MultipartMiddleware()])
app.add_sink(dispatch,'/')

# make_server('0.0.0.0',8000,app).serve_forever()