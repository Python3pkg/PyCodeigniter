#!/usr/bin/env python
# -*- coding:utf8 -*-
__author__ = 'xiaozhang'


from codeigniter import ci
from codeigniter import cache
from codeigniter import CI_Cache
import os
import json
import re
import sys
import time
import base64
import datetime
# from sql4json.sql4json import *

import threading






def auth(func):
    def decorated(*arg,**kwargs):
        if not 'HTTP_AUTH_UUID' in ci.local.env:
            return "(error)unauthorize1"
        if ci.cache.get(ci.local.env['HTTP_AUTH_UUID'])==None:
            return "(error)unauthorize"
        return func(*arg,**kwargs)
    return decorated




class HeartBeat(object):

    _singleton=False

    def __init__(self):
        self.filename='heartbeat.json'
        self.data=[]# {'uuid','status','utime','salt','ips'}
        self.load_data()
        self.uuids=set()
        if not self._singleton:
            chkthread=threading.Thread(target=self.check_online)
            chkthread.setDaemon(True)
            self._singleton=True
            # chkthread.start()


    def set_online(self,product_uuid,data):
        for d in self.data:
            if d['uuid']==product_uuid:
                for k,v in data.items():
                    d[k]=v
                break

    def check_online(self):
        while True:
            try:
                self.check_status()
                time.sleep(60*2)
            except Exception as er:
                pass


    def check_status(self):
        now=int(time.time())
        for d in self.data:
            if now-d['utime']>60*10:
                d['status']='offline'

    def status(self):
        self.check_status()
        result={'offline':0,'online':0,'count':0}
        for d in self.data:
            result['count']= result['count']+1
            if d['status']=='offline':
                result['offline']=result['offline']+1
            elif  d['status']=='online':
                result['online']=result['online']+1
        return  result


    @auth
    def offline(self):
        result=[]
        for d in self.data:
            if d['status']=='offline':
                result.append(d)
        return  result
    @auth
    def online(self):
        result=[]
        for d in self.data:
            if d['status']=='online':
                result.append(d)
        return  result


    def getetcd(self,param):
        return {'server':['172.16.119.110:4001'],'prefix':'/keeper'}
        return {'server':['172.16.119.3:4001'],'prefix  ':'/keeper'}


    # @cache.Cache()
    def heartbeat(self,params):
        if 'uuid' not in params.keys():
            return '(error) invalid request'
        objs=ci.loader.helper('DictUtil').query(self.data,select='*',where="uuid=%s"%params['uuid'])
        self.uuids.add(params['uuid'])
        salt= str(ci.uuid())
        utime=int(time.time())
        if objs==None or len(objs)==0:
            param={'uuid':params['uuid'],'salt':salt,'ips':params['ips'],'utime':utime,'status':'online'}
            self.data.append(param)
            self.set_online(params['uuid'],param)
        elif len(objs)==1:
            if 'salt' in objs[0].keys():
                salt=objs[0]['salt']
            param={'uuid':params['uuid'],'salt':salt,'ips':params['ips'],'utime':utime,'status':'online'}
            self.set_online(params['uuid'],param)
        else:
            ci.logger.error('heartbeat double: uuid=%s,ips=%s'%(params['uuid'],params['ips']))
        etcd=self.getetcd(params)
        return {'etcd':etcd, 'salt':salt}


    def get_product_uuid(self,ip):
        objs=ci.loader.helper('DictUtil').query(self.data,select='*',where="(ips in %s) or (uuid=%s)"% (ip,ip))
        return objs

    def load_data(self):
        if os.path.isfile(self.filename):
            with open(self.filename,'r') as file:
                self.data=json.loads( file.read())

    def dump_data(self):
        with open(self.filename,'w+') as file:
            file.write(json.dumps(self.data))


class Cli:

    def __init__(self):
        self.cmdkeys={}

        self.hb=HeartBeat()



    @auth
    def index(self,req,resp):
        # print ci.local.env
        #ci.set_header('WWW-Authenticate','Basic realm="Authentication System"')
        #ci.set_header('HTTP/1.0 401 Unauthorized')
        # sys.exit(0)
        return "hello world".strip()
    def abc(self,param='',**kwargs):
        # print ci.local.env
        #ci.set_header('WWW-Authenticate','Basic realm="Authentication System"')
        #ci.set_header('HTTP/1.0 401 Unauthorized')
        # sys.exit(0)
        print kwargs
        return "hello world".strip()

    def help(self,req,resp):
        h='''
        ########## 文件与shell ##############

        cli upgrade   更新 cli 程序
        cli shell -f filename  下载并接行shell指令
        cli listfile   查看文件列表
        cli upload -f filename [-d directory] 上传文件
        cli download -f filename [-d directory] [-o path/to/save]  下载文件
        cli delfile -f filename -k key  删除文件

        ########## 环境变量 ##############

        cli addenv -k key -v value  -g group (default)  增加环境变量
        cli getevn  -k key -g group (default) 获取环境变量
        cli delenv   -k key -g group 删除环境变量
        cli listenv   -g group -e 1 查看某个组的环境变量 默认 default -e 1 导出
        cli updateenv   -k key -v value -g group (default)更新环境变量
         '''
        return h

    def feedback_result(self,req,resp):
        param=req.params['param']
        data=json.loads(param)
        if 'index' in data.keys() and str(data['index']) in self.cmdkeys.keys():
            self.cmdkeys[str(data['index'])]=data['result']
        ci.logger.info("ip:%s,result:\n%s"%(data['ip'],data['result']))


    def heartbeat(self,req,resp):
        params=self._params(req.params['param'])
        return self.hb.heartbeat(params)

    def status(self,req,resp):
        return self.hb.status()

    def offline(self,req,resp):
        return self.hb.offline()

    def online(self,req,resp):
        return self.hb.online()

    def dump_heartbeat(self,req,resp):
        self.hb.dump_data()
        return 'ok'


    def cmd(self,req,resp):
        try:
            params=self._params(req.params['param'])
            etcd=self.hb.getetcd(params)
            cmd=''
            ip=''
            timeout=3
            if  'c' in params:
                cmd=params['c']
            else:
                return '-c(cmd) require'
            if  'i' in params:
                ip=params['i']
            else:
                return '-i(ip) require'
            if  't' in params:
                timeout= float( params['t'])
            import urllib2,urllib
            objs=self.hb.get_product_uuid(ip)
            salt=''
            puuid=''
            if objs==None  or len(objs)==0:
                return '(error) invalid ip'
            elif len(objs)==1:
                puuid=objs[0]['uuid']
                salt=objs[0]['salt']
                if objs[0]['status']=='offline':
                    return '(error) client status offline'
            elif len(objs)>1:
                return '(error) too many ip matched'

            if puuid=='' or salt=='':
                return '(error)client not online'

            data={'value': json.dumps( {'cmd':cmd.encode('utf-8'),'md5': ci.md5(cmd.encode('utf-8') +str(salt)),'timeout':str(timeout)}) }
            data=urllib.urlencode(data)
            req = urllib2.Request(
                    url ="http://%s/v2/keys%s/servers/%s/"%(etcd['server'][0],etcd['prefix'],puuid),
                    data=data
            )
            req.get_method = lambda: 'POST'
            # print urllib2.urlopen(req,timeout=10).read()
            ret=json.loads(urllib2.urlopen(req,timeout=10).read())


            # print ret
            index=str(ret['node']['createdIndex'])
            self.cmdkeys[index]=''
            start=time.time()
            if json.loads(ret['node']['value'])['cmd']==cmd:
                while True:
                    if (time.time()-start> timeout) or self.cmdkeys[index]!='':
                        break
                    else:
                        time.sleep(0.1)
                if self.cmdkeys[index]!='':
                    ret=self.cmdkeys[index]
                    del self.cmdkeys[index]
                    return ret.encode('utf-8')
                return '(success) submit command success'
            else:
                return '(unsafe) submit command success '
        except Exception as er:
            print er
            return 'fail'
            pass




    def disableuser(self,req,resp):
        return self._userstatus(req.params['param'],0)
    def enableuser(self,req,resp):
        return self._userstatus(req.params['param'],1)
    def _userstatus(self,param, status):
        params=self._params(param)
        user=''
        uuid='(error) not login'
        if  'u' in params:
            user=params['u']
        else:
            return '-u(user) require'
        data={'user':user,'status':status}
        ci.db.query("update user set status='{status}' where user='{user}'",data)
        return 'success'


    def dispatch_cmd(self,req,resp):
        params=self._params(req.params['param'])
        if 'i' not in params:
             return '-i(ip) require'

        return 'ls /data';








    def register(self,req,resp):
            params=self._params(req.params['param'])
            user=''
            pwd=''
            uuid='(error) not login'
            if  'u' in params:
                user=params['u']
            else:
                return '-u(user) require'
            if  'p' in params:
                pwd=params['p']
            else:
                return '-p(password) require'
            data={'user':user}

            if ci.db.scalar("select count(1) as cnt from user where user='{user}'",data)['cnt']>0:
                return "(error)user exist"
            data={'user':user,'pwd':ci.md5(pwd) }
            ci.db.query("insert into user(user,pwd) values('{user}','{pwd}')",data)
            return 'success'

    def login(self,req,resp):
        params=self._params(req.params['param'])
        user=''
        pwd=''
        ip=''
        uuid='(error) user or password error '
        if  'u' in params:
            user=params['u']
        else:
            return '-u(user) require'
        if  'p' in params:
            pwd=params['p']
        else:
            return '-p(password) require'
        if  'i' in params:
            ip=params['i']
        data={'user':user,'pwd':ci.md5(pwd)}
        is_exist=ci.db.scalar("select status from user where user='{user}' and pwd='{pwd}' limit 1 offset 0",data)
        udata={'user':user,'lasttime':time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())),'ip':ip}
        if is_exist!=None:
            if is_exist['status']!=1:
                return '(error) user not in actvie status'
            ci.db.query("update user set logincount=logincount+1,lasttime='{lasttime}',ip='{ip}' where user='{user}'",udata)
            uuid=str(ci.uuid())
            ci.cache.set(uuid,user)
        else:
            ci.db.query("update user set logincount=logincount+1,failcount=failcount+1,lasttime='{lasttime}',ip='{ip}' where user='{user}'",udata)

        return str(uuid)


    def shell(self,req,resp):
        dir=req.params.get('dir','shell')
        file=req.params.get('file','')
        dir=dir.replace('..','').replace('.','').replace('/','')
        path= 'files'+ os.path.sep+ dir+ os.path.sep + file
        if os.path.isfile(path):
            return open(path,'rb').read()
        else:
            return "#!/bin/bash\n echo '(error) file not found'"

    # def shell(self,file='',param='',dir='shell'):
    #     dir=dir.replace('..','').replace('.','').replace('/','')
    #     path= 'files'+ os.path.sep+ dir+ os.path.sep + file
    #     if os.path.isfile(path):
    #         return open(path,'rb').read()
    #     else:
    #         return "#!/bin/bash\n echo '(error) file not found'"

    def upgrade(self,req,resp):
        return open('cli').read()

    def _params(self,param='{}',opts=''):
        params= json.loads(param)
        return params

    def listfile(self,req,resp):
        params=self._params(req.params['param'])
        if 'd' in params:
            directory=params['d']
        else:
            directory=''
        directory=directory.replace('.','')
        return "\n".join(os.listdir('files/'+directory))


    def download(self,req,resp):
        dir=req.params.get('dir','/')
        file=req.params.get('file','')
        dir=dir.replace('.','')
        filepath='files/'+dir+'/'+file
        if not os.path.isfile(filepath):
            # resp.status=404
            resp.body='(error) file not found'
        else:
            with open(filepath,'rb') as file:
                resp.body=file.read()



        print(req.params)
        pass
    def upload(self,req,resp):
        #
        # print req.params
        # return
        file=req.params['file']
        filename=req.params['filename']
        directory=req.params.get('dir','/')
        directory=directory.replace('.','')
        path='files/'+directory
        path=path.replace('///','/')
        path=path.replace('//','/')
        filename=path+'/'+filename
        if not os.path.isdir(path):
            os.mkdir(path)
        if not os.path.exists(filename):
            if isinstance(file,str):
                open(filename,'wb').write(file)
            else:
                open(filename,'wb').write(file.file.read())
            return 'success'
        else:
            return 'file exists'

    def delfile(self,req,resp):
        params=self._params(req.params['param'])
        filename=''
        key='meizu.com'
        directory='/'
        k=''
        if  'f' in params:
            filename=params['f']
        else:
            return '-f(filename) require'
        if  'k' in params:
            k=params['k']
        else:
            return '-k(key) require'
        if  'd' in params:
            directory=params['d']
        if not key==k:
            return 'key error'
        directory=directory.replace('.','')
        path='files/'+directory + '/' +filename
        if os.path.exists(path):
            os.remove(path)
            return "sucess"
        else:
            return "Not Found"
    def rexec(self,req,resp):
        params=self._params(req.params['param'])
        ip=''
        cmd=''
        k=''
        key='Mz'
        user='root'
        password='root'
        port=22
        if 'i' in params:
            ip=params['i']
        else:
            return '-i(ip) require'
        if 'c' in params:
            cmd=params['c']
        else:
            return '-c(command) require'
        if  'k' in params:
            k=params['k']
        else:
            return '-k(key) require'
        if not key==k:
            return 'key error'
        if  'u' in params:
            user=params['u']
        if  'p' in params:
            password=params['p']
        if  'P' in params:
            port=params['P']
        return self._remote_exec(ip,cmd, user= user, password=password,port=port)

    def _remote_exec(self,ip,cmd,user='root',password='root',port=22):
       try:
           import paramiko
           ssh=paramiko.SSHClient()
           ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
           #pkey= paramiko.RSAKey.from_private_key_file ('keypath/filename','keypassword')
           #try:
           #    ssh.connect(ip,22,'ops','',pkey)
           #except Exception as err:
           #    self.app.logger.error("PKERROR:"+str(err))
           #    try:
           #        ssh.connect(ip,22,'root','root')
           #    except Exception as usererr:
           #        self.app.logger.error("USERERROR:"+str(err))
           #        ssh.connect(ip,16120,'root','root')

           ssh.connect(ip,port,user,password)
           ssh.exec_command('sudo -i')
           ret=[]
           reterr=[]
           if isinstance(cmd,list):
               for c in cmd:
                   stdin, stdout, stderr = ssh.exec_command(cmd)
                   reterr.append("".join(stderr.readlines()))
                   ret.append("".join(stdout.readlines()))
           else:
               stdin, stdout, stderr = ssh.exec_command(cmd)
               reterr=stderr.readlines()
               ret=stdout.readlines()

           if len(reterr)>0:
               return "".join(reterr)
           return "".join(ret)
       except Exception as er:
           self.app.logger.error(er)
           return str(er)
       finally:
           try:
              ssh.close()
           except Exception as err:
               pass

################################################env###############################################
    def _checkenv(self,param):
        params=self._params(param)
        key=''
        group='default'
        if 'g' in params:
            group=params['g']
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        rows=ci.db.query("select * from env where `group_`='%s' and `key_`='%s'"% (group,key))
        if len(rows)>0:
            return True
        else:
            return False
    def listenvgroup(self,req,resp):
        params=self._params(req.params['param'])
        sql="select group_ from env group by group_"
        rows=ci.db.query(sql)
        ret=''
        for row in rows:
            if row['group_']!=None:
                ret+=str(row['group_'])+"\n"
        return ret

        return ret
    def listenv(self,req,resp):
        params=self._params(req.params['param'])
        group='default'
        export='0'
        if 'g' in params:
            group=params['g']
        if 'e' in params:
            export=params['e']
        sql="select key_,value_ from env where `group_`='%s'" % (group)
        rows=ci.db.query(sql)
        if len(rows)==0:
            return '(error) not found'
        ret=''
        for row in rows:
            if export=='1':
                ret+='export '+row['key_']+'='+row['value_']+"\n"
            else:
                ret+=row['key_']+'='+row['value_']+"\n"

        return ret
    def updateenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        value=''
        group='default'
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if 'g' in params:
            group=params['g']
        if 'v' in params:
            value=params['v']
        else:
            return '-v(value) require'
        if not self._checkenv(req.params['param']):
            return '(error)key not is exsit'
        ci.db.update('env',{'value_':value},{'key_':key,'group_':group})
        return 'ok'

    def addenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        value=''

        group='default'
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if 'g' in params:
            group=params['g']
        if 'v' in params:
            value=params['v']
        else:
            return '-v(value) require'
        if self._checkenv(req.params['param']):
            return '(error)key is exsit'
        ci.db.insert('env',{'key_':key,'value_':value,'group_':group})
        return 'ok'
    def delenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        group='default'
        if 'g' in params:
            group=params['g']
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if self._checkenv(req.params['param']):
            ci.db.delete('env',{'key_':key,'group_':group})
            return 'ok'
        else:
            return '(error)key no found'
    def getenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        group='default'
        if 'g' in params:
            group=params['g']
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if not self._checkenv(req.params['param']):
            return '(error)key no found'
        return ci.db.scalar("select value_ from env where `group_`='%s' and `key_`='%s'"% (group,key))['value_']

################################################ doc ###############################################
    def _checkdoc(self,param):
        params=self._params(param)
        id=''
        if 'k' in params:
            id=params['k']
        else:
            return '-k(key) require'
        rows=ci.db.query("select * from doc where `id`='%s'"% (id))
        if len(rows)>0:
            return True
        else:
            return False
    def listdoc(self,req,resp):
        params=self._params(req.params['param'])
        if 'k' in params:
            return self.getdoc(req.params['param'])
        sql="select cmd from doc group by cmd"
        rows=ci.db.query(sql)
        ret=''
        for row in rows:
            if row['cmd']!=None:
                ret+=(row['cmd'].encode('utf-8'))+"\n"
        return ret


    def adddoc(self,req,resp):
        params=self._params(req.params['param'])
        cmd=''
        doc=''
        remark=''
        if 'c' in params:
            cmd=params['c']
        if 'd' in params:
            doc=params['d']
            if cmd=='':
                cmd=doc.strip().split(" ")[0]
        else:
            return '-d(document) require'
        if 'r' in params:
            remark=params['r']
        sql='''INSERT INTO doc
	(
	cmd,
	doc,
	remark
	)
	VALUES
	(
	'{cmd}',
	'{doc}',
	'{remark}'
	)'''
        ci.db.query(sql,{'cmd':cmd,'doc':doc,'remark':remark})
        #ci.db.insert('doc',{'cmd':cmd,'doc':doc,'remark':remark})
        return 'ok'
    def deldoc(self,req,resp):
        params=self._params(req.params['param'])
        id=''
        if 'k' in params:
            id=params['k']
        else:
            return '-k(id) require'
        if self._checkdoc(req.params['param']):
            ci.db.delete('doc',{'id':id})
            return 'ok'
        else:
            return '(error)key no found'
    def getdoc(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        if 'k' in params:
            key=params['k']
        else:
            return '-k(keyword) require'
        if 'a' in params:
            rows= ci.db.query("select id,doc from doc where  `cmd` like '%%%s%%' or doc like '%%%s%%'"% (key,key))
        else:
            rows= ci.db.query("select id,doc from doc where  `cmd`='%s'"% (key))
        ret=''
        outid='i' in params
        for row in rows:
            if row['doc']!=None:
                if outid:
                    ret+='# docid:  '+str(row['id'])+"\n"+(row['doc'].encode('utf-8'))+"\n"*3
                else:
                    ret+=str(unicode.encode(row['doc'],'utf-8','ignore'))+"\n"*3
                #ret+="#"*50+"\n"
        return ret

################################################ tags ###############################################
    def addtag(self,req,resp):
        params=self._params(req.params['param'])
        table=''
        tag=''
        if 'tag' in params:
            tag=params['tag']
        else:
            return '--tag(tag) require'
        if 'object' in params:
            table=params['object']
        else:
            return '--object(object name) require'
        if tag.find('=')==-1:
            return 'tag must be "key=value"'
        body={}
        for t in tag.split(';'):
            kv=t.split('=')
            if len(kv)==2:
                body[kv[0]]=kv[1]
        row=ci.db.scalar("select id,body from tags where tbname='{tbname}' limit 1 offset 0",{'tbname':table})
        if row==None:
            data={'tbname':table, 'body':json.dumps(body)}
            ci.db.query("insert into tags(tbname,body) values('{tbname}','{body}')",data)
        else:
            old=json.loads(row['body'])
            for k in body.keys():
                old[k]=body[k]
            data={'body':json.dumps(old),'id':row['id']}
            ci.db.query("update tags set body='{body}' where id='{id}'",data)
        return 'success'

    def listtag(self,req,resp):
        params=self._params(req.params['param'])
        rows=ci.db.query("select tbname,body from tags")
        # return rows
        s=set()
        for row in rows:
            tags=json.loads(row['body'])
            for k in tags.keys():
                s.add('object_name: '+row['tbname'].encode('utf-8')+"\ttags: "+ k.encode('utf-8')+"=%s"% tags[k].encode('utf-8') )
        return "\n".join(s)


    def _check_body_val(self,table,key,value):
        row=ci.db.scalar("select body from tags where tbname='%s' limit 1 offset 0"%table)
        body={}
        if row!=None:
            body=json.loads(row['body'])
        else:
            return True,'OK'
        if key in body.keys():
            if body[key]!='':
                if value in body[key].split(','):
                    return  True,'OK'
                else:
                    return  False," value:'%s' must be in %s" %(key,str(body[key].encode('utf-8').split(',')))
            else:
                return True,'OK'
        else:
            return False," tag name must be in %s" %(str([ k.encode('utf-8') for k in body.keys()]))


################################################ hosts ###############################################

    def addhosttag(self,req,resp):
        params=self._params(req.params['param'])
        tag=''
        ip=''
        if 't' in params:
            tag=params['t']
        else:
            return '-t(tag) require'
        if tag.find('=')==-1:
            return 'tag must be "key=value"'
        if 'i' in params:
            ip=params['i']
        else:
            return '-i(ip) require'
        body={}
        for t in tag.split(';'):
            kv=t.split('=')
            if len(kv)==2:
                ok,messege=self._check_body_val('hosts',kv[0],kv[1])
                if not ok:
                    return messege.encode('utf-8')
                body[kv[0]]=kv[1]

        row=ci.db.scalar("select id,body from hosts where ip='{ip}' limit 1 offset 0",{'ip':ip})
        if row==None:
            data={'ip':ip,'body':json.dumps(body)}
            ci.db.query("insert into hosts(ip,body) values('{ip}','{body}')",data)
        else:
            old=json.loads(row['body'])
            for k in body.keys():
                old[k]=body[k]
            data={'ip':ip,'body':json.dumps(old),'id':row['id']}
            ci.db.query("update hosts set ip='{ip}',body='{body}' where id='{id}'",data)
        return 'success'
    # @cache.Cache(ttl=300)
    def gethost(self,req,resp):
        params=self._params(req.params['param'])
        if 't' not in params:
            return '-t(tag) require'
        rows=ci.db.query("select ip,body from hosts")
        # rows=self._cache_table('hosts')
        ret=[]
        tag=params['t']
        start=time.time()
        rows= self._search_body('hosts',tag)
        print(time.time()-start)
        for row in rows:
                # ret.append(row['ip'])
                ret.append(row['app'])
        return "\n".join(ret)

    def viewhost(self,req,resp):
        params=self._params(req.params['param'])
        if 'i' not in params:
            return '-i(ip) require'
        else:
            ip=params['i']
        data={'ip':ip}
        row=ci.db.scalar("select ip,body from hosts where ip='{ip}' limit 1 offset 0",data)
        return row['body']
    # @cache.Cache(ttl=3600)
    def listhosttag(self,req,resp):
        params=self._params(req.params['param'])
        rows=ci.db.query("select body from hosts")
        # return rows
        s=set()
        for row in rows:
            tags=json.loads(row['body'])
            for k in tags.keys():
                s.add(k.encode('utf-8')+"=%s"% tags[k].encode('utf-8') )
        return "\n".join(s)

    @cache.Cache(ttl=3600,key="#p[0]",md5=False)
    def _cache_table(self,table):
        print('xxxxxx')
        return ci.db.query("select * from %s" % table)


    def aaa(self,req,resp):
        print ci.loader.helper('DictUtil')
        rows=ci.db.query('select * from hosts')
        print rows
        #return ci.loader.helper('DictUtil').query(rows,'select aa,bb,ip where ip like 172.17.140.133')
        return ci.loader.helper('DictUtil').query({"xx":"x"},"select aa,bb,ip where ip like '' ")

    def abc(self,req,resp):
        return u'你好'
        s=time.time()
        for i in xrange(1,100000):
            self._cache_table('hosts')[0]
        print(time.time()-s)
        return 'abc'


    def test2(self,req,resp):
        # pass
        print ci.db.query("select * from objs where ip='{ip}'",{'ip':'172.17.140.133'})




    def test3(self,req,resp):
        rows=self._cache_table('hosts')
        for index,row in enumerate(rows):
            r=json.loads(row['body'])

            rows[index]=r
        # import pymongo
        #
        # conn = pymongo.MongoClient("127.0.0.1",27017)
        # db = conn.test
        # for row in rows:
        #
        #     db.test.insert_one(row)



    def test(self,req,resp):

        # from data_query_engine import DataQueryEngine

        rows=self._cache_table('hosts')
        # rows=self.db.query('select * from hosts limit 10')
        # rows=self.db.query('select * from hosts ')
        start=time.time()
        data=[]

        for index,row in enumerate(rows):
            r=json.loads(row['body'])

            rows[index]=r


        # print(rows)
        # query = DataQueryEngine(rows, "select * from ")
        # return  query.get_results()




        # query = Sql4Json(json.dumps({"data":rows}), "select ip,business from / where room_en_short=='GZ-NS'")
        # query = Sql4Json(json.dumps({"data":rows}), "select * from data")
        # query = Sql4Json(json.dumps(rows), "select ip,business from / where  module > 'sync-web'")


        # query = DataQueryEngine(rows, "select * from  /  where  module == 'sync-web'")
        # return  query.get_results()
        #
        # print time.time()-start
        # results_dictionary = query.get_results()
        # return results_dictionary







    def _search_body(self,table='', exp=''):
        # assert  table!=''
        # exp=exp.replace('&&',' and ')
        # exp=exp.replace('||',' or ')
        # rows=ci.db.query("select * from %s"%table)
        # ret=[]
        # def tmp(a):
        #     return ('('+(a.group(0)).encode("utf-8").replace("'",'')+')').decode('utf-8')
        # exp=re.sub(r'(\w+\s*(=|like)\s*[\'](?:[^\']+)[\'])|(\w+(=|like)\s*(?:[^\s]+)\s*)',tmp,exp)
        # print(exp)
        # s=time.time()
        rows=ci.db.query("select * from %s"%table)

        ret=[]

        # for row in rows:
        #     row['ip']=row['ip']



        rows=map(lambda row: json.loads( row['body']) ,rows)


        dutil=ci.loader.helper('DictUtil')

        print(rows)



        return  dutil.query( rows,select="name", where=exp)


        # expmatch= dutil.query( rows, exp)
        #
        # print len(rows)
        #
        #
        # ret = filter(lambda row: expmatch.calc(data_dict=json.loads( row['body'])), rows)
        # print("xxxxxxxxxxxxxx:"+str(time.time()-s))
        # return ret

# ################################################ objs ###############################################
    def addobjs(self,req,resp):
            params=self._params(req.params['param'])
            tag=''
            ip=''
            otype='hosts'
            key=''
            if 't' in params:
                tag=params['t']
            else:
                return '-t(tag) require'
            if tag.find('=')==-1:
                return 'tag must be "key=value"'
            if 'i' in params:
                ip=params['i']
            else:
                return '-i(ip) require'
            if 'o' in params:
                otype=params['o']
            else:
                return '-o(object type) require'
            if 'k' in params:
                key=params['k']
            else:
                key=ip
            body={}
            for t in tag.split(';'):
                kv=t.split('=')
                if len(kv)==2:
                    ok,messege=self._check_body_val(otype,kv[0],kv[1])
                    if not ok:
                        return messege.encode('utf-8')
                    body[kv[0]]=kv[1]

            row=ci.db.scalar("select id,body from objs where `key`='{key}' and otype='{otype}' limit 1 offset 0",{'key':key,'otype':otype})
            if row==None:
                body['_key']=key
                body['_otype']=otype
                data={'ip':ip,'body':json.dumps(body),'otype':otype,'key':key}
                ci.db.query("insert into objs(ip,body,otype,`key`) values('{ip}','{body}','{otype}','{key}')",data)
            else:
                old=json.loads(row['body'])
                for k in body.keys():
                    old[k]=body[k]
                data={'ip':ip,'body':json.dumps(old),'id':row['id']}
                ci.db.query("update objs set ip='{ip}',body='{body}' where id='{id}'",data)
            return 'success'

    def getobjs(self,req,resp):
        params=self._params(req.params['param'])
        otype=''
        tag=''
        cols='*'
        if 't' not in params:
            return '-t(tag) require'
        else:
            tag= params['t']
        if 'o' not in params:
            return '-o(object type) require'
        else:
            otype=params['o']
        if 'c'  in params:
            cols= params['c']
        rows=ci.db.query("select * from objs where otype='{otype}'",{'otype':otype})
        rows=map(lambda row:json.loads(row['body']),rows)
        # print(rows)
        return ci.loader.helper('DictUtil').query(rows,select=cols,where=tag)

